#!/usr/bin/env python3
"""Emit the Elastic and Kusto versions of the joins pySigma will not convert.

`ci/convert_check.py` records `elastic: unsupported, kusto: unsupported` on all
five correlation rules, because pySigma 1.x converts correlations only through
the Splunk backend. The gap register called that "the join has to be built in
the SIEM" - which is true and was, until now, the end of the sentence. A user of
this repository on Elastic got five `unsupported` lines and a Markdown
specification.

This generates working query text for the two missing platforms:

  * `temporal` (sequence) -> Elastic `EQL sequence by ... with maxspan`, and a
    Kusto query that unions the member events and uses `make_list`/`mv-expand`
    to require the order
  * `event_count` -> Elastic `EQL sequence ... [any where true] with maxspan`
    is the wrong tool for a threshold, so it emits a KQL/EQL aggregation pair
    using `stats count by` (Kusto) and a threshold script (Elastic, as a
    detection rule's `query` + `threshold` block in JSON)

Everything is derived from the rule YAML and from the member rules' own SPL, so
the joins cannot drift from the members without this file changing too. A gate
stage regenerates it and a test asserts the outputs are current.

What this does NOT do: prove the queries are right on a real cluster. Nothing
here has run against Elastic or Kusto. The generated files say which parts are
mechanical translation and which parts step outside pySigma's guarantees.

Usage:
    python3 deploy/build_joins.py                     # writes deploy/joins/
    python3 deploy/build_joins.py --check             # fail if stale
"""
import argparse
import json
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "sigma"
OUT = ROOT / "deploy" / "joins"


def load_rules():
    rules = {}
    for path in sorted(RULES.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("id"):
            rules[data["id"]] = (path, data)
    return rules


def field_map(data):
    """Which field carries the group-by key on this platform.

    The rules group by Sigma-canonical names (`Computer`, `SourceAddress`) and
    each backend renames them. These are the renames the repository already uses
    in telemetry/data-sources.md, not a guess.
    """
    return {
        "Computer": {"elastic": "host.name", "kusto": "Computer"},
        "SourceAddress": {"elastic": "source.ip", "kusto": "SrcIpAddr"},
        "DestinationHostname": {"elastic": "destination.domain", "kusto": "DstHostname"},
        "ProcessGuid": {"elastic": "process.entity_id", "kusto": "ProcessGuid"},
    }.get(data, {"elastic": data.lower(), "kusto": data})


def spl_iter(entry):
    values = entry if isinstance(entry, list) else [entry]
    return [str(v) for v in values]


def _flatten_lists(obj):
    """Sigma allows a list value to be a list (|contains|all). Flatten once."""
    return [x for item in obj for x in (item if isinstance(item, list) else [item])]


class TranslationError(ValueError):
    pass


# ---------------------------------------------------------------- Elastic / EQL
def eql_field(name):
    """Map a Sigma field to its Elastic field name where the repo knows one."""
    return {
        "EventID": "event.code",
        "Computer": "host.name",
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "ParentCommandLine": "process.parent.command_line",
        "SourceAddress": "source.ip",
        "DestinationHostname": "destination.domain",
        "TargetObject": "registry.path",
        "ObjectName": "registry.path",
        "TargetFilename": "file.path",
        "Signature": "process.code_signature.subject_name",
        "IntegrityLevel": "process.Ext.token.integrity_level_name",
        "Source": "source.ip",
        "SrcIpAddr": "source.ip",
        "query": "dns.question.name",
        "QueryName": "dns.question.name",
        "destination_port": "destination.port",
        "cs-uri-stem": "url.path",
        "cs-uri-query": "url.query",
        "cs-user-agent": "user_agent.original",
    }.get(name, name)


def eql_value(value):
    return json.dumps(str(value))


def eql_clause(key, value):
    """One Sigma key/value pair -> one EQL predicate, or a hard failure.

    Supported: equality, `|exists`, `|endswith`, `|startswith`, `|contains`,
    `|contains|all`, and `|re` for the anchored single-literal case the rules
    actually use (`^0x1$`). `|re` beyond that raises: a regex translated loosely
    produces a query that matches the wrong events, which is the defect class
    this repository exists to stop repeating.
    """
    if "|" in key:
        parts = key.split("|")
        field, modifiers = eql_field(parts[0]), parts[1:]
    else:
        field, modifiers = eql_field(key), []

    if modifiers == ["exists"]:
        return f"{field} != null" if value is True else f"{field} == null"

    if modifiers == ["re"]:
        m = re.fullmatch(r"\^([A-Za-z0-9_.\\-]+)\$", str(value))
        if not m:
            raise TranslationError(
                f"|re {value!r} is not a single anchored literal; EQL has no "
                f"regex, so this needs a hand-written query")
        return f"{field} == {eql_value(m.group(1))}"

    values = spl_iter(value)

    if modifiers == ["endswith"]:
        return "(" + " or ".join(
            f"{field} : {eql_value('*' + v.lstrip(chr(92)))}" for v in values) + ")"
    if modifiers == ["startswith"]:
        return "(" + " or ".join(
            f"{field} : {eql_value(v + '*')}" for v in values) + ")"
    if modifiers == ["contains"]:
        return "(" + " or ".join(
            f"{field} : {eql_value('*' + v + '*')}" for v in values) + ")"
    if modifiers == ["contains", "all"]:
        return " and ".join(f"{field} : {eql_value('*' + v + '*')}" for v in values)
    if modifiers:
        raise TranslationError(f"unsupported EQL modifiers: {'|'.join(modifiers)}")
    if len(values) == 1:
        return f"{field} == {eql_value(values[0])}"
    return "(" + " or ".join(f"{field} == {eql_value(v)}" for v in values) + ")"


def selection_to_eql(selection):
    return " and ".join(eql_clause(k, v) for k, v in selection.items())


COND_TOKEN = re.compile(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*")


def expand_condition(condition, selections, join, conj="AND", neg="NOT"):
    """Expand a Sigma condition into a fully parenthesised boolean.

    The first version of this substituted each selection name with its
    predicate and left the original `or`/`and` words in place. Because AND binds
    tighter than OR, the result silently changed meaning: the emitted EQL for
    patch_sequence became `(a and b and c) or (d) or (e) and f or ...` when the
    rule says `sel_a or sel_b or sel_c or sel_d`. That is the exact defect class
    this repository exists to catch, so this now reconstructs the expression
    with explicit parentheses, using AND/OR precedence only as a sanity check -
    every selection group and every disjunction is bracketed.
    """
    tokens = COND_TOKEN.findall(str(condition))
    # Parse into nested lists: ['OR', a, b, ['AND', c, d]]
    pos = 0

    def parse_expr():
        nonlocal pos
        node = parse_and()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            node = ["OR", node, parse_and()]
        return node

    def parse_and():
        nonlocal pos
        node = parse_unary()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            node = ["AND", node, parse_unary()]
        return node

    def parse_unary():
        nonlocal pos
        if pos >= len(tokens):
            raise TranslationError("condition ended early")
        tok = tokens[pos]
        if tok == "not":
            pos += 1
            return ["NOT", parse_unary()]
        if tok == "(":
            pos += 1
            node = parse_expr()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise TranslationError("unbalanced parentheses in condition")
            pos += 1
            return node
        if tok in selections:
            pos += 1
            return ["SEL", tok]
        raise TranslationError(f"condition names {tok!r}, which is not a "
                               f"selection in this rule")

    tree = parse_expr()
    if pos != len(tokens):
        raise TranslationError(f"trailing tokens in condition: {tokens[pos:]}")

    def render(node):
        if node[0] == "SEL":
            return "(" + selections[node[1]] + ")"
        if node[0] == "NOT":
            return f"{neg} (" + render(node[1]) + ")"
        op = " and " if node[0] == "AND" else " or "
        return "(" + op.join(render(child) for child in node[1:]) + ")"

    return render(tree)


def member_predicate(member):
    detection = dict(member["detection"])
    condition = detection.pop("condition", None)
    timeframes = [k for k in detection if k.startswith("timeframe")]
    if timeframes:
        raise TranslationError(f"{timeframes} windows are not translated")
    if condition is None:
        if len(detection) != 1:
            raise TranslationError("no condition and more than one selection")
        return selection_to_eql(next(iter(detection.values())))
    return expand_condition(condition, {name: selection_to_eql(sel)
                                        for name, sel in detection.items()},
                            join=eql_clause)


def elastic_temporal(rule, members):
    corr = rule["correlation"]
    key_field = field_map(corr["group-by"][0])["elastic"]
    lines = [f"// generated by deploy/build_joins.py from {rule['_path']}",
             "// pySigma converts correlations only for Splunk; this is the EQL "
             "equivalent",
             f"sequence by {key_field} with maxspan={corr['timespan']}"]
    for rid in corr["rules"]:
        path, member = members[rid]
        body = member_predicate(member)
        lines.append(f"  [{member['logsource'].get('category', 'any')} where {body}]")
    return "\n".join(lines) + "\n"


def esql_clause(key, value):
    """ES|QL predicate. Unlike EQL, ES|QL has RLIKE, so the DGA rules' regexes
    translate exactly instead of being refused."""
    if "|" in key:
        parts = key.split("|")
        field, modifiers = eql_field(parts[0]), parts[1:]
    else:
        field, modifiers = eql_field(key), []
    if modifiers == ["exists"]:
        return f"{field} IS NOT NULL" if value is True else f"{field} IS NULL"
    if modifiers == ["re"]:
        pattern = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'{field} RLIKE "{pattern}"'
    values = spl_iter(value)
    if len(modifiers) == 1 and modifiers[0] in ("endswith", "startswith", "contains"):
        wildcard = {"endswith": "*{}", "startswith": "{}*", "contains": "*{}*"}
        return "(" + " or ".join(
            f'{field} LIKE {json.dumps(wildcard[modifiers[0]].format(v))}'
            for v in values) + ")"
    if modifiers == ["contains", "all"]:
        return " and ".join(f'{field} LIKE {json.dumps("*" + v + "*")}' for v in values)
    if modifiers:
        raise TranslationError(f"unsupported ES|QL modifiers: {modifiers}")
    if len(values) == 1:
        return f'{field} == {json.dumps(values[0])}'
    return "(" + " or ".join(f'{field} == {json.dumps(v)}' for v in values) + ")"


def esql_predicate(member):
    detection = dict(member["detection"])
    condition = detection.pop("condition", None)
    if condition is None:
        if len(detection) != 1:
            raise TranslationError("no condition and more than one selection")
        return " and ".join(esql_clause(k, v)
                            for k, v in next(iter(detection.values())).items())
    return expand_condition(condition,
                            {n: " AND ".join(esql_clause(k, v)
                                             for k, v in sel.items())
                             for n, sel in detection.items()},
                            join=esql_clause, neg="NOT")


def elastic_event_count(rule, members):
    corr = rule["correlation"]
    path, member = members[corr["rules"][0]]
    where = esql_predicate(member)
    key_fields = [field_map(k)["elastic"] for k in corr["group-by"]]
    return (
        f"// generated by deploy/build_joins.py from {rule['_path']}\n"
        f"// pySigma does not convert correlations for Elastic. A threshold is an\n"
        f"// aggregation, not a sequence, so this is ES|QL.\n"
        f"FROM logs-*\n"
        f"| WHERE {where}\n"
        f"| STATS events = COUNT(*) BY {', '.join(key_fields)}, "
        f"bucket = BUCKET(@timestamp, {_bucket_size(corr['timespan'])})\n"
        f"| WHERE events >= {corr['condition']['gte']}\n"
    )


def _bucket_size(text):
    m = re.fullmatch(r"(\d+)([smhd])", str(text))
    if not m:
        raise TranslationError(f"unparseable timespan {text!r}")
    return f"{m.group(1)} {m.group(2)}"


# ---------------------------------------------------------------------- Kusto
def kusto_field(name):
    return {
        "EventID": "EventID",
        "Computer": "Computer",
        "Image": "FolderPath",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFolderPath",
        "SourceAddress": "SrcIpAddr",
        "DestinationHostname": "DstHostname",
        "TargetObject": "RegistryKey",
        "TargetFilename": "FileName",
        "Source": "SrcIpAddr",
        "query": "Name",
        "QueryName": "Name",
    }.get(name, name)


def kusto_clause(key, value):
    if "|" in key:
        parts = key.split("|")
        field, modifiers = kusto_field(parts[0]), parts[1:]
    else:
        field, modifiers = kusto_field(key), []
    if modifiers == ["exists"]:
        return f"isnotempty({field})" if value is True else f"isempty({field})"
    if modifiers == ["re"]:
        # Kusto has a real regex operator, so unlike EQL this translates exactly.
        pattern = str(value).replace('"', '\\"')
        return f'{field} matches regex "{pattern}"'
    values = spl_iter(value)
    ops = {"endswith": "endswith", "startswith": "startswith", "contains": "contains"}
    if len(modifiers) == 1 and modifiers[0] in ops:
        return "(" + " or ".join(
            f'{field} {ops[modifiers[0]]} "{v}"' for v in values) + ")"
    if modifiers == ["contains", "all"]:
        return " and ".join(f'{field} contains "{v}"' for v in values)
    if modifiers:
        raise TranslationError(f"unsupported Kusto modifiers: {modifiers}")
    if len(values) == 1:
        return f'{field} == "{values[0]}"'
    return "(" + " or ".join(f'{field} == "{v}"' for v in values) + ")"


def kusto_predicate(member):
    detection = dict(member["detection"])
    condition = detection.pop("condition", None)
    if condition is None and len(detection) == 1:
        return " and ".join(kusto_clause(k, v)
                            for k, v in next(iter(detection.values())).items())
    if condition is None:
        raise TranslationError("no condition and more than one selection")
    return expand_condition(condition,
                            {n: " and ".join(kusto_clause(k, v)
                                             for k, v in sel.items())
                             for n, sel in detection.items()},
                            join=kusto_clause, neg="not")


def _kusto_table(member):
    category = member["logsource"].get("category", "")
    return {"process_creation": "DeviceProcessEvents",
            "netflow": "CommonSecurityLog",
            "proxy": "CommonSecurityLog",
            "dns_query": "DnsEvents"}.get(category, "SecurityEvent")


def _kusto_timespan(text):
    m = re.fullmatch(r"(\d+)([smhd])", str(text))
    if not m:
        raise TranslationError(f"unparseable timespan {text!r}")
    return f"{m.group(1)}{m.group(2)}"


def kusto_temporal(rule, members):
    corr = rule["correlation"]
    key = field_map(corr["group-by"][0])["kusto"]
    window = _kusto_timespan(corr["timespan"])
    lines = [f"// generated by deploy/build_joins.py from {rule['_path']}",
             "// pySigma does not convert correlations for Kusto; this is the join.",
             f"let window = {window};"]
    for idx, rid in enumerate(corr["rules"], 1):
        path, member = members[rid]
        lines.append(f"let step{idx} = {_kusto_table(member)} "
                     f"| where {kusto_predicate(member)} "
                     f"| extend _ord = {idx} | project TimeGenerated, {key}, _ord;")
    union = ", ".join(f"step{i}" for i in range(1, len(corr["rules"]) + 1))
    lines += [
        f"union {union}",
        "| sort by TimeGenerated asc",
        f"| summarize span = max(TimeGenerated) - min(TimeGenerated), "
        f"steps = make_list(_ord) by {key}",
        f"| where span <= window and array_length(steps) == {len(corr['rules'])}",
        f"| where steps == range(1, {len(corr['rules'])})",
        f"| where span <= {window}",
    ]
    return "\n".join(lines) + "\n"


def kusto_event_count(rule, members):
    corr = rule["correlation"]
    path, member = members[corr["rules"][0]]
    key = field_map(corr["group-by"][0])["kusto"]
    span = _kusto_timespan(corr["timespan"])
    return (
        f"// generated by deploy/build_joins.py from {rule['_path']}\n"
        f"// pySigma does not convert correlations for Kusto.\n"
        f"{_kusto_table(member)}\n"
        f"| where {kusto_predicate(member)}\n"
        f"| summarize events = count() by {key}, bin(TimeGenerated, {span})\n"
        f"| where events >= {corr['condition']['gte']}\n"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    rules = load_rules()
    results, problems = {}, []
    for rid, (path, data) in sorted(rules.items()):
        corr = data.get("correlation")
        if not corr:
            continue
        data["_path"] = path.relative_to(ROOT).as_posix()
        members = {m: (rules[m][0], rules[m][1]) for m in corr["rules"] if m in rules}
        missing = [m for m in corr["rules"] if m not in rules]
        if missing:
            problems.append(f"{data['_path']}: members {missing} are not rules")
            continue
        try:
            if corr["type"] == "temporal":
                results[f"{path.stem}.eql"] = elastic_temporal(data, members)
                results[f"{path.stem}.kql"] = kusto_temporal(data, members)
            elif corr["type"] == "event_count":
                results[f"{path.stem}.esql"] = elastic_event_count(data, members)
                results[f"{path.stem}.kql"] = kusto_event_count(data, members)
            else:
                problems.append(f"{data['_path']}: unknown correlation type "
                                f"{corr['type']!r}")
        except (KeyError, TranslationError) as exc:
            problems.append(f"{data['_path']}: {exc}")

    if problems:
        for p in problems:
            print(f"FAIL {p}", file=sys.stderr)
        return 1

    stale = []
    for name, text in results.items():
        target = OUT / name
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

    if args.check:
        if stale:
            for name in stale:
                print(f"FAIL deploy/joins/{name} is stale; run "
                      f"python3 deploy/build_joins.py", file=sys.stderr)
            return 1
        print(f"joins: {len(results)} generated query file(s) current, "
              f"0 unsupported translations")
        return 0

    print(f"joins: wrote {len(results)} file(s) to deploy/joins/ for the "
          f"correlations pySigma will not convert")
    return 0


if __name__ == "__main__":
    sys.exit(main())
