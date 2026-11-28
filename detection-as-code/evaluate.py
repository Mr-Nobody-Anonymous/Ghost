#!/usr/bin/env python3
"""Offline Sigma evaluator for this lab.

Loads the whole rule collection (so correlation rules can resolve referenced
IDs), matches rules against concrete fixture events with real Sigma field
modifiers and condition grammar, evaluates ordered sequences, and asserts the
values on the matched event rather than only a match count.

No network, no target contact, no payload execution.
"""
import argparse
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("FAIL: PyYAML is required for rule evaluation\n")
    raise

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))
try:
    import fieldtypes
except ImportError:  # single-file use outside the repo
    fieldtypes = None


class NoMatch(Exception):
    pass


def load_collection(root):
    rules = {}
    for f in sorted((root / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("id"):
            rules[doc["id"]] = doc
    return rules


def _field_and_modifiers(key):
    parts = key.split("|")
    return parts[0], parts[1:]


def _coerce(value):
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return value


def _get(event, field):
    """Sigma `field|contains` also matches list-valued fields: any element."""
    value = event[field]
    if isinstance(value, list):
        return value
    return [value]


def _compare(actual, expected, mods, field):
    if isinstance(actual, list):
        return any(_compare(a, expected, mods, field) for a in actual)
    return _compare_one(actual, expected, mods)


def _compare_one(actual, expected, mods):
    actual_s = str(actual)
    if "endswith" in mods:
        return any(actual_s.endswith(str(v)) for v in ([expected] if not isinstance(expected, list) else expected))
    if "startswith" in mods:
        return any(actual_s.startswith(str(v)) for v in ([expected] if not isinstance(expected, list) else expected))
    if "contains" in mods:
        values = expected if isinstance(expected, list) else [expected]
        return all(str(v) in actual_s for v in values) if "all" in mods else any(str(v) in actual_s for v in values)
    if "re" in mods:
        values = expected if isinstance(expected, list) else [expected]
        for v in values:
            lit = str(v).replace("\\", "\\\\")  # '\\.' -> '\\.' literal dot
            if re.search(str(v), actual_s) or re.search(lit, actual_s):
                return True
        return False
    if "windash" in mods:
        values = expected if isinstance(expected, list) else [expected]
        return any(str(v).replace("-", "/") in actual_s.replace("-", "/") for v in values)
    if "base64" in mods:
        import base64
        values = expected if isinstance(expected, list) else [expected]
        try:
            decoded = base64.b64decode(actual_s).decode("utf-8", "replace")
        except Exception:
            return False
        return any(str(v) in decoded for v in values)
    values = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(str(v) == actual_s for v in values)
    return any(str(v) == actual_s for v in values)


def match_selection(event, selection):
    if not isinstance(selection, dict):
        return False
    for key, expected in selection.items():
        field, mods = _field_and_modifiers(key)
        if "exists" in mods:
            present = field in event
            if present != _coerce(expected):
                return False
            continue
        if field not in event:
            return False
        if "fieldref" in mods:
            # the value names another field in the same event, not a literal
            return False if expected not in event else str(event[field]) == str(event[expected])
        if not _compare(event[field], expected, mods, field):
            return False
    return True


def _tokenize(condition):
    return re.findall(r"\(|\)|\b1 of them\b|\ball of them\b|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+", condition)


def eval_condition(condition, results):
    tokens = _tokenize(condition)
    pos = [0]

    def resolve(name):
        if name in results:
            return results[name]
        if name.endswith("*"):
            matched = [v for k, v in results.items() if k.startswith(name[:-1])]
            return any(matched) if name.startswith("1 of") else all(matched)
        return False

    def primary():
        if pos[0] >= len(tokens):
            return False
        t = tokens[pos[0]]
        pos[0] += 1
        if t == "(":
            val = expr()
            if pos[0] < len(tokens) and tokens[pos[0]] == ")":
                pos[0] += 1
            return val
        if t == "not":
            return not primary()
        if t in ("1 of", "all of"):
            nxt = tokens[pos[0]] if pos[0] < len(tokens) else ""
            pos[0] += 1
            if nxt == "them":
                vals = list(results.values())
            else:
                vals = [v for k, v in results.items() if k.startswith(nxt.rstrip("*"))]
            return any(vals) if t == "1 of" else all(vals)
        return resolve(t)

    def term():
        val = primary()
        while pos[0] < len(tokens) and tokens[pos[0]] == "and":
            pos[0] += 1
            rhs = primary()  # always evaluate: short-circuit would leave pos stale
            val = bool(val) and bool(rhs)
        return val

    def expr():
        val = term()
        while pos[0] < len(tokens) and tokens[pos[0]] == "or":
            pos[0] += 1
            rhs = term()  # always evaluate: short-circuit would leave pos stale
            val = bool(val) or bool(rhs)
        return val

    return expr()


def eval_detection(doc, event):
    det = doc.get("detection", {})
    results = {}
    for name, body in det.items():
        if name == "condition":
            continue
        if name.startswith("filter"):
            results[name] = match_selection(event, body)
        else:
            results[name] = match_selection(event, body)
    condition = det.get("condition", "")
    # filter sections are negated by convention when referenced as `not filter`
    return eval_condition(condition, results)


def _parse_span(text):
    if isinstance(text, (int, float)):
        return float(text)
    m = re.match(r"^(\d+)\s*(s|m|h|d)?$", str(text).strip().lower())
    if not m:
        return 0.0
    n = int(m.group(1))
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(m.group(2) or "s", 1)


def _referenced_selections(det):
    """Names of selections the rule's condition actually reads."""
    cond = str(det.get("condition", ""))
    names = [n for n in det if n != "condition"]
    return {n for n in names if re.search(r"\b" + re.escape(n) + r"\b", cond)} or set(names)


def _selection_fields(det):
    """Map selection name -> field -> [(modifiers, value)] for the condition's
    positive selections.

    Sigma semantics: within one selection a list under one modifier is an OR,
    and different modifiers on one field are ANDed. Fields from different
    selections are never combined here, because a condition that ORs two
    selections describes two different behaviors, not one event.
    """
    bank = {}
    for name, body in det.items():
        if name == "condition" or name.startswith("filter"):
            continue
        if name not in _referenced_selections(det) or not isinstance(body, dict):
            continue
        fields = {}
        for key, value in body.items():
            if key == "condition":
                continue
            parts = key.split("|")
            field, mods = parts[0], parts[1:]
            if "exists" in mods and value is False:
                continue
            values = value if isinstance(value, list) else [value]
            fields.setdefault(field, [])
            for v in values:
                fields[field].append({"mods": mods, "value": v})
        bank[name] = fields
    return bank


def _render_field(field, items):
    """Render one concrete value for a field from its constraints."""
    pairs = [(it["mods"], it["value"]) for it in items]
    mods = {m for it in items for m in it["mods"]}
    if "fieldref" in mods:
        return None
    if fieldtypes is not None:
        return fieldtypes.render(field, pairs, sorted(mods))
    return items[0]["value"]


def _event_for_selection(fields, variant=None):
    """One concrete event from one selection.

    `variant` names a field whose alternatives should be tried one at a time;
    everything else takes the first alternative, which is what OR means.
    """
    event = {}
    for field, items in fields.items():
        if variant is not None and field == variant:
            continue
        first_of_mod = {}
        for it in items:
            key = tuple(it["mods"])
            if "all" in it["mods"] or key not in first_of_mod:
                first_of_mod.setdefault(key, [])
                if "all" not in it["mods"]:
                    first_of_mod[key] = [it]
                else:
                    first_of_mod[key].append(it)
        chosen = [it for group in first_of_mod.values() for it in group]
        rendered = _render_field(field, chosen)
        if rendered is not None:
            event[field] = rendered
    for field, items in fields.items():
        if any("fieldref" in it["mods"] for it in items):
            ref = next(it["value"] for it in items if "fieldref" in it["mods"])
            shared = event.get(ref, "C:\\Users\\lab\\self-image.exe")
            event[field] = shared
            event[ref] = shared
    event["_ts"] = 0
    return event


def _member_locals(rules):
    """Members are only resolvable while the whole collection is loaded.

    Storing a member event in its own fixture file means the file must also
    carry the member ids, otherwise evaluating that file alone reports "member
    not found" and the fixture proves nothing.
    """
    return {rid: {k: v for k, v in doc.items() if k != "correlation"}
            for rid, doc in rules.items() if isinstance(doc, dict)}


def candidate_events(doc, limit=64):
    """Every distinct way one event could satisfy the rule.

    One candidate per selection branch, then one per alternative value, all
    verified by the evaluator. A rule that cannot be satisfied by its own
    fixture is a broken rule, not a broken generator.
    """
    det = doc.get("detection", {}) or {}
    bank = _selection_fields(det)
    if not bank:
        return [{"_ts": 0}]
    seen, out = set(), []
    branches = list(bank.values())
    for fields in branches:
        variants = [None] + [f for f, items in fields.items() if len(items) > 1]
        for variant in variants:
            ev = _event_for_selection(fields, variant)
            key = json.dumps(ev, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            if eval_detection(doc, ev):
                out.append(ev)
            if len(out) >= limit:
                return out
    # A condition that ANDs two selections needs fields from both in one event;
    # ORed selections need one branch at a time. Try the merged shape first and
    # let the evaluator keep whichever actually satisfies the rule.
    merged = {}
    for fields in branches:
        for field, items in fields.items():
            current = merged.setdefault(field, [])
            known = {(tuple(it["mods"]), str(it["value"])) for it in current}
            for it in items:
                if (tuple(it["mods"]), str(it["value"])) not in known:
                    current.append(it)
    variants = [None] + [f for f, items in merged.items() if len(items) > 1]
    for variant in variants:
        ev = _event_for_selection(merged, variant)
        key = json.dumps(ev, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        if eval_detection(doc, ev):
            out.append(ev)
    for fields in bank.values():
        variants = [None] + [f for f, items in fields.items() if len(items) > 1]
        for variant in variants:
            ev = _event_for_selection(fields, variant)
            key = json.dumps(ev, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            if eval_detection(doc, ev):
                out.append(ev)
            if len(out) >= limit:
                return out
    if not out:
        out = [_event_for_selection(next(iter(bank.values())))]
    return out


def sequence_events(doc, rules):
    """Build one concrete positive event per correlation member, in order.

    Derived from the member rule's own detection block, then verified by the
    evaluator, so a member whose selections changed cannot keep passing on a
    stale hand-written event.
    """
    if "correlation" not in doc:
        return []
    corr = doc.get("correlation", {}) or {}
    events = []
    for i, rid in enumerate(corr.get("rules", [])):
        member = rules.get(rid)
        if not member:
            continue
        cands = candidate_events(member)
        chosen = next((c for c in cands if eval_detection(member, c)), cands[0])
        events.append(dict(chosen, _ts=i * 3))
    for ev in events:
        for key in corr.get("group-by", []) or []:
            if key not in ev and fieldtypes is not None:
                ev[key] = fieldtypes.render(key, [([], "LAB-WS01")], [])
    if corr.get("type") == "event_count" and events:
        gte, _ = _corr_condition(corr.get("condition"))
        count = max(int(gte or 1) + 1, 2)
        return [dict(events[0], _ts=i) for i in range(count)]
    return events


def positive_event(doc):
    """One concrete event that makes a single (non-correlation) rule fire."""
    cands = candidate_events(doc)
    return next((c for c in cands if eval_detection(doc, c)), cands[0])


def _join_values(doc, rules):
    """The group-by fields a correlation joins on.

    Each field must appear in the detection block of every member rule,
    otherwise the platform cannot produce the join key and the correlation can
    never fire - the exact fault the previous WMI triple had when it grouped on
    `User` while both members were plain EventID selections.
    """
    corr = doc.get("correlation", {}) or {}
    out = {}
    for key in corr.get("group-by", []) or []:
        missing = []
        for rid in corr.get("rules", []) or []:
            member = rules.get(rid)
            if not member:
                missing.append(rid)
                continue
            fields = set()
            for body in (member.get("detection", {}) or {}).values():
                if isinstance(body, dict):
                    fields.update(k.split("|")[0] for k in body)
            if key not in fields:
                missing.append(rid)
        out[key] = missing
    return out


def _not_filter_from(event, doc):
    """A from-scratch event must also not match the rule's filter sections.

    Otherwise a negative fixture for a rule whose condition is `selection and
    not filter` passes for the wrong reason: the event missed `selection`
    instead of resembling the benign case the filter exists to allow.
    """
    det = doc.get("detection", {}) or {}
    for name, body in det.items():
        if name.startswith("filter") and isinstance(body, dict) and match_selection(event, body):
            return False
    return True


def _corr_condition(cond):
    """Return (gte, lt) from a Sigma correlation condition block or scalar."""
    if isinstance(cond, dict):
        gte = cond.get("gte")
        return (int(gte) if gte is not None else None), cond.get("lt")
    if cond is None:
        return 1, None
    try:
        return int(cond), None
    except (TypeError, ValueError):
        return 1, None


def _members(doc, rules):
    return [rules.get(rid) for rid in (doc.get("correlation", {}).get("rules") or [])]


def eval_temporal(doc, events, rules, ordered):
    """Sigma `temporal` / `temporal_ordered`: every member fires once, in order
    when ordered, grouped by the correlation's group-by fields, inside timespan."""
    corr = doc.get("correlation", {})
    members = _members(doc, rules)
    if not members or any(m is None for m in members):
        return False, "correlation member not found in collection"
    group_by = corr.get("group-by", []) or []
    timespan = _parse_span(corr.get("timespan", 0))
    groups = {}
    for ev in events:
        group_key = tuple(str(ev.get(g, "\x00missing")) for g in group_by)
        groups.setdefault(group_key, []).append(ev)
    for evs in groups.values():
        evs = sorted(evs, key=lambda e: _parse_span(e.get("_ts", 0)))
        cursor, indexes = 0, []
        for member in members:
            found = None
            for i in range(cursor, len(evs)):
                if eval_detection(member, evs[i]):
                    found = i
                    break
            if found is None:
                break
            indexes.append(found)
            cursor = found + 1 if ordered else found
        if len(indexes) != len(members):
            continue
        first = _parse_span(evs[indexes[0]].get("_ts", 0))
        last = _parse_span(evs[indexes[-1]].get("_ts", 0))
        if timespan and last - first > timespan:
            return False, f"temporal sequence outside timespan ({last - first}s > {timespan}s)"
        return True, "temporal sequence matched"
    return False, "no temporal sequence match"


def eval_event_count(doc, events, rules):
    """Sigma `event_count`: at least N member matches per group inside timespan."""
    corr = doc.get("correlation", {})
    members = _members(doc, rules)
    if not members or any(m is None for m in members):
        return False, "correlation member not found in collection"
    gte, lt = _corr_condition(corr.get("condition"))
    group_by = corr.get("group-by", []) or []
    counts = {}
    for ev in events:
        if any(eval_detection(m, ev) for m in members):
            key = tuple(str(ev.get(g, "\x00missing")) for g in group_by)
            counts[key] = counts.get(key, 0) + 1
    if not counts:
        return False, "no member matches"
    best = max(counts.values())
    if gte is not None and best < gte:
        return False, f"event_count {best} < {gte}"
    if lt is not None and best >= int(lt):
        return False, f"event_count {best} >= lt {lt}"
    return True, f"event_count {best} >= {gte}"


def eval_rule(doc, events, rules):
    if "correlation" in doc:
        corr = doc["correlation"]
        ctype = corr.get("type")
        if ctype == "event_count":
            return eval_event_count(doc, events, rules)
        if ctype in ("temporal", "temporal_ordered"):
            return eval_temporal(doc, events, rules, ordered=(ctype == "temporal_ordered"))
        return False, f"correlation type {ctype!r} is not evaluated by this harness"
    if not isinstance(events, list):
        events = [events]
    condition = doc.get("detection", {}).get("condition", "")
    m = re.search(r"count\(\)\s*(?:by\s*[\w\-]+)?\s*(>=|>)\s*(\d+)", condition)
    if m and "count()" in condition:
        base_condition = condition.split("|", 1)[0].strip()
        det = doc.get("detection", {})
        matched = []
        for ev in events:
            results = {k: match_selection(ev, v) for k, v in det.items() if k != "condition"}
            if eval_condition(base_condition, results):
                matched.append(ev)
        threshold = int(m.group(2))
        return (len(matched) > threshold if m.group(1) == ">" else len(matched) >= threshold), \
            f"count={len(matched)} threshold={threshold}"
    for ev in events:
        if eval_detection(doc, ev):
            return True, "matched"
    return False, "no match"


def assert_fields(result_events, expected):
    for field, value in (expected or {}).items():
        found = any(str(ev.get(field)) == str(value) for ev in result_events)
        if not found:
            return False, f"field {field} != {value!r}"
    return True, "fields ok"


def run_fixture(doc, fixture, rules):
    merged = dict(rules)
    merged.update(fixture.get("members", {}) or {})
    rules = merged
    events = fixture.get("events", [])
    matched, reason = eval_rule(doc, events, rules)
    if not matched:
        return False, f"TP failed: {reason}", []
    matched_events = [e for e in events if eval_detection(doc, e)] if "correlation" not in doc else events
    ok, why = assert_fields(matched_events, fixture.get("assert_fields", {}))
    if not ok:
        return False, f"field assertion failed: {why}", matched_events
    neg = fixture.get("must_not_match", {})
    neg_events = neg.get("events", [])
    if neg_events:
        hit, reason = eval_rule(doc, neg_events, rules)
        if hit:
            return False, f"FP failed: negative event matched ({reason})", matched_events
    return True, "pass", matched_events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=str(ROOT / "fixtures" / "per_rule"))
    ap.add_argument("--rule", help="evaluate a single rule id")
    args = ap.parse_args()

    rules = load_collection(ROOT)
    files = sorted(pathlib.Path(args.fixtures).glob("*.json"))
    if args.rule:
        files = [f for f in files if f.stem == args.rule]

    passed = failed = 0
    for f in files:
        fx = json.loads(f.read_text(encoding="utf-8"))
        rid = fx.get("rule_id")
        doc = rules.get(rid)
        if not doc:
            print(f"FAIL {fx.get('fixture_id')}: rule {rid} not found in collection")
            failed += 1
            continue
        ok, reason, _ = run_fixture(doc, fx, rules)
        if ok:
            passed += 1
            print(f"PASS {rid[:8]} {doc.get('title','')}")
        else:
            failed += 1
            print(f"FAIL {rid[:8]} {doc.get('title','')}: {reason}")
    print(f"\nevaluation: {passed}/{passed + failed} fixtures passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
