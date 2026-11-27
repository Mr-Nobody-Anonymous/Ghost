#!/usr/bin/env python3
"""Offline Sigma evaluator for this lab.

Loads the whole rule collection (so correlation rules can resolve referenced
IDs), matches rules against concrete fixture events with real Sigma field
modifiers and condition grammar, evaluates ordered sequences, and asserts the
values on the matched event rather than only a match count.

No network, no target contact, no payload execution.
"""
import argparse
import datetime
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


def _compare(actual, expected, mods, field):
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
        return any(re.search(str(v), actual_s) for v in values)
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


def sequence_events(doc, rules):
    """Build a concrete event sequence from a correlation rule's member rules."""
    corr = doc.get("correlation", {}) or {}
    events = []
    for i, rid in enumerate(corr.get("rules", [])):
        member = rules.get(rid)
        if not member:
            continue
        det = member.get("detection", {}) or {}
        event = {"_ts": i * 3}
        for name, body in det.items():
            if name == "condition" or name.startswith("filter") or not isinstance(body, dict):
                continue
            for key, value in body.items():
                if key == "condition":
                    continue
                parts = key.split("|")
                field, mod = parts[0], (parts[1] if len(parts) > 1 else "")
                val = value[0] if isinstance(value, list) else value
                if field == "EventID":
                    event[field] = int(val) if str(val).isdigit() else 1
                elif mod == "endswith":
                    event[field] = "C:\\Windows\\System32" + str(val)
                elif mod == "contains":
                    event[field] = "C:\\Users\\lab\\" + str(val)
                elif mod == "re":
                    event[field] = "abcdefghijklmnop.top" if "[a-z]{14,}" in str(val) else str(val).strip("^$")
                else:
                    event[field] = val
            break
        events.append(event)
    return events


def eval_sequence(doc, events, rules):
    corr = doc.get("correlation", {})
    members = [rules.get(r) for r in corr.get("rules", [])]
    if any(m is None for m in members):
        return False, "correlation member not found in collection"
    group_by = corr.get("group-by", []) or []
    timespan = _parse_span(corr.get("timespan", 0))
    ordered = bool(corr.get("ordered", False))
    groups = {}
    for ev in events:
        key = tuple(str(ev.get(g, "")) for g in group_by)
        groups.setdefault(key, []).append(ev)
    for evs in groups.values():
        evs.sort(key=lambda e: _parse_span(e.get("_ts", 0)))
        indexes = []
        cursor = 0
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
        if len(indexes) == len(members):
            first = _parse_span(evs[indexes[0]].get("_ts", 0))
            last = _parse_span(evs[indexes[-1]].get("_ts", 0))
            if not timespan or last - first <= timespan:
                return True, "sequence matched"
            return False, "sequence outside timespan"
    return False, "no sequence match"


def eval_rule(doc, events, rules):
    if "correlation" in doc:
        corr = doc["correlation"]
        if corr.get("type") == "frequency":
            member = rules.get((corr.get("rules") or [None])[0])
            if not member:
                return False, "frequency member not found"
            gte = int((corr.get("condition", {}) or {}).get("gte", 1))
            count = sum(1 for ev in events if eval_detection(member, ev))
            return count >= gte, f"frequency count={count} gte={gte}"
        return eval_sequence(doc, events, rules)
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
