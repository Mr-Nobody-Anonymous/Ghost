#!/usr/bin/env python3
"""Emit the event each rule should see — and prove the rule actually matches it.

Makes no system calls. This is a tabletop artifact: it tells a lab operator what
telemetry to expect for a behaviour, and it is *checkable*.

The previous version emitted seven hand-written descriptors that no rule matched
(0/32). It called them "expected events", which reads like evidence while being
prose in JSON. It also cited `sigma/wmi_event_subscription_persistence.yml` and a
`T1562.001` tag that no longer exists, so the file drifted silently.

Now the descriptor is derived from the rule — the same generator the fixtures use
— and every event is run through the evaluator before printing. If a rule does
not match its own expected event, this script fails; that is the only thing that
makes the output worth reading.

Usage:
  python3 emulation/emit_expected_events.py            # table + verification
  python3 emulation/emit_expected_events.py --json     # machine-readable
  python3 emulation/emit_expected_events.py --rule <id-prefix>
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))

import evaluate


def build(rules, only=None):
    out = []
    for rid, doc in rules.items():
        if only and not rid.startswith(only):
            continue
        attack = next((t.split(".", 1)[1].upper() for t in doc.get("tags", [])
                       if str(t).lower().startswith("attack.t")), "")
        entry = {
            "rule_id": rid,
            "rule": doc.get("path") or f"sigma/{rid}.yml",
            "title": doc.get("title"),
            "attack": attack,
            "logsource": doc.get("logsource", {}),
            "correlation": bool(doc.get("correlation")),
        }
        if doc.get("correlation"):
            entry["expected"] = {"members": doc["correlation"].get("rules", []),
                                 "type": doc["correlation"].get("type"),
                                 "timespan": doc["correlation"].get("timespan")}
            entry["verified"] = "n/a - correlation; see fixtures/per_rule"
            out.append(entry)
            continue
        events = evaluate.candidate_events(doc)
        if not events:
            entry["expected"] = None
            entry["verified"] = "NO CANDIDATE EVENT - rule may be unmatchable"
            out.append(entry)
            continue
        matched = [e for e in events if evaluate.eval_detection(doc, e)]
        entry["expected"] = matched[0] if matched else events[0]
        entry["verified"] = bool(matched)
        out.append(entry)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--rule", help="id prefix")
    args = ap.parse_args()

    rules = evaluate.load_collection(ROOT)
    # record the file each rule came from, for the human table
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        import yaml
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("id") in rules:
            rules[doc["id"]]["path"] = f.relative_to(ROOT).as_posix()

    rows = build(rules, args.rule)
    bad = [r for r in rows if r["verified"] is False]

    if args.json:
        print(json.dumps({"generated_utc": None, "rules": rows}, indent=2))
    else:
        print(f"{'ATT&CK':10} {'verified':8} {'rule'}")
        for r in rows:
            mark = ("yes" if r["verified"] is True else
                    "n/a" if r["verified"] == "n/a - correlation; see fixtures/per_rule"
                    else "NO")
            print(f"{r['attack']:10} {mark:8} {r['title'][:58]}")
        print(f"\n{len(rows)} rules, {len(bad)} without a matching expected event")
    if bad:
        print("FAIL: a rule that does not match its own expected event cannot be "
              "verified by any capture; fix the rule before trusting the descriptor",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
