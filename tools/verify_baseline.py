#!/usr/bin/env python3
"""Verify a clean baseline capture against the pinned config and the rules.

This is gate 4 of docs/maturity.md, the one nothing in this repo could check:
"the telemetry a rule needs actually exists on this host". The generated
fixtures prove a rule is internally consistent; they cannot prove that Sysmon
on *your* box emits `TargetObject` at all, because Sysmon silently drops
selections whose event type is not enabled.

Run it against a capture from an idle host:

    wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:true > baseline.xml
    python3 tools/verify_baseline.py --input baseline.xml

It reports, per rule, whether every EventID the rule selects appears in the
capture and whether the fields it reads are present on those events. A rule
whose event never appears is not "quiet": it is unmatched, and reporting it as
zero alerts would be a lie.
"""
import argparse
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))

import evaluate  # noqa: E402
import yaml  # noqa: E402
from evtx_to_fixture import parse_events  # noqa: E402

# Fields that exist only on the *event* a rule matches, grouped by Sysmon event.
# Used to explain "field missing" without pretending the baseline is wrong: an
# idle host legitimately has no CreateRemoteThread events.
STRUCTURAL = {
    1: {"Image", "CommandLine", "ParentImage", "ProcessGuid", "ParentProcessGuid"},
    3: {"Image", "DestinationIp", "DestinationPort"},
    8: {"SourceImage", "TargetImage"},
    10: {"SourceImage", "TargetImage", "GrantedAccess"},
    11: {"TargetFilename", "Image"},
    12: {"EventType", "TargetObject"},
    13: {"EventType", "TargetObject", "Details"},
    19: {"EventNamespace", "Name", "Query"},
    20: {"Name", "Destination", "Consumer"},
    21: {"Consumer", "Filter"},
    22: {"QueryName", "Image"},
    23: {"TargetFilename", "Image"},
    26: {"TargetFilename", "Image"},
}


def selected_eids(doc):
    det = doc.get("detection") or {}
    out = set()
    for name, body in det.items():
        if name == "condition" or not isinstance(body, dict):
            continue
        eid = body.get("EventID")
        if isinstance(eid, int):
            out.add(eid)
        elif isinstance(eid, list):
            out.update(x for x in eid if isinstance(x, int))
    corr = doc.get("correlation") or {}
    return out, corr.get("rules") or []


def fields_read(doc):
    det = doc.get("detection") or {}
    out = set()
    for name, body in det.items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for key in body:
            out.add(key.split("|")[0])
    out.discard("EventID")
    return out


def check_document(doc, by_eid, all_events, rules):
    """Return (eids_present, missing_eids, missing_fields)."""
    eids, members = selected_eids(doc)
    if members:  # correlation: check its members, it emits nothing itself
        present, missing, fields = set(), set(), {}
        for mid in members:
            m = rules.get(mid)
            if m:
                p, mi, f = check_document(m, by_eid, all_events, rules)
                present |= p
                missing |= mi
                fields.update({k: v for k, v in f.items() if v})
        return present, missing, fields
    present = {e for e in eids if by_eid.get(e)}
    missing = eids - present
    # field check only over the events the rule would read
    pool = [ev for e in eids for ev in by_eid.get(e, [])]
    absent = {}
    for field in fields_read(doc):
        if not any(field in ev for ev in pool):
            absent[field] = True
    return present, missing, absent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="wevtutil /f:xml output")
    ap.add_argument("--json", help="write a machine-readable report here")
    ap.add_argument("--allow-missing", action="store_true",
                    help="exit 0 even when rules are unmatched (still reports)")
    args = ap.parse_args()

    events = parse_events(pathlib.Path(args.input).read_text(encoding="utf-8", errors="replace"))
    if not events:
        raise SystemExit("no events parsed - is this really wevtutil /f:xml output?")
    by_eid = collections.defaultdict(list)
    for ev in events:
        by_eid[ev.get("EventID")].append(ev)

    manifest = json.loads((ROOT / "baseline" / "manifest.json").read_text(encoding="utf-8"))
    sysmon_pin = manifest.get("sysmon_config_sha256")
    import hashlib
    actual = hashlib.sha256((ROOT / "telemetry" / "sysmon-config.xml").read_bytes()).hexdigest()
    pin_ok = (sysmon_pin == actual) if sysmon_pin else None

    rules = evaluate.load_collection(ROOT)
    report = {"events": len(events), "event_ids": {str(k): len(v) for k, v in sorted(by_eid.items(), key=lambda x: (x[0] is None, x[0]))},
              "config_pin_matches": pin_ok, "rules": {}}
    bad = 0
    for rid, doc in rules.items():
        present, missing, absent = check_document(doc, by_eid, events, rules)
        matched_by_baseline = bool(present) and not missing
        report["rules"][rid] = {
            "title": doc.get("title"),
            "event_ids_present": sorted(present),
            "event_ids_missing": sorted(missing),
            "fields_absent_in_capture": sorted(absent),
            "verdict": "matched" if matched_by_baseline and not absent else
                       ("unmatched-eid" if missing else "unmatched-field"),
        }
        if missing or absent:
            bad += 1

    print(f"baseline: {len(events)} events, {len(by_eid)} distinct event IDs")
    print(f"config pin matches telemetry/sysmon-config.xml: {pin_ok}")
    if not any(by_eid.get(e) for e in STRUCTURAL):
        print("note: not a single process-create event in the capture - "
              "this is not a usable baseline")
    for rid, row in report["rules"].items():
        if row["verdict"] != "matched":
            detail = []
            if row["event_ids_missing"]:
                detail.append("missing EID " + ",".join(map(str, row["event_ids_missing"])))
            if row["fields_absent_in_capture"]:
                detail.append("absent fields " + ",".join(row["fields_absent_in_capture"]))
            print(f"  {row['verdict']:16} {row['title'][:58]:58} {'; '.join(detail)}")
    print(f"\n{len(report['rules']) - bad}/{len(report['rules'])} rules have their "
          f"EventIDs and fields in this capture")
    print("An unmatched rule on an idle host is expected for behavior that did not "
          "occur. It is NOT evidence the rule works - that needs the per-rule "
          "capture in tools/capture_kit.py.")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    ok = pin_ok is not False and (args.allow_missing or bad == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
