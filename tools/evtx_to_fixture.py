#!/usr/bin/env python3
"""Convert captured Windows event XML into a per-rule fixture.

Accepts `wevtutil qe <log> /f:xml /e:true` output (one or more <Event> nodes)
or a single exported .evtx rendered to XML. No implant is needed to run this:
it only parses events a lab operator already captured.

Usage:
  wevtutil qe Security /q:"*[System[(EventID=4663)]]" /f:xml /e:true > cpu.xml
  python3 tools/evtx_to_fixture.py --input cpu.xml --rule-id <id> --output fixtures/per_rule/<id>.json
"""
import argparse
import json
import pathlib
import re
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_events(text):
    wrapped = "<Events>" + text + "</Events>" if not text.lstrip().startswith("<Events") else text
    root = ET.fromstring(wrapped)
    events = []
    for ev in root.iter(NS + "Event"):
        out = {}
        system = ev.find(NS + "System")
        if system is not None:
            eid = system.find(NS + "EventID")
            if eid is not None:
                out["EventID"] = int(eid.text or 0)
            for tag in ("Computer", "Execution", "Correlation"):
                node = system.find(NS + tag)
                if node is not None:
                    out[tag] = node.attrib.get("ProcessID") or (node.text or "")
        data = ev.find(NS + "EventData")
        if data is not None:
            for d in data.findall(NS + "Data"):
                name = d.attrib.get("Name")
                if name:
                    out[name] = d.text or ""
        events.append(out)
    return events


def normalise(events):
    """Strip host-specific identifiers but keep the field shape and values."""
    for ev in events:
        for key in ("Computer", "SubjectUserSid", "TargetUserSid"):
            if key in ev:
                ev[key] = "<host-or-user>"
        if "Execution" in ev and isinstance(ev["Execution"], str):
            ev["Execution"] = "<process-id>"
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--rule-id", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    text = pathlib.Path(args.input).read_text(encoding="utf-8", errors="replace")
    events = normalise(parse_events(text))
    if not events:
        raise SystemExit("no events parsed")

    fixture = {
        "fixture_id": "FX-" + args.rule_id[:8],
        "rule_id": args.rule_id,
        "status": "captured",
        "sample_ref": "PIN-0000",
        "events": events,
        "assert_fields": {k: events[0][k] for k in events[0] if k != "Computer"},
        "note": "Parsed from captured event XML. Review before promoting to validated.",
    }
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} with {len(events)} events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
