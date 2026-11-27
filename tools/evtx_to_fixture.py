#!/usr/bin/env python3
"""Convert captured Windows event XML into a *checked* per-rule fixture.

Accepts `wevtutil qe <log> /f:xml /e:true` output (one or more <Event> nodes)
or an exported .evtx rendered to XML. No implant is needed to run this: it only
parses events a lab operator already captured.

The previous version of this script had three defects that made a "captured"
fixture meaningless:

1. It wrote `status: captured` without ever checking that the rule matched the
   captured event. A capture that does not match is a *finding*, not a fixture.
2. It defaulted `--output` into `fixtures/per_rule/`, overwriting the generated
   fixture and destroying the only evidence of what the rule was supposed to
   match. Captures go to `fixtures/captured/`.
3. It replaced `Computer` with `<host-or-user>`. `Computer` is the correlation
   join key for the WMI and tamper sequences; scrubbing it makes the fixture
   unevaluatable.

It also now refuses to mark a capture `captured` unless the rule actually fires,
and it records the Sysmon/config hashes so a fixture can be tied to the box it
came off.

Usage:
  wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=1)]]" \
      /f:xml /e:true > cap.xml
  python3 tools/evtx_to_fixture.py --input cap.xml --rule-id <uuid>
  python3 tools/evtx_to_fixture.py --input cap.xml --rule-id <uuid> --allow-no-match
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))

import evaluate  # noqa: E402
import xml.etree.ElementTree as ET  # noqa: E402

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Never invented, only masked: a host name or SID is not a detection field, and
# keeping the real one in a public repo leaks lab identity. Computer is kept
# because correlations join on it.
MASK = {"SubjectUserSid", "TargetUserSid", "SubjectLogonId", "TargetLogonId"}


def parse_events(text):
    wrapped = text if text.lstrip().startswith("<Events") else "<Events>" + text + "</Events>"
    root = ET.fromstring(wrapped)
    events = []
    for ev in root.iter(NS + "Event"):
        out = {}
        system = ev.find(NS + "System")
        if system is not None:
            eid = system.find(NS + "EventID")
            if eid is not None:
                out["EventID"] = int(eid.text or 0)
            comp = system.find(NS + "Computer")
            if comp is not None:
                out["Computer"] = comp.text or ""
            time = system.find(NS + "TimeCreated")
            if time is not None:
                out["_utc"] = time.attrib.get("SystemTime", "")
            prov = system.find(NS + "Provider")
            if prov is not None:
                out["Provider"] = prov.attrib.get("Name", "")
        data = ev.find(NS + "EventData")
        if data is not None:
            for d in data.findall(NS + "Data"):
                name = d.attrib.get("Name")
                if name:
                    out[name] = d.text or ""
        events.append(out)
    return events


def normalise(events):
    """Mask identity only. Values a rule reads must survive verbatim."""
    for ev in events:
        for key in MASK:
            if key in ev and ev[key]:
                ev[key] = "<masked>"
    return events


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--rule-id", required=True)
    ap.add_argument("--output", help="defaults to fixtures/captured/<id>.json")
    ap.add_argument("--allow-no-match", action="store_true",
                    help="record the capture even though the rule did not fire - "
                         "this writes status 'unmatched', never 'captured'")
    ap.add_argument("--sample-ref", default="",
                    help="PIN-xxxx from samples/PINS.md; required for 'captured'")
    args = ap.parse_args()

    rules = evaluate.load_collection(ROOT)
    doc = rules.get(args.rule_id)
    if doc is None:
        raise SystemExit(f"no rule with id {args.rule_id}")

    text = pathlib.Path(args.input).read_text(encoding="utf-8", errors="replace")
    events = normalise(parse_events(text))
    if not events:
        raise SystemExit("no events parsed")

    matched, reason = evaluate.eval_rule(doc, events, rules)
    status = "captured" if matched else "unmatched"
    if not matched and not args.allow_no_match:
        print(f"the rule did NOT fire on this capture ({reason}).\n"
              f"Re-run with --allow-no-match to record it as 'unmatched', which is "
              f"the honest status and still worth keeping: it is how you find out\n"
              f"the rule's fields do not match what the host emits.",
              file=sys.stderr)
        return 2
    if matched and not args.sample_ref:
        print("warning: no --sample-ref; the fixture will fail the test suite's "
              "captured-needs-a-pin check", file=sys.stderr)

    out = pathlib.Path(args.output) if args.output else \
        ROOT / "fixtures" / "captured" / f"{args.rule_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    fixture = {
        "fixture_id": "FX-" + args.rule_id[:8],
        "rule_id": args.rule_id,
        "attack_id": next((t.split(".", 1)[1].upper() for t in doc.get("tags", [])
                           if str(t).lower().startswith("attack.t")), ""),
        "status": status,
        "sample_ref": args.sample_ref or "PIN-0000",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc)
                                 .replace(microsecond=0).isoformat(),
        "capture_source": {
            "input_sha256": _sha(pathlib.Path(args.input)),
            "sysmon_config_sha256": _sha(ROOT / "telemetry" / "sysmon-config.xml"),
            "match_result": reason,
        },
        "events": events,
        "assert_fields": {k: v for k, v in events[0].items()
                          if k not in ("_utc", "Provider") and not k.startswith("_")},
        "note": ("Captured from a lab host and matched by the evaluator."
                 if status == "captured" else
                 "Captured but the rule did not fire - a telemetry/field mismatch, "
                 "not a fixture. Investigate before editing either side."),
    }
    out.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    shown = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
    print(f"wrote {shown} status={status} ({reason})")
    return 0 if status == "captured" else 2


if __name__ == "__main__":
    raise SystemExit(main())
