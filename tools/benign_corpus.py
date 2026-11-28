#!/usr/bin/env python3
"""Measure per-rule precision against real benign software (G-03).

`fixtures/benign/README.md` has been a table of intentions since the beginning:
"run each class for one business day, record what trips". Nobody could act on
it, because there was nothing to run. This is what to run.

It answers the question the repository could not answer before: **for one rule,
out of N benign events, how many did it select?** That is precision's numerator.
Volume (G-04) is the denominator and needs a different measurement, but without
this one the ceilings in `metrics/ceilings.json` are editor guesses.

Three modes, because a lab has three kinds of evidence and only one of them is
a live host:

  --from-jsonl   events already collected, one JSON object per line
  --from-xml     one or more `wevtutil qe /f:xml` outputs concatenated
  --classes      list the software classes a full run needs, with what each is
                 expected to trip
  --collect      print the exact collection commands for one class: what to
                 enable, how to export, and the format the other two modes read

The first two run here, now, on synthetic input, and their tests prove the
arithmetic. The third is the part that needs the VM - and it says so instead of
pretending otherwise.

Usage:
    python3 tools/benign_corpus.py --classes
    python3 tools/benign_corpus.py --collect signed-installer
    python3 tools/benign_corpus.py --from-jsonl capture.jsonl --out report.json
    python3 tools/benign_corpus.py --from-jsonl capture.jsonl --rule <id> --explain
"""
import argparse
import contextlib
import json
import pathlib
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))

# The classes a full precision run needs. `expected_trips` is what the design
# predicts, so a run that produces something else is itself a finding.
CLASSES = [
    {"class": "signed-installer", "example": "7-Zip MSI",
     "expected_trips": ["run_key_write", "dropper_unsigned_temp_exec"],
     "why": "an MSI writes Run keys and extracts to %TEMP% - the same two events\n"
            "the persistence and dropper rules read",
     "duration": "one install + one uninstall"},
    {"class": "browser-updater", "example": "Chrome",
     "expected_trips": ["credential_file_access", "beaconing_frequency"],
     "why": "an updater reads its own credential store and polls a CDN",
     "duration": "one update cycle"},
    {"class": "file-sync", "example": "OneDrive",
     "expected_trips": ["sqlite_temp_copy", "beacon_interval_shift"],
     "why": "sync clients copy SQLite databases to temp and poll on a timer",
     "duration": "4 hours with files changing"},
    {"class": "backup-agent", "example": "Windows Server Backup",
     "expected_trips": ["credential_file_access", "schtask_onlogon"],
     "why": "backup reads everything and schedules itself",
     "duration": "one backup window"},
    {"class": "electron-app", "example": "VS Code",
     "expected_trips": ["mei_extraction_dir", "beaconing_frequency"],
     "why": "Electron unpacks to a temp dir on every launch",
     "duration": "10 launches"},
    {"class": "management-agent", "example": "SCCM / Intune",
     "expected_trips": ["security_component_tamper", "wmi_recon_command"],
     "why": "agents stop and start services and query WMI constantly",
     "duration": "one policy refresh"},
    {"class": "python-tooling", "example": "pip, ansible",
     "expected_trips": ["python_parent_child_shape"],
     "why": "python shells out to system utilities - the exact tree the rule matches",
     "duration": "one install and one playbook run"},
    {"class": "office-macro", "example": "an approved macro workbook",
     "expected_trips": ["dropper_unsigned_temp_exec"],
     "why": "Office spawns signed children from %TEMP% during macro execution",
     "duration": "one macro run"},
]


# The gap `--classes` left: it names the software to run but not how to turn a
# host into an NDJSON file. An operator who has to invent the export step will
# export a different schema than the rules read, or export nothing. This is the
# missing middle, written out so it can be pasted into the lab VM.
COLLECT_PREAMBLE = """\
# Collecting a benign corpus for: {cls}  ({example})
#
# Expected trips (a run that produces something ELSE is itself a finding):
{trips}
# Duration: {duration}
# Why this class matters:\n{why}
#
# Run all of this inside the disposable lab VM, never on a workstation you keep.

# 1. Make sure the channel the rules read is actually on. The persistence and
#    process rules read Sysmon; the credential rules read Object Access. If
#    either is off the corpus will look clean and prove nothing.
wevtutil gl Microsoft-Windows-Sysmon/Operational | findstr /i "enabled"
auditpol /get /category:* | findstr /i "File System\|Registry\|Handle"

# 2. Run the software for the stated duration. Do nothing else in the VM: every
#    event in the window is attributed to this class.

# 3. Export the window as XML - one file, `--from-xml` takes it directly. The
#    query keeps the last 24 hours; narrow it if the class ran for less.
wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:xml /e:Events > %USERPROFILE%\\Desktop\\{cls}.xml

# 4. Or export as NDJSON, which `--from-jsonl` takes:
#    wevtutil epl writes EVTX; use `Get-WinEvent | Select | ConvertTo-Json -Compress`
#    one object per line. The rules read flat field names (Image, CommandLine,
#    TargetObject, EventID), so flatten before writing:
powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'}} | ForEach-Object {{ $e=$_; $h=@{{EventID=$e.Id; TimeCreated=$e.TimeCreated.ToString('o')}}; ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object {{ $h[$_.Name]=$_.'#text' }}; [pscustomobject]$h }} | ConvertTo-Json -Compress" > %USERPROFILE%\\Desktop\\{cls}.jsonl

# 5. Score it. Nothing here leaves the VM.
python3 tools/benign_corpus.py --from-xml %USERPROFILE%\\Desktop\\{cls}.xml --out report-{cls}.json
python3 tools/benign_corpus.py --from-xml %USERPROFILE%\\Desktop\\{cls}.xml --rule run_key_write --explain
"""


def collect_text(cls):
    """The collection runbook for one class, or SystemExit naming the choices."""
    chosen = [c for c in CLASSES if c["class"] == cls]
    if not chosen:
        names = ", ".join(c["class"] for c in CLASSES)
        raise SystemExit(f"unknown class {cls!r}; choose one of: {names}")
    entry = chosen[0]
    trips = "".join(f"#   - {name}\n" for name in entry["expected_trips"])
    why = "\n".join("#   " + line for line in entry["why"].splitlines())
    return COLLECT_PREAMBLE.format(
        cls=entry["class"], example=entry["example"], trips=trips,
        duration=entry["duration"], why=why)


def parse_jsonl(path):
    events = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{number}: not JSON - {exc}") from exc
    return events


def parse_xml(path):
    """`wevtutil qe /f:xml` output, possibly several documents concatenated."""
    import evaluate

    text = path.read_text(encoding="utf-8", errors="replace")
    if "<Events>" in text:
        text = text.replace("<Events>", "").replace("</Events>", "")
    parse = getattr(evaluate, "parse_events", _parse_events_fallback)
    return parse(text)


def _parse_events_fallback(text):
    events = []
    for chunk in text.split("<Event "):
        if not chunk.strip():
            continue
        try:
            root = ET.fromstring("<Event " + chunk if not chunk.startswith("<Event")
                                 else chunk)
        except ET.ParseError:
            continue
        record = {}
        for node in root.iter():
            tag = node.tag.split("}")[-1]
            if node.text and node.text.strip():
                record.setdefault(tag, node.text)
            attr = node.get("Name")
            if attr and node.text and node.text.strip():
                record[attr] = node.text
        if "EventID" in record:
            # A non-numeric EventID is left as-is rather than dropped: a rule
            # that reads it should see what the host actually emitted.
            with contextlib.suppress(TypeError, ValueError):
                record["EventID"] = int(record["EventID"])
            events.append(record)
    return events


def measure(events, rules):
    """rule id -> how many benign events it selects.

    Two evaluation paths, because the harness has two. A single-event rule is
    tested per event with `eval_detection`, which is what "did this rule select
    this event" means. A correlation rule is a property of the *sequence*, so it
    is evaluated once over the whole corpus with `eval_rule` - running it
    per-event would always be false and would report free precision that does
    not exist.
    """
    import evaluate

    result = {}
    for rule_id, doc in rules.items():
        correlation = isinstance(doc.get("correlation"), dict)
        try:
            if correlation:
                matched, reason = evaluate.eval_rule(doc, events, rules)
                result[rule_id] = {
                    "title": doc.get("title"),
                    "kind": "correlation",
                    "selected": len(events) if matched else 0,
                    "of": len(events),
                    "rate": 1.0 if matched else 0.0,
                    "reason": reason,
                }
                continue
            selected = sum(1 for event in events
                           if evaluate.eval_detection(doc, event))
            result[rule_id] = {
                "title": doc.get("title"),
                "kind": "single-event",
                "selected": selected,
                "of": len(events),
                "rate": round(selected / len(events), 4) if events else 0.0,
            }
        except Exception as exc:      # a rule that crashes is a finding too
            result[rule_id] = {"error": f"{type(exc).__name__}: {exc}"}
    return result


def verdict(report, ceiling_per_day=1.0):
    """Which rules are not production ready, by the corpus alone."""
    noisy = []
    for rule_id, row in report.items():
        if "error" in row:
            noisy.append((rule_id, "crashed", row["error"]))
            continue
        if row["selected"] > 0:
            noisy.append((rule_id, f"{row['selected']}/{row['of']}",
                          f"{row['rate'] * 100:.1f}% of benign events"))
    return noisy


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-jsonl")
    ap.add_argument("--from-xml")
    ap.add_argument("--rule")
    ap.add_argument("--out")
    ap.add_argument("--explain", action="store_true",
                    help="with --rule: print each benign event that tripped it")
    ap.add_argument("--collect", metavar="CLASS",
                    help="print the collection runbook for one software class")
    ap.add_argument("--classes", action="store_true",
                    help="list the software classes a full run needs")
    args = ap.parse_args()

    if args.classes:
        for entry in CLASSES:
            print(f"{entry['class']:20} {entry['example']}")
            print(f"  expected: {', '.join(entry['expected_trips'])}")
            print(f"  duration: {entry['duration']}")
            for line in entry["why"].splitlines():
                print(f"  why:      {line}")
            print()
        print(f"{len(CLASSES)} classes. A full precision run is roughly two "
              f"business days of VM time, and it is the only way G-03 closes.")
        return 0

    if args.collect:
        print(collect_text(args.collect))
        return 0

    if not (args.from_jsonl or args.from_xml):
        ap.error("one of --from-jsonl, --from-xml, --classes or --collect is "
                 "required")

    events = (parse_jsonl(pathlib.Path(args.from_jsonl)) if args.from_jsonl
              else parse_xml(pathlib.Path(args.from_xml)))
    if not events:
        print("no events parsed - an empty corpus measures nothing", file=sys.stderr)
        return 2

    import evaluate
    rules = evaluate.load_collection(ROOT)
    if args.rule:
        rules = {k: v for k, v in rules.items() if k.startswith(args.rule)}

    report = measure(events, rules)
    noisy = verdict(report)

    for rule_id, count, why in noisy:
        print(f"TRIP  {rule_id[:8]}  {count:>8}  {why}")
    if not noisy:
        print("clean: no rule selected any benign event in this corpus")
        print("       (that is only good news if the corpus is representative -")
        print("        one app for one hour proves very little)")

    if args.explain and args.rule:
        rule_id = next(iter(rules))
        doc = rules[rule_id]
        print(f"\n--- events selected by {rule_id[:8]} ---")
        if isinstance(doc.get("correlation"), dict):
            print("correlation rule: selected the whole sequence or nothing; "
                  "see the `reason` field in --out for the count")
        else:
            for event in events:
                if evaluate.eval_detection(doc, event):
                    print(json.dumps({k: event[k] for k in list(event)[:8]},
                                     default=str))

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps({
            "events": len(events),
            "rules": len(report),
            "noisy": len(noisy),
            "report": report,
        }, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.out}")

    # Non-zero when anything trips: in a gate, a clean corpus is the pass.
    return 1 if noisy else 0


if __name__ == "__main__":
    sys.exit(main())
