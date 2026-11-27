#!/usr/bin/env python3
"""Turn a lab host into a capture kit: what to collect, what to run, what to check.

The repository's weakest gate is maturity level 5: every fixture is `designed`,
none is a blind capture. That gap does not close by writing more rules - it
closes by running the emulator on a disposable VM, collecting the events, and
converting them with tools/evtx_to_fixture.py.

This script prints that workflow for a given rule or for the whole collection:
the Sysmon channels and event IDs to collect, the fields the rule reads, the
inert emulator command that should produce them, and the exact commands to
convert and promote the result. It makes no system calls of its own.

Usage:
    python3 tools/capture_kit.py                       # whole collection, summary
    python3 tools/capture_kit.py --rule 2d7f4b90       # one rule, full runbook
    python3 tools/capture_kit.py --rule 2d7f4b90 --markdown
"""
import argparse
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Sysmon event IDs -> collection source. Only the ones this repo uses.
EID_SOURCE = {
    1: ("Microsoft-Windows-Sysmon/Operational", "ProcessCreate"),
    8: ("Microsoft-Windows-Sysmon/Operational", "CreateRemoteThread"),
    10: ("Microsoft-Windows-Sysmon/Operational", "ProcessAccess"),
    11: ("Microsoft-Windows-Sysmon/Operational", "FileCreate"),
    12: ("Microsoft-Windows-Sysmon/Operational", "RegistryEvent (object add/delete)"),
    13: ("Microsoft-Windows-Sysmon/Operational", "RegistryEvent (value set)"),
    14: ("Microsoft-Windows-Sysmon/Operational", "RegistryEvent (key/value rename)"),
    19: ("Microsoft-Windows-Sysmon/Operational", "WmiEventFilter"),
    20: ("Microsoft-Windows-Sysmon/Operational", "WmiEventConsumer"),
    21: ("Microsoft-Windows-Sysmon/Operational", "WmiEventConsumerToFilter"),
    22: ("Microsoft-Windows-Sysmon/Operational", "DnsQuery"),
    23: ("Microsoft-Windows-Sysmon/Operational", "FileDelete (archived)"),
    26: ("Microsoft-Windows-Sysmon/Operational", "FileDelete"),
    4663: ("Security", "Object access (SACL)"),
}

NETWORK_SOURCES = {"proxy", "netflow", "zeek", "dns", "firewall"}

# Behaviours the inert emulator can actually produce, by rule id.
EMULATOR = {
    "2d7f4b90-8e31-4c5a-b2d6-9f1a0c3e7d52":
        "python3 emulation/local_listener.py --port 8080 &\n"
        "python3 emulation/inert_beacon.py --count 5 --delay 2",
    "1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a0d":
        "python3 emulation/inert_beacon.py --count 1   # single instance guards on loopback",
}

# Behaviours with no safe emulator: what to do instead.
MANUAL = {
    "default":
        "No inert emulator covers this behaviour. Use a benign analogue that "
        "produces the same event shape (see fixtures/benign/README.md) and "
        "record it in docs/tuning-log.md."
}


def load_rules():
    rules = {}
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(d, dict) and d.get("id"):
            d["_path"] = f.relative_to(ROOT).as_posix()
            rules[d["id"]] = d
    return rules


def fields_of(doc):
    out = set()
    for body in (doc.get("detection") or {}).values():
        if isinstance(body, dict):
            for key in body:
                if key != "condition":
                    out.add(key.split("|")[0])
    return sorted(out)


def event_ids(doc):
    ids = set()
    for body in (doc.get("detection") or {}).values():
        if not isinstance(body, dict):
            continue
        value = body.get("EventID")
        if isinstance(value, list):
            ids.update(int(v) for v in value if str(v).isdigit())
        elif str(value).isdigit():
            ids.add(int(value))
    return sorted(ids)


def is_network(doc):
    ls = doc.get("logsource", {}) or {}
    return ls.get("category") in NETWORK_SOURCES or ls.get("product") in ("zeek", "suricata")


def plan(rid, doc, rules):
    lines = []
    title = doc.get("title", rid)
    lines.append(f"## {title}")
    lines.append("")
    lines.append(f"- rule: `{doc['_path']}`")
    lines.append(f"- id: `{rid}`")
    lines.append(f"- logsource: `{doc.get('logsource')}`")
    lines.append(f"- lifecycle: `{doc.get('lifecycle')}`")
    lines.append(f"- fields read: {', '.join(f'`{f}`' for f in fields_of(doc)) or '(correlation only)'}")

    if is_network(doc):
        lines += [
            "",
            "**Collection is network-side.** Host Sysmon capture cannot produce this.",
            "Collect the proxy/SWG request log, or Zeek `dns.log`/`http.log`/`ssl.log`, with",
            "full header retention. If your export drops custom headers, this rule cannot fire",
            "and the gap belongs in `telemetry/data-sources.md`, not in the rule.",
        ]
        fields = fields_of(doc)
        if any(f.startswith("cs-header-") for f in fields):
            lines += [
                "",
                "Header visibility check before anything else:",
                "```",
                "curl -s -o /dev/null -v http://127.0.0.1:8080/poll?id=canary&seq=1 \\",
                "  -H 'X-Id: canary' -H 'X-Seq: 1' -H 'User-Agent: Mozilla/5.0'",
                "```",
                "then confirm the proxy log records `X-Id`/`X-Seq` and the export is not",
                "stripping them.",
            ]
    else:
        ids = event_ids(doc)
        lines.append("")
        lines.append("**Collect:**")
        for eid in ids:
            channel, name = EID_SOURCE.get(eid, ("(unknown)", "unknown event id"))
            lines.append(f"- EventID {eid} from `{channel}` - {name}")
        if not ids:
            lines += ["- correlation rule: collect each member rule's events instead"]
        lines += [
            "",
            "```powershell",
            "# on the lab VM, as Administrator",
            "wevtutil qe Microsoft-Windows-Sysmon/Operational "
            f'/q:"*[System[(EventID={" or ".join(str(i) for i in ids) or "1"})]]" '
            "/f:xml /e:true > capture.xml",
            "```",
        ]

    if "correlation" in doc:
        members = doc["correlation"].get("rules", [])
        lines.append("")
        lines.append("**Correlation members:**")
        for m in members:
            member = rules.get(m)
            lines.append(f"- `{m}` {member['title'] if member else '(missing)'}")

    lines += ["", "**Produce the behaviour on the host:**", "", "```bash"]
    lines.append(EMULATOR.get(rid, MANUAL["default"].strip()))
    lines += ["```", ""]
    if is_network(doc):
        lines += [
            "The emulator above produces the traffic shape on loopback. It does **not**",
            "prove the proxy export retains the fields the rule reads - see the header",
            "visibility check earlier on this page. Record a pass only when the collected",
            "record contains them.",
            "",
        ]

    lines += [
        "**Convert and promote:**",
        "",
        "```bash",
        f"python3 tools/evtx_to_fixture.py --input capture.xml \\",
        f"  --rule-id {rid} --output fixtures/per_rule/{rid}.json",
        f"python3 detection-as-code/evaluate.py --rule {rid}",
        "python3 -m unittest discover -s tests -p 'test_*.py'",
        "```",
        "",
        "Then set the rule's `lifecycle:` to `captured`, fill the fixture's `sample_ref`",
        "with a real pin from `samples/PINS.md`, and re-run `ci/gate.sh`. Do not mark a",
        "fixture `captured` because the fields look plausible - only because an event was",
        "pulled off a host and matched.",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rule", help="rule id (or unique id prefix)")
    ap.add_argument("--markdown", action="store_true", help="emit one markdown document")
    args = ap.parse_args()

    rules = load_rules()
    if args.rule:
        matches = [rid for rid in rules if rid.startswith(args.rule)]
        if len(matches) != 1:
            print(f"{len(matches)} rules match {args.rule!r}; pass a longer prefix", file=sys.stderr)
            return 1
        print(plan(matches[0], rules[matches[0]], rules))
        return 0

    print("# Capture plan\n")
    print(f"{len(rules)} rules. Each row is what must exist before its fixture can "
          f"stop saying `designed`.\n")
    print("| Rule | Lifecycle | Logsource | Event IDs | Fields |")
    print("|---|---|---|---|---|")
    for rid, doc in sorted(rules.items(), key=lambda kv: kv[1].get("title", "")):
        eids = "-" if is_network(doc) else ("correlation" if "correlation" in doc
                                            else ",".join(map(str, event_ids(doc))) or "-")
        fields = ", ".join(fields_of(doc)) or "(correlation)"
        print(f"| {doc['title'][:52]} | {doc.get('lifecycle')} | "
              f"{doc.get('logsource', {}).get('category') or doc.get('logsource', {}).get('service') or '-'} | "
              f"{eids} | {fields[:60]} |")
    print("\nFull runbook for one rule: `python3 tools/capture_kit.py --rule <id-prefix>`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
