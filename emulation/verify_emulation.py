#!/usr/bin/env python3
"""Parse the inert emulator's traffic log and check the rules it should exercise.

The lab procedure says: run `local_listener.py`, run `inert_beacon.py`, and that
produces telemetry comparable to the design. Nothing ever checked the second
half of that sentence. The listener writes `emulator_traffic.log`; this tool
turns that log into proxy-shaped events and runs the rules whose logsource is
`proxy` against them.

It answers one question honestly: *does the emulator actually produce events the
header rules match?* If the answer is no, either the emulator and the rule have
diverged, or the field mapping between them is wrong - and both are silent
failures today.

This is a loopback artefact check, not a capture. It proves the emulator emits
the right *shape*; it cannot prove a proxy would export those headers
(G-11 in docs/gap-register.md).

Usage:
  python3 emulation/verify_emulation.py                 # uses ./emulator_traffic.log
  python3 emulation/verify_emulation.py --log path.log
  python3 emulation/verify_emulation.py --dry-run       # synthesise, no listener
"""
import argparse
import datetime
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))

import evaluate
import yaml

DEFAULT_LOG = ROOT / "emulator_traffic.log"
LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<method>[A-Z]+)\s+(?P<path>\S+)"
    r"(?:\s+X-Id=(?P<xid>\S+))?(?:\s+X-Seq=(?P<xseq>\S+))?"
    r"(?:\s+UA=(?P<ua>[^\s]+))?(?:\s+bytes=(?P<bytes>\d+))?"
)


def parse_log(path):
    """Each log line becomes an event with the headers the *listener saw*.

    Fields a proxy would add (Accept-Language, Cookie) are not synthesised: a
    missing header is meaningful to at least one rule, and inventing absence here
    would make an unrelated rule look like it fires.
    """
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = LINE_RE.match(line.strip())
        if not m or not m.group("xid"):
            continue  # startup/shutdown notices carry no request headers
        path_part, _, query = m.group("path").partition("?")
        events.append({
            "cs-uri-stem": path_part,
            "cs-uri-query": query,
            "cs-header-X-Id": m.group("xid"),
            "cs-header-X-Seq": m.group("xseq") or "",
            "cs-user-agent": m.group("ua") or "",
            # The listener sees a loopback connection; a proxy would attach the
            # real client and destination. Both are present so the rule's
            # `|exists` guards can pass, and clearly marked as loopback.
            "SourceAddress": "127.0.0.1",
            "DestinationHostname": "loopback",
            "_ts": 0,
        })
    return events


def synthesise():
    """A minimal synthetic log, for --dry-run on a machine with no listener."""
    vid = "9f3c1a7e-2b64-4d18-8e75-0c2f8a41b6e3"
    now = datetime.datetime.now(datetime.UTC).isoformat()
    return (
        f"{now} GET /poll?id={vid}&seq=1 X-Id={vid} X-Seq=1 UA=Mozilla/5.0 bytes=0\n"
        f"{now} GET /poll?id={vid}&seq=2 X-Id={vid} X-Seq=2 UA=Mozilla/5.0 bytes=0\n"
        f"{now} POST /result X-Id={vid} X-Seq=2 UA=Mozilla/5.0 bytes=72\n"
    ), None


def rules_the_emulator_targets():
    """Only the rules the emulator is *supposed* to exercise.

    It emits `X-Id`/`X-Seq` with a browser UA. It does not emit an egress to a
    public-IP service, and it deliberately emits no Accept-Language or Cookie
    header - which is the absence `ua_anomaly.yml` looks for. Running every proxy
    rule against it would report two failures that are not failures, and the
    first draft of this tool did exactly that.
    """
    TARGETS = {"beacon_custom_headers.yml", "beaconing_frequency.yml"}
    out = []
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        if f.name not in TARGETS:
            continue
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        out.append((f, doc))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=str(DEFAULT_LOG))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.dry_run:
        text, _ = synthesise()
        tmp = pathlib.Path("/tmp/ghost-emulator-dryrun.log")
        tmp.write_text(text, encoding="utf-8")
        log_path = tmp
    else:
        log_path = pathlib.Path(args.log)
        if not log_path.is_file():
            print(f"no traffic log at {log_path}\n"
                  f"Run emulation/local_listener.py, then emulation/inert_beacon.py, "
                  f"from the repository root. Or use --dry-run to check the mapping "
                  f"without a listener.", file=sys.stderr)
            return 2

    events = parse_log(log_path)
    if not events:
        print(f"{log_path} has no request lines with X-Id - the beacon never ran, "
              f"or the log is from a listener that only started", file=sys.stderr)
        return 2

    print(f"emulator log: {len(events)} request(s) parsed from {log_path.name}")
    candidates = rules_the_emulator_targets()
    if not candidates:
        print("the emulator's target rules are missing from sigma/")
        return 2

    failures = 0
    for path, doc in candidates:
        det = doc.get("detection") or {}
        if "correlation" in doc or not det:
            print(f"skip {doc.get('title', path.name)} (correlation)")
            continue
        hits = [e for e in events if evaluate.eval_detection(doc, e)]
        mark = "MATCH" if hits else "NO MATCH"
        print(f"{mark:8} {doc.get('title')}  ({len(hits)}/{len(events)} events)")
        if not hits:
            failures += 1
            sample = events[0]
            print("         first event:", {k: v for k, v in sample.items() if k != "_ts"})
            print("         rule reads :", sorted({k.split('|')[0] for body in det.values()
                                                   if isinstance(body, dict) for k in body}))
    if failures:
        print(f"\nFAIL: {failures} proxy rule(s) matched none of the emulator's events. "
              f"Either the emulator shape and the rule diverged, or the log-to-field "
              f"mapping in this tool is wrong. Neither is caught anywhere else.")
        return 1
    print("\nThe emulator produces events these rules match. This proves the shape, "
          "not that a proxy retains the headers - see G-11.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
