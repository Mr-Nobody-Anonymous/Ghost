#!/usr/bin/env python3
"""Validate, render and apply alert-quality observations.

`docs/tuning-log.md` was an empty Markdown table with a vocabulary section. That
is a place to write, not a feedback loop: nothing connected an observation to
the rule it was about, to the rule's event ceiling, or to the lifecycle state
the repository claims for it.

This tool is the loop. Observations live in `tuning/observations.csv`, one row
per trip an analyst actually looked at. `--check` refuses bad rows, `--render`
writes the Markdown table from the CSV so the two cannot disagree, and
`--apply-ceilings` promotes a measured events/day into `metrics/ceilings.json`
so a ceiling stops being a guess at the moment it stops being a guess.

The rule that matters: **a rule may not be `lifecycle: tuned` without at least
one `keep` observation.** Tuning is a claim about a host watching the rule and
deciding it was right. Without a row, it is a wish.

Usage:
    python3 tools/tuning_log.py --check
    python3 tools/tuning_log.py --render          # rewrite docs/tuning-log.md
    python3 tools/tuning_log.py --apply-ceilings  # promote measured events/day
"""
import argparse
import csv
import datetime
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "tuning" / "observations.csv"
DOC_PATH = ROOT / "docs" / "tuning-log.md"
CEILINGS = ROOT / "metrics" / "ceilings.json"
RULES_DIR = ROOT / "sigma"

DECISIONS = {"allowlist", "threshold", "retire", "keep"}
COLUMNS = ["date", "rule_id", "benign_class", "observed_trip",
           "decision", "rationale", "events_per_day", "reporter"]
BEGIN = "<!-- BEGIN GENERATED TABLE -->"
END = "<!-- END GENERATED TABLE -->"


def rule_index():
    """id -> (path, lifecycle, title), read without PyYAML so the loop works in
    a bare checkout."""
    index = {}
    for path in sorted(RULES_DIR.rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        rid = re.search(r"^id:\s*(\S+)", text, re.M)
        life = re.search(r"^lifecycle:\s*(\S+)", text, re.M)
        title = re.search(r"^title:\s*(.+)$", text, re.M)
        if not rid:
            continue
        index[rid.group(1).strip("\"'")] = (
            path.relative_to(ROOT).as_posix(),
            (life.group(1) if life else "designed").strip("\"'"),
            (title.group(1).strip("\"'") if title else ""),
        )
    return index


def load_rows():
    if not CSV_PATH.is_file():
        return []
    with CSV_PATH.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            raise SystemExit(f"FAIL: {CSV_PATH.relative_to(ROOT)} header is "
                             f"{reader.fieldnames}, expected {COLUMNS}")
        return [r for r in reader if any((v or "").strip() for v in r.values())]


def validate(rows, index):
    problems = []
    today = datetime.date.today()
    seen = set()
    for n, row in enumerate(rows, start=2):
        where = f"{CSV_PATH.name}:{n}"
        rid = (row.get("rule_id") or "").strip()
        if rid not in index:
            problems.append(f"{where}: rule_id {rid!r} is not a rule in this repository")
            continue
        try:
            date = datetime.date.fromisoformat((row.get("date") or "").strip())
        except ValueError:
            problems.append(f"{where}: date {row.get('date')!r} is not YYYY-MM-DD")
            date = None
        if date and date > today:
            problems.append(f"{where}: date {date} is in the future")
        decision = (row.get("decision") or "").strip()
        if decision not in DECISIONS:
            problems.append(f"{where}: decision {decision!r} is not one of "
                            f"{sorted(DECISIONS)}")
        for field in ("benign_class", "observed_trip", "rationale"):
            if len((row.get(field) or "").strip()) < 8:
                problems.append(f"{where}: {field} is missing or too short to be "
                                f"a record of anything")
        epd = (row.get("events_per_day") or "").strip()
        if epd:
            try:
                value = float(epd)
            except ValueError:
                problems.append(f"{where}: events_per_day {epd!r} is not a number")
            else:
                if value < 0:
                    problems.append(f"{where}: events_per_day is negative")
        key = (rid, (row.get("observed_trip") or "").strip())
        if key in seen:
            problems.append(f"{where}: duplicate observation for {rid}")
        seen.add(key)
    return problems


def tuned_without_evidence(index, rows):
    """The invariant. A `tuned` rule needs a `keep` row from a real deployment."""
    kept = {r["rule_id"].strip() for r in rows if r["decision"].strip() == "keep"}
    return [f"{rid} ({path}) is lifecycle: tuned with no `keep` observation "
            f"in tuning/observations.csv"
            for rid, (path, life, _) in sorted(index.items())
            if life == "tuned" and rid not in kept]


def render(index, rows):
    out = ["| Date | Rule | Benign class | Observed trip | Decision | Rationale |",
           "|---|---|---|---|---|---|"]
    if not rows:
        out.append("| — | — | — | — | — | no observations recorded yet |")
    for r in sorted(rows, key=lambda r: (r["date"], r["rule_id"])):
        title = index.get(r["rule_id"].strip(), ("", "", r["rule_id"]))[2]
        link = index.get(r["rule_id"].strip(), ("",))[0]
        cell = lambda v: (v or "").replace("|", "\\|").strip()  # noqa: E731
        out.append(f"| {cell(r['date'])} | `{cell(r['rule_id'])}` {cell(title)} "
                   f"({link}) | {cell(r['benign_class'])} | {cell(r['observed_trip'])} "
                   f"| `{cell(r['decision'])}` | {cell(r['rationale'])} |")
    return "\n".join(out)


def write_doc(index, rows):
    text = DOC_PATH.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        raise SystemExit(f"FAIL: {DOC_PATH.relative_to(ROOT)} is missing the "
                         f"{BEGIN} / {END} markers")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    new = f"{head}{BEGIN}\n{render(index, rows)}\n{END}{tail}"
    DOC_PATH.write_text(new, encoding="utf-8")


def apply_ceilings(index, rows):
    data = json.loads(CEILINGS.read_text(encoding="utf-8"))
    changed = []
    for row in rows:
        rid = row["rule_id"].strip()
        raw = (row.get("events_per_day") or "").strip()
        if not raw or rid not in data:
            continue
        data[rid]["measured"] = True
        data[rid]["observed_events_per_day"] = float(raw)
        data[rid]["note"] = (f"measured {row['date'].strip()}: "
                             f"{row['benign_class'].strip()}")
        changed.append(rid)
    if changed:
        CEILINGS.write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n",
                            encoding="utf-8")
    return changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--apply-ceilings", action="store_true")
    args = ap.parse_args()
    if not (args.check or args.render or args.apply_ceilings):
        ap.error("choose at least one of --check, --render, --apply-ceilings")

    index = rule_index()
    rows = load_rows()
    problems = validate(rows, index) + tuned_without_evidence(index, rows)

    if args.render:
        write_doc(index, rows)
        print(f"tuning-log: rendered {len(rows)} observation(s) into "
              f"{DOC_PATH.relative_to(ROOT)}")
    if args.apply_ceilings:
        changed = apply_ceilings(index, rows)
        print(f"ceilings: {len(changed)} rule(s) now measured")
    if problems:
        for p in problems:
            print(f"FAIL {p}", file=sys.stderr)
        print(f"tuning-log: {len(problems)} problem(s) across {len(rows)} row(s)",
              file=sys.stderr)
        return 1
    if args.check:
        tuned = sum(1 for _, (_, life, _) in index.items() if life == "tuned")
        print(f"tuning-log: {len(rows)} observation(s), {tuned} rule(s) claimed "
              f"tuned, all backed; {len(index)} rules known")
    return 0


if __name__ == "__main__":
    sys.exit(main())
