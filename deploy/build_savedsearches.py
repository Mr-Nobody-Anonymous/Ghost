#!/usr/bin/env python3
"""Turn the deploy bundle into a `savedsearches.conf` a Splunk admin can install.

The bundle was a `.spl` file of queries plus a JSON manifest. That is enough to
read and not enough to deploy: 38 saved searches, each needing a schedule, a
suppression policy and a severity, had to be created by hand or by an API script
the repository did not contain.

This emits the conf file. It is deliberately conservative:

  * every search is **disabled** (`enableSched = 0`) and `runOnStartup = 0`:
    nothing pages anyone because they installed a file
  * `counttype = number of events`, `relation = greater than`, `quantity = 0`
    is Splunk's "alert on any result" - the rule is the filter, not the count
  * suppression comes from the rule's own declared `dedup_key` / `dedup_window`
  * the schedule is derived from `min_eval_interval` and **never faster than
    five minutes**, because every rule's floor is under that and a 10s schedule
    on 38 searches is a self-inflicted load incident
  * `action.email` is present but disabled, with a comment saying so - a
    correctly-formed stanza is more useful than a documented absence

Naming: `Ghost - <level> - <title> [<id-prefix>]`. The id prefix makes the
saved search traceable back to the rule without opening it.

Usage:
    python3 deploy/build_savedsearches.py                       # dist/savedsearches.conf
    python3 deploy/build_savedsearches.py --out configs/local/savedsearches.conf
    python3 deploy/build_savedsearches.py --allow-enabled        # for a lab, tells you why not
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "dist" / "splunk-manifest.json"
QUERIES = ROOT / "dist" / "splunk-queries.spl"

MIN_SCHEDULE_MINUTES = 5


def parse_interval(text, default_minutes=5):
    """'10s' -> 5 (floored), '15m' -> 15. Never below MIN_SCHEDULE_MINUTES."""
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(text or ""))
    if not m:
        return default_minutes
    n, unit = int(m.group(1)), m.group(2)
    minutes = {"s": max(1, n // 60), "m": n, "h": n * 60, "d": n * 1440}[unit]
    return max(MIN_SCHEDULE_MINUTES, minutes)


def parse_queries(path):
    """Split the .spl into {id: query} using the `-- [level] title  (id)` headers."""
    out, current, buf = {}, None, []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^-- \[(\w+)\] .*\(([0-9a-f-]{36})\)\s*$", line)
        if m:
            if current:
                out[current] = "\n".join(buf).strip()
            current, buf = m.group(2), []
            continue
        if line.startswith("-- source:"):
            continue
        if current is not None:
            buf.append(line)
    if current:
        out[current] = "\n".join(buf).strip()
    return {k: v for k, v in out.items() if v}


def trace_tags(rows):
    """A stanza name must be traceable back to exactly one rule.

    The obvious tag is the UUID prefix, and it is wrong here: this repository's
    rule ids were minted sequentially and all 38 share the first eight
    characters, so a prefix tag would label every stanza identically while
    looking like an identifier. Use the shortest tail that is unique, and fail
    loudly if no tag is unique.
    """
    ids = [r["id"] for r in rows]
    for width in (8, 12, 16, len(ids[0])):
        tags = {i: i[-width:] for i in ids}
        if len(set(tags.values())) == len(ids):
            return tags
    raise SystemExit("FAIL: rule ids are not distinguishable by any suffix; "
                     "stanza names could not be traced back to a rule")


def escape_value(text):
    """A conf value is one line; a newline ends the stanza."""
    return " ".join(str(text).split())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "savedsearches.conf"))
    ap.add_argument("--allow-enabled", action="store_true",
                    help="emit enableSched = 1 (still disabled per-search by default)")
    args = ap.parse_args()

    if not MANIFEST.is_file() or not QUERIES.is_file():
        print("FAIL: run deploy/build_bundle.py first (needs dist/splunk-manifest.json "
              "and dist/splunk-queries.spl)", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    queries = parse_queries(QUERIES)
    rows = [r for r in manifest.get("deployable", []) if not r.get("correlation")]
    correlated = [r for r in manifest.get("deployable", []) if r.get("correlation")]

    missing = [r["path"] for r in rows if r["id"] not in queries]
    if missing:
        print(f"FAIL: {len(missing)} rule(s) have no query text in the .spl "
              f"({missing[:3]}); the manifest and bundle disagree", file=sys.stderr)
        return 1

    tags = trace_tags(rows)

    out = []
    out.append("# Ghost detection lab - Splunk saved searches")
    out.append(f"# Generated from conversion {manifest.get('generated_utc')}.")
    out.append(f"# {len(rows)} single-event searches. Every one ships DISABLED.")
    out.append("# The [tag] is a unique suffix of the rule id, not a prefix: these ids")
    out.append("# share their first eight characters, so a prefix tag would be ambiguous.")
    out.append("# Enable in batches by severity; see docs/deployment.md.")
    out.append("#")
    out.append(f"# NOT included: {len(correlated)} correlation rule(s). pySigma emits them as")
    out.append("# a single SPL statement that Splunk evaluates as a subsearch; they need")
    out.append("# the member searches to exist and a schedule that contains the whole")
    out.append("# timespan. Build those by hand from docs/sequence-rules.md.")
    out.append("")

    for row in sorted(rows, key=lambda r: (r.get("level") or "", r.get("title") or "")):
        rid = row["id"]
        level = (row.get("level") or "medium").lower()
        title = escape_value(row.get("title") or rid)
        name = f"Ghost - {level} - {title} [{tags[rid]}]"
        note = row.get("dedup_note") or {}
        interval = parse_interval(note.get("min_schedule"))
        cron = f"*/{interval} * * * *" if interval < 60 else f"0 */{interval // 60} * * *"

        out.append(f"[{name}]")
        out.append(f"# source: {row['path']}")
        out.append(f"# lifecycle: {row.get('lifecycle')} - no captured fixture exists, so this "
                   f"search is unproven")
        out.append(f"search = {escape_value(queries[rid])}")
        out.append("enableSched = " + ("1" if args.allow_enabled else "0"))
        out.append("runOnStartup = 0")
        out.append(f"cron_schedule = {cron}")
        out.append("counttype = number of events")
        out.append("relation = greater than")
        out.append("quantity = 0")
        out.append(f"alert.severity = { {'high': 4, 'medium': 3, 'low': 2}.get(level, 3) }")
        out.append("alert.track = 1")
        fields = note.get("suppress_fields") or []
        if fields:
            out.append("alert.suppress = 1")
            out.append(f"alert.suppress.fields = {', '.join(fields)}")
            out.append(f"alert.suppress.period = {note.get('suppress_period', '5m')}")
        else:
            out.append("alert.suppress = 0")
        out.append("action.email = 0")
        out.append("")
    out.append("# To enable: set enableSched = 1 on the searches you have tuned, one")
    out.append("# severity band at a time. docs/deployment.md step 5.")

    names = [line[1:-1] for line in out if line.startswith("[Ghost - ")]
    if len(set(names)) != len(names):
        print("FAIL: duplicate stanza names; Splunk would merge them", file=sys.stderr)
        return 1

    target = pathlib.Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {target}: {len(rows)} saved searches (all disabled), "
          f"{len(correlated)} correlation(s) excluded by design")
    return 0


if __name__ == "__main__":
    sys.exit(main())
