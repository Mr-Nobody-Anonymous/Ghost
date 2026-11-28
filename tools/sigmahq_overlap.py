#!/usr/bin/env python3
"""Check this repository's rules against upstream SigmaHQ for overlap.

The gap: "whether any duplicates an existing SigmaHQ rule (and diverges from it)
is unknown. Citation and fork management are unhandled." That is a risk in both
directions. A forked rule drifts; a silent divergence is a false negative the
upstream project already solved; and a re-invented rule makes this repository's
coverage claims look larger than they are.

How overlap is decided
----------------------
Titles are useless (`proc_creation_win_powershell_download` and "PowerShell
Download Cradle" share no token). Exact field/value pairs are too strict. This
compares what determines behaviour:

  * **event family** - Sysmon EventID mapped to the category name upstream uses,
    with upstream's own aliases (`registry_event` covers 12/13/14)
  * **product** - Linux `process_creation` is not Windows `process_creation`
  * **technique set** - ATT&CK tags, intersected
  * **selection coverage** - how much of *my* selection upstream's rule already
    selects at least as broadly

Coverage is directed on purpose. The question is "is my rule already covered",
so my constraints are the denominator and upstream is the cover.

Levels
------
  `duplicate`  >= 80% covered and my techniques are a subset of upstream's
  `divergent`  >= 80% covered but the technique sets disagree - one of the two
               is probably mistagged, or they detect different halves
  `near`       >= 55% covered - a relationship worth recording
  (below 55% is not reported)

A `duplicate` or `divergent` finding that is not recorded in
`attack/sigmahq-overlap.json` fails `--check`. A recorded finding with decision
`defer` means upstream covers it better; `attack/matrix.md` and the Navigator
layer then stop counting that rule as this repository's unique coverage.

Offline by default
------------------
Fetching thousands of rules on every gate run would make the gate depend on
GitHub. `--fetch` caches a snapshot under `attack/cache/sigmahq/` with the
upstream commit sha; the gate runs `--check` against the cache. A missing cache
fails the check rather than passing, because "no overlap" and "never looked"
must not print the same thing.

Usage:
    python3 tools/sigmahq_overlap.py --fetch        # refresh the cache
    python3 tools/sigmahq_overlap.py                # report against the cache
    python3 tools/sigmahq_overlap.py --check        # gate
    python3 tools/sigmahq_overlap.py --json
"""
import argparse
import datetime
import json
import pathlib
import re
import sys
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / "attack" / "cache" / "sigmahq"
INDEX = CACHE / "index.json"
RECORD = ROOT / "attack" / "sigmahq-overlap.json"
UPSTREAM = "SigmaHQ/sigma"
API = "https://api.github.com"

# Sysmon EventID -> the category name upstream uses.
SYSMON_EVENT_CATEGORY = {
    1: "process_creation", 2: "file_change", 3: "network_connection",
    5: "process_terminate", 6: "driver_load", 7: "image_load",
    8: "create_remote_thread", 9: "raw_access_thread", 10: "process_access",
    11: "file_event", 12: "registry_add_delete", 13: "registry_set",
    14: "registry_rename", 15: "create_stream_hash", 17: "pipe_created",
    18: "pipe_connected", 19: "wmi_event", 20: "wmi_event", 21: "wmi_event",
    22: "dns_query", 23: "file_delete", 24: "clipboard_capture",
    25: "process_tampering", 26: "file_delete", 27: "file_block",
    28: "file_block",
}

# Upstream names for the same event family. Sysmon 12/13/14 is one family
# upstream calls `registry_event` and this repository splits by EventID meaning.
FAMILY_ALIASES = {
    "registry_event": {"registry_set", "registry_add_delete", "registry_rename"},
    "registry_add": {"registry_add_delete"},
    "registry_delete": {"registry_add_delete"},
    "file_creation": {"file_event"},
}

UPSTREAM_WINDOWS_CATEGORIES = {
    "process_creation", "file_event", "file_delete", "file_change",
    "image_load", "network_connection", "registry_set", "registry_add",
    "registry_delete", "registry_rename", "pipe_created", "dns_query",
    "process_access", "create_remote_thread", "driver_load", "wmi_event",
    "create_stream_hash", "process_tampering",
}


# --------------------------------------------------------------------- fetch
def _get(url, binary=False):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.raw" if not binary else "*/*",
        "User-Agent": "ghost-detection-lab-overlap-check",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    return data if binary else data.decode("utf-8")


def upstream_head():
    payload = json.loads(_get(f"{API}/repos/{UPSTREAM}/commits?per_page=1&path=rules"))
    return payload[0]["sha"], payload[0]["commit"]["committer"]["date"]


def fetch(max_rules=None):
    sha, date = upstream_head()
    tree = json.loads(_get(f"{API}/repos/{UPSTREAM}/git/trees/{sha}?recursive=1"))
    if tree.get("truncated"):
        raise SystemExit("FAIL: upstream tree listing was truncated; refusing to "
                         "write a partial cache")
    paths = sorted(e["path"] for e in tree["tree"]
                   if e["path"].endswith(".yml") and e["path"].startswith("rules/"))
    if max_rules:
        paths = paths[:max_rules]

    INDEX.parent.mkdir(parents=True, exist_ok=True)
    stored = 0
    for path in paths:
        target = CACHE / path
        if target.is_file():
            stored += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_text(
                _get(f"{API}/repos/{UPSTREAM}/contents/{path}?ref={sha}"),
                encoding="utf-8")
            stored += 1
        except Exception as exc:  # noqa: BLE001 - one bad file must not kill the snapshot
            print(f"WARN: {path}: {exc}", file=sys.stderr)
    INDEX.write_text(json.dumps({
        "upstream": UPSTREAM, "commit": sha, "commit_date": date,
        "fetched_utc": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat(),
        "rules": len(paths),
    }, indent=2) + "\n", encoding="utf-8")
    print(f"sigmahq: cached {stored} rule(s) at {sha[:12]} ({date})")
    return 0


# ------------------------------------------------------------------- compare
def load_ours():
    out = {}
    for path in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("id"):
            out[doc["id"]] = {"doc": doc,
                              "path": path.relative_to(ROOT).as_posix()}
    return out


def load_theirs():
    records = {}
    for path in sorted(CACHE.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and doc.get("detection"):
            records[path.relative_to(CACHE).as_posix()] = doc
    return records


def _event_ids(doc):
    ids = set()
    for name, body in (doc.get("detection") or {}).items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for key, value in body.items():
            if key.split("|", 1)[0] == "EventID":
                values = value if isinstance(value, list) else [value]
                for v in values:
                    try:
                        ids.add(int(v))
                    except (TypeError, ValueError):
                        continue
    return ids


def _expand(family):
    return {family} | FAMILY_ALIASES.get(family, set())


def _families(doc):
    """The set of event families a rule can see, in upstream's vocabulary.

    A rule with `service: sysmon` and EventID 1 is `process_creation`. A rule
    with no EventID can see every Sysmon family, so it is compared against all of
    them: over-reporting is the right way to be wrong for a check whose failure
    mode is "claimed there was no overlap".
    """
    ls = doc.get("logsource") or {}
    service = (ls.get("service") or "").lower()
    category = (ls.get("category") or "").lower()
    product = (ls.get("product") or "").lower()

    if service == "sysmon" or (product == "windows" and not category):
        ids = _event_ids(doc)
        if ids:
            fams = set()
            for i in ids:
                fams |= _expand(SYSMON_EVENT_CATEGORY.get(i, f"sysmon_{i}"))
            return fams
        return set(UPSTREAM_WINDOWS_CATEGORIES) | {"sysmon"}
    if category:
        return _expand(category)
    return {service or category or product}


def _product(doc):
    """Linux `process_creation` is not Windows `process_creation`.

    Without this guard, this repository's Windows rules were compared against
    Linux shell wrappers sharing nothing but a category name and a tag.
    """
    ls = doc.get("logsource") or {}
    product = (ls.get("product") or "").lower()
    if product:
        return product
    if (ls.get("service") or "").lower() == "sysmon":
        return "windows"
    return "unspecified"


def _techniques(doc):
    return {t.split(".", 1)[1].upper() for t in (doc.get("tags") or [])
            if isinstance(t, str) and t.startswith("attack.t")}


def _norm_path(value):
    """One separator spelling, no leading or trailing wildcards.

    An earlier version replaced the separator class with a *doubled* backslash,
    so every normalised path contained `\\\\` and the comparison then re-split on
    it - a one-character bug that silently halved every score.
    """
    text = str(value).lower().strip("*")
    text = text.replace("/", "\\")
    return re.sub(r"\\{2,}", lambda _m: "\\", text).strip("\\")


def _signature(doc):
    """field -> set of whole selected values, normalised.

    Whole values, not path segments: a segment set turns
    `\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run` into five independent
    tokens and destroys the one fact the comparison needs - that the path sits
    inside a parent key.
    """
    sig = {}
    for name, body in (doc.get("detection") or {}).items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for key, value in body.items():
            field = key.split("|", 1)[0].lower()
            if field == "eventid":
                continue   # the family join already compares this
            values = value if isinstance(value, list) else [value]
            for v in values:
                if isinstance(v, (str, int, float)):
                    sig.setdefault(field, set()).add(_norm_path(v))
    return sig


def _covered_by(evidence, cover):
    """Fraction of my (field, value) constraints that upstream also selects.

    Semantics, spelled out because this was implemented three times with the
    comparison reversed and every version produced plausible percentages:

        Rule A is covered by rule B when every event A matches, B also matches.
        For `contains` selections that holds exactly when B's required substring
        sits inside A's: if A requires `...\\CurrentVersion\\Run` and B requires
        `...\\CurrentVersion`, every A event is a B event, so B covers A.

    So the denominator is *my* evidence. 1.0 means "upstream already sees
    everything this rule sees". A symmetric Jaccard scores that pair near zero
    and reports a duplicate as unrelated.
    """
    if not evidence:
        return 0.0
    hits = total = 0
    for field_, values in evidence.items():
        theirs = cover.get(field_, set())
        for value in values:
            total += 1
            # One direction only: upstream covers mine when upstream's required
            # substring is inside mine. The symmetric `or` made a *narrow*
            # upstream rule look like it covered a *broad* one, which is the
            # opposite of the truth: `...\Run` selects fewer events than
            # `...\CurrentVersion`, so it covers less, not more.
            if any(t in value for t in theirs):
                hits += 1
    return hits / total if total else 0.0


def compare(ours, theirs):
    findings = []
    for rid, mine in ours.items():
        mdoc = mine["doc"]
        m_tech, m_sig = _techniques(mdoc), _signature(mdoc)
        for path, tdoc in theirs.items():
            if _product(tdoc) != _product(mdoc):
                continue
            if not (_families(tdoc) & _families(mdoc)):
                continue
            t_tech = _techniques(tdoc)
            if not (m_tech & t_tech):
                continue
            overlap = _covered_by(evidence=m_sig, cover=_signature(tdoc))
            if overlap >= 0.8 and m_tech <= t_tech:
                level = "duplicate"
            elif overlap >= 0.8:
                level = "divergent"
            elif overlap >= 0.55:
                level = "near"
            else:
                continue
            findings.append({
                "level": level,
                "ours": mine["path"],
                "ours_title": mdoc.get("title"),
                "upstream": path,
                "upstream_title": tdoc.get("title"),
                "overlap": round(overlap, 3),
                "techniques": sorted(m_tech & t_tech),
                "techniques_only_upstream": sorted(t_tech - m_tech),
                "techniques_only_ours": sorted(m_tech - t_tech),
            })
    order = {"duplicate": 0, "divergent": 1, "near": 2}
    findings.sort(key=lambda f: (order[f["level"]], -f["overlap"], f["ours"]))
    return findings


# ---------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-rules", type=int)
    args = ap.parse_args()

    if args.fetch:
        return fetch(args.max_rules)

    if not INDEX.is_file():
        print("FAIL: no upstream snapshot at attack/cache/sigmahq/. Run "
              "`python3 tools/sigmahq_overlap.py --fetch` - an empty cache and "
              "'no overlap found' must not print the same thing.", file=sys.stderr)
        return 1

    index = json.loads(INDEX.read_text(encoding="utf-8"))
    theirs = load_theirs()
    if not theirs:
        print("FAIL: the snapshot index exists but contains no rules", file=sys.stderr)
        return 1

    findings = compare(load_ours(), theirs)
    recorded = {}
    if RECORD.is_file():
        recorded = json.loads(RECORD.read_text(encoding="utf-8"))
    reviewed = {(r["ours"], r["upstream"]): r for r in
                (recorded.get("reviewed") or [])}

    if args.json:
        print(json.dumps({"snapshot": index, "findings": findings}, indent=2))
        return 0

    unreviewed = [f for f in findings
                  if f["level"] in ("duplicate", "divergent")
                  and (f["ours"], f["upstream"]) not in reviewed]
    by_level = {}
    for f in findings:
        by_level[f["level"]] = by_level.get(f["level"], 0) + 1

    print(f"sigmahq snapshot {index['commit'][:12]} ({index['commit_date']}), "
          f"{len(theirs)} rules")
    for f in findings:
        mark = "REVIEWED" if (f["ours"], f["upstream"]) in reviewed else "        "
        print(f"{f['level']:10} {f['overlap']:>5.0%}  {mark}  "
              f"{f['ours']}  ~  {f['upstream']}")
        if f["level"] == "divergent":
            print(f"{'':12}upstream-only techniques: "
                  f"{', '.join(f['techniques_only_upstream']) or '-'}; "
                  f"ours-only: {', '.join(f['techniques_only_ours']) or '-'}")
    print(f"\noverlap: {len(findings)} relationship(s) with a compatible logsource "
          f"and a shared technique ({by_level}); {len(unreviewed)} unreviewed "
          f"duplicate/divergent pair(s)")

    if args.check and unreviewed:
        for f in unreviewed:
            print(f"FAIL {f['ours']} overlaps {f['upstream']} "
                  f"({f['level']}, {f['overlap']:.0%} covered by upstream) and "
                  f"nobody has recorded the relationship", file=sys.stderr)
        print("      record it in attack/sigmahq-overlap.json under `reviewed` "
              "with a decision from the file's own vocabulary", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
