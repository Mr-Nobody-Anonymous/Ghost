#!/usr/bin/env python3
"""Beacon jitter detector: inter-arrival statistics, not a count threshold.

`docs/sequence-rules.md` said the distribution job "is documented here and not
implemented". A fixed `count >= N in T` cannot tell a 45 s beacon with 0.35
jitter from a busy poller, because the beacon's *intervals* are regular and the
poller's are not. This implements the test.

Method, per (source, destination) pair:

  1. collect event timestamps, sort, diff -> inter-arrival times
  2. drop the warm-up pair: fewer than MIN_INTERVALS intervals is noise
  3. compute median and the coefficient of variation (CV = stdev / mean)
  4. a beacon is a pair whose CV is below JITTER_CEILING while its median
     interval sits in a plausible sleep range

Jitter is exactly CV: a beacon sleeping `base * (1 +- jitter)` in uniform draws
has stdev = base*jitter/sqrt(3), so CV = jitter/sqrt(3) ~= 0.577*jitter. A 45 s
beacon with 0.35 jitter has CV ~= 0.20. A human, a scheduler, or a retry storm
has CV well above 0.4.

What this is not: a detector of *any* periodic traffic. Backups, NTP, metrics
scrapers and update checks are periodic on purpose, and no statistic can
separate them from C2 - that is what destination reputation and the rule's own
benign-class list are for. The tool reports candidate pairs and their numbers;
a human decides.

Self-test is part of the contract: `--selftest` generates a synthetic beacon
with jitter and a synthetic noisy poller and asserts the detector separates
them. ci/gate.sh runs it, so a change that breaks the statistic fails the build
instead of quietly returning fewer alerts.

Usage:
    python3 analytics/beacon_jitter.py --selftest
    python3 analytics/beacon_jitter.py fixtures/beacon_jitter_sample.jsonl
    python3 analytics/beacon_jitter.py --json flows.jsonl
"""
import argparse
import json
import random
import statistics
import sys

MIN_INTERVALS = 5           # fewer than this and a "pattern" is an accident
JITTER_CEILING = 0.30       # CV at or below this is regular
MIN_MEDIAN, MAX_MEDIAN = 5.0, 3600.0   # plausible sleep range, seconds

# The candidate filter from sigma/network/netflow/beacon_interval_shift.yml,
# duplicated here on purpose: the rule narrows the flow set and this tool
# measures it, and both halves must be checked separately. Backups to
# vault.corp at exactly 300s have a CV of 0.012 and are indistinguishable from
# a beacon by statistic alone - the filter, not the maths, is what removes them.
LOCAL_SUFFIXES = (".local", ".internal", ".corp")


def inter_arrivals(times):
    ts = sorted(t for t in times)
    return [b - a for a, b in zip(ts, ts[1:]) if b > a]


def analyse(times):
    """Return a verdict dict for one pair's timestamp list."""
    iv = inter_arrivals(times)
    result = {
        "events": len(times),
        "intervals": len(iv),
        "verdict": "insufficient_data",
        "median_interval": None,
        "mean_interval": None,
        "stdev": None,
        "cv": None,
    }
    if len(iv) < MIN_INTERVALS:
        return result
    mean = statistics.fmean(iv)
    median = statistics.median(iv)
    stdev = statistics.stdev(iv) if len(iv) > 1 else 0.0
    cv = stdev / mean if mean else 0.0
    result.update(mean_interval=round(mean, 3), median_interval=round(median, 3),
                  stdev=round(stdev, 3), cv=round(cv, 4))
    if not (MIN_MEDIAN <= median <= MAX_MEDIAN):
        result["verdict"] = "interval_out_of_range"
    elif cv <= JITTER_CEILING:
        result["verdict"] = "beacon_like"
    else:
        result["verdict"] = "irregular"
    return result


def apply_rule_filter(pairs):
    """Split pairs into (kept, filtered) using the rule's local-domain filter."""
    kept, filtered = {}, {}
    for (src, dst), times in pairs.items():
        if dst.lower().endswith(LOCAL_SUFFIXES):
            filtered[(src, dst)] = times
        else:
            kept[(src, dst)] = times
    return kept, filtered


def load_pairs(path):
    """Group timestamps under (src, dst) from JSONL flow records.

    Accepts `SourceAddress`/`src` and `DestinationHostname`/`dst` because the
    repository's two netflow sources name them differently, and `_ts` or `ts`
    in epoch seconds.
    """
    pairs = {}
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"FAIL: {path}:{n} is not JSON: {exc}") from exc
            src = rec.get("SourceAddress") or rec.get("src")
            dst = rec.get("DestinationHostname") or rec.get("dst")
            ts = rec.get("_ts", rec.get("ts"))
            if src is None or dst is None or ts is None:
                raise SystemExit(f"FAIL: {path}:{n} needs src/SourceAddress, "
                                 f"dst/DestinationHostname and ts/_ts")
            pairs.setdefault((src, dst), []).append(float(ts))
    return pairs


def selftest():
    """A synthetic beacon and a synthetic noisy poller must separate."""
    random.seed(20261127)          # deterministic: this is a build gate
    base, jitter, n = 45.0, 0.35, 31
    t = 0.0
    beacon = []
    for _ in range(n):
        t += base * (1 + random.uniform(-jitter, jitter))
        beacon.append(t)

    # A poller with the same mean but log-normal-ish noise, which is what a
    # retry backoff or a user-driven client actually looks like.
    t = 0.0
    noisy = []
    for _ in range(n):
        t += base * random.lognormvariate(0, 0.9)
        noisy.append(t)

    # A flood: 200 events in a very short window, well under the median floor.
    flood = [i * 0.05 for i in range(200)]

    b, p, f = analyse(beacon), analyse(noisy), analyse(flood)
    print(f"beacon : events={b['events']} median={b['median_interval']}s "
          f"cv={b['cv']} -> {b['verdict']}")
    print(f"poller : events={p['events']} median={p['median_interval']}s "
          f"cv={p['cv']} -> {p['verdict']}")
    print(f"flood  : events={f['events']} median={f['median_interval']}s "
          f"cv={f['cv']} -> {f['verdict']}")

    ok = True
    if b["verdict"] != "beacon_like":
        print(f"FAIL: a {base}s beacon with {jitter} jitter was not detected "
              f"(cv={b['cv']}, ceiling={JITTER_CEILING})", file=sys.stderr)
        ok = False
    if p["verdict"] == "beacon_like":
        print(f"FAIL: a log-normal poller was called a beacon (cv={p['cv']})",
              file=sys.stderr)
        ok = False
    if f["verdict"] != "interval_out_of_range":
        print(f"FAIL: a 20/s flood was not rejected on interval "
              f"({f['median_interval']}s)", file=sys.stderr)
        ok = False

    # The load-bearing claim: a count threshold cannot separate these two.
    # Both have ~30 events; only the interval distribution differs.
    if b["events"] < 20 or p["events"] < 20:
        print("FAIL: selftest series too short to prove the point", file=sys.stderr)
        ok = False
    # The composition claim: the statistic cannot remove a regular backup, the
    # rule's domain filter can, and the tool must apply it.
    backup = [i * 300.0 for i in range(30)]
    kept, filtered = apply_rule_filter({("h", "vault.corp"): backup,
                                        ("h", "cdn.example"): beacon})
    if set(filtered) != {("h", "vault.corp")} or set(kept) != {("h", "cdn.example")}:
        print("FAIL: the rule's local-domain filter did not split the pairs",
              file=sys.stderr)
        ok = False
    if analyse(backup)["verdict"] != "beacon_like":
        print("FAIL: selftest assumes a 300s backup looks beacon-like; if the "
              "statistic changed, this claim in the docs is stale", file=sys.stderr)
        ok = False

    print("selftest:", "OK - a count threshold sees two 30-event flows, the "
                       "interval distribution sees one beacon" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flows", nargs="?", help="JSONL flow records")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--no-rule-filter", action="store_true",
                    help="keep .local/.internal/.corp destinations; they are "
                         "filtered by default, as beacon_interval_shift.yml does")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.flows:
        ap.error("give a JSONL file or --selftest")

    pairs = load_pairs(args.flows)
    filtered = {}
    if not args.no_rule_filter:
        pairs, filtered = apply_rule_filter(pairs)
    findings = []
    for (src, dst), times in sorted(pairs.items()):
        verdict = analyse(times)
        verdict.update(src=src, dst=dst)
        findings.append(verdict)

    if args.json:
        # Nothing but JSON on stdout: the sample fixture test parses this.
        print(json.dumps(findings, indent=2))
        beacons = [f for f in findings if f["verdict"] == "beacon_like"]
        print(f"beacon_jitter: {len(findings)} pair(s), {len(beacons)} beacon-like",
              file=sys.stderr)
    else:
        print(f"{'src':<18} {'dst':<28} {'n':>4} {'median':>8} {'cv':>7}  verdict")
        for f in findings:
            print(f"{f['src']:<18} {f['dst']:<28} {f['events']:>4} "
                  f"{str(f['median_interval']):>8} {str(f['cv']):>7}  {f['verdict']}")

    if args.json:
        return 0

    beacons = [f for f in findings if f["verdict"] == "beacon_like"]
    print(f"beacon_jitter: {len(findings)} pair(s) after the rule's local-domain "
          f"filter, {len(beacons)} beacon-like "
          f"(cv <= {JITTER_CEILING}, median {MIN_MEDIAN:g}-{MAX_MEDIAN:g}s)")
    if filtered:
        print(f"  filtered by rule (never measured): {len(filtered)} pair(s) - "
              f"{', '.join(sorted(d for _, d in filtered))}")
        print("  A regular backup to *.corp has cv 0.01 and is not separable by "
              "statistic; the filter is what removes it. Run --no-rule-filter "
              "to see that.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
