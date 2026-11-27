# Deployment

A Sigma rule that validates but does not convert to your backend is shelfware.

## Build a bundle

```bash
python3 ci/convert_check.py --backends splunk elastic kusto   # measure first
python3 deploy/build_bundle.py --backend splunk \
  --out dist/splunk-queries.spl --manifest dist/splunk-manifest.json
```

`build_bundle.py` emits the **real query text** produced by pySigma for every
rule that converts on the chosen backend, plus a manifest naming each excluded
rule and the reason. It refuses to build when `attack/conversion.json` is
missing or older than the rules it describes - a bundle built from stale results
is a bundle nobody proved.

Correlation rules are emitted with their member rules; on a platform that does
not convert correlations, deploy the members separately and build the join in
the SIEM.

## Which backends each rule converts to

`attack/matrix.md` ends with a per-rule, per-backend table generated from the
conversion run. The honest totals today: splunk 38/38, elastic 32/38,
kusto 32/38.

## Rollout

1. Stage as `informational` only; do not page anyone.
2. Measure events/day per rule (`metrics/`).
3. Run the benign corpus; tune allowlists.
4. Promote severity only after the FP rate is acceptable.
5. Keep the previous rule set available for rollback.

No rule has completed steps 1-3 yet: `metrics/ceilings.json` has
`measured: false` for all 37, and the benign corpus has never been run.

## Rollback

On a false-positive surge, disable by rule ID, not by deleting the file. Record
the disable and reason in `docs/tuning-log.md`.
