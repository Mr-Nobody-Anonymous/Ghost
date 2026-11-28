# Tuning log

Every false positive gets an entry. A rule without documented FP decisions is
not production-ready.

<!-- BEGIN GENERATED TABLE -->
| Date | Rule | Benign class | Observed trip | Decision | Rationale |
|---|---|---|---|---|---|
| — | — | — | — | — | no observations recorded yet |
<!-- END GENERATED TABLE -->

## Decision vocabulary

- `allowlist` — exclude a specific image, path, host, or account
- `threshold` — raise event count or time window
- `retire` — rule cannot achieve acceptable precision with available telemetry
- `keep` — trip was legitimate behavior and should be investigated

## How this loop works

`tuning/observations.csv` is the source of truth: one row per alert a human
actually looked at. `tools/tuning_log.py --render` writes the table above from
it, so the CSV and the document cannot drift apart. `--check` rejects a row that
names a rule this repository does not contain, a date in the future, a decision
outside the vocabulary, or a rationale too short to mean anything.

`--apply-ceilings` copies a measured `events_per_day` into
`metrics/ceilings.json` and flips that rule's `measured` flag. A ceiling stops
being a guess at the moment an observation makes it one.

**The invariant the gate enforces:** a rule may not be `lifecycle: tuned`
without at least one `keep` observation. `tuned` is a statement that somebody
watched this rule fire on real telemetry and judged it correct. Nothing in a
repository can substitute for that, so the check does not try - it only refuses
the claim when the evidence is missing.

Every rule here is currently `designed`, so the invariant holds vacuously today
and starts biting the first time anyone promotes one.

## Review cadence

Quarterly. Re-run the benign corpus after any rule or telemetry change. Record
precision (true positives / all alerts) in `reports/`.
