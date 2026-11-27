# Tuning log

Every false positive gets an entry. A rule without documented FP decisions is
not production-ready.

| Date | Rule ID | Benign class | Observed trip | Decision | Rationale |
|---|---|---|---|---|---|
| — | — | — | — | — | no entries yet |

## Decision vocabulary

- `allowlist` — exclude a specific image, path, host, or account
- `threshold` — raise event count or time window
- `retire` — rule cannot achieve acceptable precision with available telemetry
- `keep` — trip was legitimate behavior and should be investigated

## Review cadence

Quarterly. Re-run the benign corpus after any rule or telemetry change. Record
precision (true positives / all alerts) in `reports/`.
