# Pipeline

Rules must run against parsed fields, not regex on raw event text.

## Flow

```
collector -> parser -> field normalization -> index -> rules -> alerts
```

- **Collector:** Sysmon/ETX, Zeek, proxy/SWG, EDR memory telemetry.
- **Parser:** map each source to the field names in `telemetry/data-sources.md`.
- **Normalizer:** preserve original field names in a `raw.*` namespace so a rule
  that fires for the wrong reason can be debugged.
- **Index:** one event type per index; keep UTC timestamps synchronized via NTP.
- **Rules:** Sigma converted per backend; YARA against collected artifacts.

## Field contract

Every rule's `detection` selections reference fields defined in
`telemetry/data-sources.md`. If a field is not in the table, the rule is not
deployable until the field is added and proven in a baseline capture.

## Drift test

Compare the deployed collector config hash to the repo copy. A mismatch fails CI.
