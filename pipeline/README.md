# Pipeline

Rules must run against parsed fields, not regex on raw event text.

## Flow

```
collector -> parser -> field normalization -> index -> rules -> alerts
```

- **Collector:** Sysmon, Zeek, proxy/SWG, EDR memory telemetry.
- **Parser:** map each source to the field names in `telemetry/data-sources.md`.
- **Normalizer:** keep original field names under `raw.*` so a rule that fires
  for the wrong reason can be debugged.
- **Index:** one event type per index; UTC timestamps via NTP.
- **Rules:** Sigma converted per backend; YARA against collected artifacts.

## Field contract (enforced)

```bash
python3 pipeline/field_contract.py --strict
```

Every field a rule reads must appear in the contract table in
`telemetry/data-sources.md`, with the event that carries it. The check also
rejects selections that can never match and are recorded there:

- Sysmon 10 `TargetImage` selecting a **DLL** - TargetImage is a process image,
  never a loaded module
- Sysmon **23** used as a delete event - FileDelete is 26
- Sysmon **24** (ClipboardChange) in a rule - not enabled in the lab config

This is the check that the previous prose version of this page described and no
code performed.

## Query lint

```bash
python3 pipeline/lint_queries.py
```

The hunting queries in `hunt-queries.md`, `network/ja3-x509.md` and
`docs/sequence-rules.md` are checked for balanced delimiters and unbounded
`index=` searches. They are not executed - none of them has run against a real
index.

## Drift test

`baseline/manifest.json` pins the hashes of `telemetry/sysmon-config.xml` and
`telemetry/auditpol.md`; `tests/test_rules.py::test_baseline_config_drift` fails
when either changes without a re-pin.
