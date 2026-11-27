# Runbook

## Validate a rule change

```bash
python3 detection-as-code/validate_rules.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/generate_matrix.py
```

A rule is not done until the CI gate in `ci/gate.sh` passes end to end.

## Prove a rule fires (true positive)

1. Stand up a disposable lab VM on an Internal network; snapshot first.
2. Enable the telemetry in `telemetry/sysmon-config.xml` and `telemetry/auditpol.md`.
3. Run the inert fixture for the technique. No real credentials, no real C2.
4. Compare expected fields from `fixtures/malicious/<T-ID>.json` with the events
   actually collected. Mark the fixture `validated` only if they match.
5. Record UTC timestamps, event IDs, and field values in the fixture file.

## Prove a rule stays quiet (false positive)

1. Run each class in `fixtures/benign/README.md` for one business day.
2. For every trip, write a tuning decision in `docs/tuning-log.md`.
3. Re-run the rule; a class that still trips after tuning is a blocker.

## Handle a rebuild

A new build invalidates `samples/PINS.md` references. Do not edit a rule's
`sample_ref` in place. Create a new pin with a new hash, regenerate fixtures,
and re-run the gate.

## Response to an alert

See `analysis/iocs.md` and `analysis/report-template.md`. Preserve original artifacts, hash everything, record
UTC timestamps, and distinguish observed from inferred behavior.

## Stop conditions

Stop immediately if a test touches a system outside the lab, produces
availability impact, or uses real user data or credentials. Restore the snapshot.
