# Runbook

## Validate a rule change

```bash
python3 detection-as-code/validate_rules.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/generate_fixtures.py --check
python3 pipeline/field_contract.py --strict
bash ci/gate.sh
```

A rule is not done until the gate in `ci/gate.sh` passes end to end. The gate
fails on its own if a dependency is missing - it is never allowed to skip a
stage.

## Prove a rule fires (true positive)

The fixtures in `fixtures/per_rule/` are generated, not captured. To move one to
`captured`:

1. `python3 tools/capture_kit.py --rule <id-prefix>` - prints exactly which
   event IDs to collect, which fields the rule reads, and which inert emulator
   command produces the behaviour.
2. Stand up a disposable lab VM on an Internal network; snapshot first.
3. Apply `telemetry/sysmon-config.xml` and the policy in `telemetry/auditpol.md`.
4. Run the inert fixture for the technique. No real credentials, no real C2.
5. Capture the events and convert them:

   ```bash
   wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:true > capture.xml
   python3 tools/evtx_to_fixture.py --input capture.xml \
     --rule-id <id> --output fixtures/per_rule/<id>.json
   ```

6. Compare the captured event with what the rule asserts. Mark the rule
   `lifecycle: captured` and give the fixture a real `sample_ref` from
   `samples/PINS.md` only if the event actually matched.

A fixture status of `captured` with `sample_ref: PIN-0000` fails the test suite.

## Prove a rule stays quiet (false positive)

1. Run each class in `fixtures/benign/README.md` for one business day.
2. For every trip, write a tuning decision in `docs/tuning-log.md`.
3. Re-run the rule; a class that still trips after tuning is a blocker.

No benign class has been executed yet. Precision is unknown, not good.

## Handle a rebuild

A new build invalidates `samples/PINS.md` references. Do not edit a rule's
`sample_ref` in place. Create a new pin with a new hash, regenerate fixtures, and
re-run the gate.

## ATT&CK pin

The pin is generated from the real STIX bundle, not hand-written:

```bash
python3 tools/pin_attack_bundle.py --version 14.1 --fetch
python3 tools/pin_attack_bundle.py --verify
```

The bundle is not committed (`attack/cache/` is ignored). If the cached bundle
is absent, validation checks technique IDs against the pinned list and says so;
it does not silently pretend to have verified the bundle.

## Response to an alert

See `analysis/iocs.md`, `analysis/report-template.md`, and the per-rule triage
step in `response/rules/<id>.md`. Preserve original artifacts, hash everything,
record UTC timestamps, and distinguish observed from inferred behavior.

## Stop conditions

Stop immediately if a test touches a system outside the lab, produces
availability impact, or uses real user data or credentials. Restore the snapshot.
