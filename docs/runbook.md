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
2. Stand up a disposable lab VM on an Internal network; snapshot first. Match
   `telemetry/lab-image.json` - Windows build, Sysmon version, audit policy,
   UTC clock. A capture from a different build is refused, and rightly: the
   fields a rule reads change between builds and the fixture would be evidence
   about a machine nobody can reproduce.
3. Apply `telemetry/sysmon-config.xml` and the policy in `telemetry/auditpol.md`.
4. Run the inert fixture for the technique. No real credentials, no real C2.
5. Capture the events and convert them:

   ```bash
   wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:true > capture.xml
   cmd /c ver          # note the build; the converter wants it
   python3 tools/evtx_to_fixture.py --input capture.xml \
     --rule-id <id> --host-build 10.0.22631.4169
   ```

   Output goes to `fixtures/captured/<id>.json` by default. Never write over
   `fixtures/per_rule/` - that file is the record of what the rule is *meant*
   to match, and overwriting it destroys the only evidence the rule was ever
   checked against.

6. Compare the captured event with what the rule asserts. Mark the rule
   `lifecycle: captured` and give the fixture a real `sample_ref` from
   `samples/PINS.md` only if the event actually matched.

The converter exits 2 and writes nothing when the rule does not fire on the
capture, or when the capture cannot say which build it came from. Both are
findings about the environment or the rule, not files to file away.

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
python3 tools/pin_attack_bundle.py --version 20.1 --fetch
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
