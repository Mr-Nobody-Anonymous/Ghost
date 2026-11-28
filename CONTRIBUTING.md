# Contributing

## Requirements

- Python **3.9 or newer** (the floor: `Path.is_relative_to` in
  `tools/evtx_to_fixture.py`; enforced by `ci/check_env.py`, and CI runs both
  3.9 and 3.11)
- `pip install -r requirements.txt` — the versions are pinned because the gate
  compares generated query text against results produced with exactly those
  versions. A backend upgrade is a deliberate commit, not a side effect.


Thanks for helping improve the detection content.

## What belongs here

- Sigma rules (`sigma/`), YARA rules (`yara/`)
- Telemetry definitions and collector configuration (`telemetry/`, `pipeline/`)
- Inert fixtures and test harnesses (`fixtures/`, `tests/`, `ci/`)
- Documentation that makes detections reviewable (`docs/`, `response/`, `metrics/`)

## What does not belong here

- Implant source, build recipes, or compiled payloads
- Exploit code, evasion implementations, or working C2
- Real credentials, real user data, or captures from systems you do not own
- Anything that executes against a third party

Contributions containing offensive implementations will be declined. This is
a defensive repository by design.

## Before opening a pull request

1. Read `sigma/_schema.md`. Every rule needs `level`, `falsepositives`,
   `references`, `dedup_key`, pinned ATT&CK technique tags, and a separate
   `tactics` list.
2. Run the checks locally:

```bash
python3 detection-as-code/validate_rules.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/generate_matrix.py
```

3. Add or update a fixture under `fixtures/per_rule/` and a negative case under
   `fixtures/negative/`. Fixtures must be authored from captured events, not
   copied from the rule. If you cannot capture yet, mark status `designed`.
4. Add a triage step in `response/rules/<id>.md` and a volume ceiling entry in
   `metrics/ceilings.json`.
5. If you change `telemetry/sysmon-config.xml` or `telemetry/auditpol.md`,
   regenerate `baseline/manifest.json` and explain why in the PR.

## Commit hygiene

- Keep commits focused; one rule per commit where practical.
- Never commit generated packages (`dist/`), bytecode, or traffic logs.
- Use the repository LICENSE for all contributions.
