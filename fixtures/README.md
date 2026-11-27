# Fixtures

A fixture is a description of expected telemetry, not a payload. No fixture in
this folder executes code or contains a working exploit.

## malicious/

One JSON file per technique, named `<T-ID>.json`. Each file states the expected
event, the fields the rule reads, and the benign lookalikes that must not trip
the rule. Start from `_template.json`.

## benign/

The false-positive corpus. Each entry names a legitimate software class, the
events it produces, and the tuning decision that keeps our rules quiet.

## Rule

- A rule is not "covered" until both a malicious fixture passes and the benign
  corpus is clean.
- Fixtures reference rules by `rule_id`, never by path.
- If telemetry changes, regenerate the fixture; never hand-edit observed values
  to make a test pass.
