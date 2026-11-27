# Detection-as-code tooling

Utilities for keeping the rule set valid as it grows. No network access, no
external services.

## validate_rules.py

Reads every `*.yml` in `../sigma/` and fails on:

- duplicate YAML keys (a strict loader; PyYAML's last-wins is not accepted)
- a `status` outside the Sigma enum (which pySigma rejects before conversion)
- a `lifecycle` outside the repo state machine
- missing required metadata: `level`, `falsepositives`, `references`,
  `dedup_key`, `conversion`, `dedup_window`, `min_eval_interval`, `min_os`,
  `sample_ref`, `sigma_spec_version`
- an ATT&CK technique outside the pinned bundle, or a tactic tag in `tags:`
- a malformed UUID (must be lowercase v4) or a non-ISO `date`
- an incomplete `conversion:` block

```bash
python3 validate_rules.py            # checks ../sigma
python3 validate_rules.py --path /some/other/rules
```

## evaluate.py

Matches rules against the JSON fixtures in `../fixtures/per_rule/` using real
Sigma semantics:

- field modifiers: `contains`, `contains|all`, `startswith`, `endswith`, `re`,
  `base64`, `windash`, `exists`, and 2.x `fieldref`
- condition grammar: `and` / `or` / `not`, parentheses, `1 of x*`, with **NOT >
  OR > AND** precedence (which is also Splunk's, so generated SPL behaves the
  same way this harness does)
- correlations: `event_count` (group-by, timespan, `condition: {gte|lt}`) and
  `temporal` / `temporal_ordered` (one match per member, in order when required,
  inside the timespan, per group)

```bash
python3 evaluate.py                     # all fixtures
python3 evaluate.py --rule <id>         # one rule
```

The harness also *generates* fixtures (`sequence_events`, `candidate_events`)
so `tools/generate_fixtures.py` cannot drift from the rules it describes: a
candidate event is only emitted if the evaluator says the rule matches it.

## fieldtypes.py

The field-type model used when rendering fixture values. Without it, every
constraint collapsed into one `C:\...` string and produced registry keys under
`C:\Users`, URIs as file paths, and `.bmp` as a directory name. It renders:

| Field class | Rendered as |
|---|---|
| `TargetObject`, `ObjectName` | a registry path with the right hive |
| `Image`, `ParentImage`, `TargetFilename` | an absolute path anchored on the constraint (`\AppData\Local\Temp\`, `\Program Files\`, ...) |
| `CommandLine` | a plausible command line, not a path |
| `cs-uri-*`, `QueryName`, `query` | a URI / DNS name |
| `cs-header-*` | a header value of the right shape |

## Working together

```
validate_rules.py  -> structure
pipeline/field_contract.py -> every field read is documented
evaluate.py        -> the rule matches what it says it matches
tools/generate_fixtures.py --check -> fixtures are not stale
ci/convert_check.py -> the rule converts to the backend it claims
```

Exit code 0 means every check above passed. Wire `ci/gate.sh` into a pre-commit
hook or CI job so a broken rule never reaches a SIEM.
