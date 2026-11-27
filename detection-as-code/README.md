# Detection-as-code tooling

Utilities for keeping the rule set valid as it grows. No network access, no
external services.

## validate_rules.py

Reads every `*.yml` in `../sigma/` and checks structure: required keys, unique
IDs, presence of `logsource`/`detection`/`condition`, ATT&CK tags, and YAML
syntax when PyYAML is installed.

```bash
python3 validate_rules.py            # checks ../sigma
python3 validate_rules.py --path /some/other/rules
```

Exit code 0 means all rules passed; 1 means at least one failed. Wire this into
a pre-commit hook or CI job so a broken rule never reaches a SIEM.
