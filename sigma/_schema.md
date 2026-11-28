# Sigma rule schema for this lab

## Required keys

Every rule under `sigma/` must have all of these. `detection` is required unless
a `correlation` block is present.

```yaml
title: short imperative title
id: lowercase UUIDv4 (unique across the repo, never shared with a member rule)
dedup_key: "rule:<id>:host:user"     # suppression identity - required
status: experimental                  # Sigma status - parsed by pySigma
lifecycle: designed                   # repo lifecycle - separate on purpose
description: what behavior it detects and why
author: ghost-detection-lab
date: YYYY-MM-DD                      # ISO date, parsed as a date not a string
tags: [attack.tXXXX]                  # TECHNIQUES only
tactics: [attack.<tactic>]            # TACTICS only - never in tags
references:                           # non-empty list - required
  - https://attack.mitre.org/techniques/TXXXX/
  - inventory.md
logsource: {product: windows, service: sysmon}
detection: { <selections>, condition: <expression> }
falsepositives: [documented benign lookalikes]
level: informational | low | medium | high | critical
sample_ref: PIN-0000                  # optional; must match samples/PINS.md
fixture_ref: fixtures/per_rule/<id>.json
conversion:                           # required: measured, not aspirational
  splunk: supported
  elastic: unsupported
  kusto: unsupported
  note: why the backend cannot take it
```

## Sigma `status` vs repo `lifecycle`

These were conflated, and it broke conversion: pySigma validates `status`
against its own enum (`stable`, `test`, `experimental`, `deprecated`,
`unsupported`) and raised `SigmaStatusError` on every rule in this repo, so no
rule ever reached a backend. Now:

- `status` is the Sigma field and must hold a Sigma value.
- `lifecycle` is the repo's own state machine:
  `desired -> designed -> captured -> validated -> deployed`, plus `stale` and
  `deprecated`. It is not read by pySigma.

A rule cannot move to `captured` until a fixture captured from a host exists
(`tools/capture_kit.py` prints the procedure).

## Hard rules enforced by `detection-as-code/validate_rules.py`

1. **Duplicate keys fail.** The loader uses a custom `construct_mapping` that
   raises on repeated YAML keys. PyYAML's last-wins behavior is not accepted.
1a. **Path literals get exactly one escaping layer.** In a single-quoted YAML
   string `'\\autorun.inf'` is the two-character sequence `\` + `a`; that is a
   real path. `'\\\\autorun.inf'` is two backslashes and can never match a
   Windows path. `tests/test_rules.py::test_no_double_escaped_paths` enforces it.
1b. **Correlation join keys must exist in every member.** A correlation that
   groups by `ProcessId` while its members select only `EventID` can never fire;
   `evaluate._join_values` checks this and a test asserts it.
2. **Tactics and techniques are separate.** `attack.execution` in `tags` is a
   validation error. Only `attack.tXXXX` IDs belong in `tags`.
3. **ATT&CK IDs are pinned.** Every technique must appear in
   `attack/attack-bundle-pin.json`. The pin records the ATT&CK version and a
   bundle hash; update the pin deliberately, never by accident of a new tag.
4. **`level`, `falsepositives`, and `references` are required.** An alert with no
   severity, no tuning guidance, and no reference is not reviewable.
4a. **`conversion` is required.** Each rule states which of splunk / elastic /
   kusto it converts to. `ci/convert_check.py` measures the claim and fails the
   gate on either over-claiming or under-claiming.
5. **`dedup_key` is required.** Without a suppression key, 31 rules on one host
   alert-storm.
6. **IDs are lower-case UUIDv4; dates are ISO dates.**

## ID namespace

All IDs are v4 UUIDs generated once and never reused. Overwriting a rule keeps
its ID; changing the behavior creates a new rule and a new ID.

## Deprecation policy

A rule is never deleted in place. Set `status: deprecated`, keep its ID, add a
`references` entry explaining why, and remove it from deployment in `deploy/`.
The matrix still lists deprecated rules so coverage accounting stays honest.
After one quarter, a deprecated rule can move to `yara/deprecated/` with a
matching changelog entry.

## Coverage generation

`attack/matrix.md` is generated from `tags` only. Tactics are counted separately
and never reported as techniques. Network-only rules are marked
`single-sourced`; correlation rules are marked `conversion-risk`.
