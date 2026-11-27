# Sigma rule schema for this lab

## Required keys

Every rule under `sigma/` must have all of these. `detection` is required unless
a `correlation` block is present.

```yaml
title: short imperative title
id: lowercase UUIDv4 (unique across the repo)
dedup_key: "rule:<id>:host:user"     # suppression identity - required
status: experimental | test | stable
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
```

## Hard rules enforced by `detection-as-code/validate_rules.py`

1. **Duplicate keys fail.** The loader uses a custom `construct_mapping` that
   raises on repeated YAML keys. PyYAML's last-wins behavior is not accepted.
2. **Tactics and techniques are separate.** `attack.execution` in `tags` is a
   validation error. Only `attack.tXXXX` IDs belong in `tags`.
3. **ATT&CK IDs are pinned.** Every technique must appear in
   `attack/attack-bundle-pin.json`. The pin records the ATT&CK version and a
   bundle hash; update the pin deliberately, never by accident of a new tag.
4. **`level`, `falsepositives`, and `references` are required.** An alert with no
   severity, no tuning guidance, and no reference is not reviewable.
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
