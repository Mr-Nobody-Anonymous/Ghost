# Maturity model

Per technique, ten checks. A behavior is **covered** only at ten.

| # | Gate | Evidence |
|---|---|---|
| 1 | Telemetry present | `telemetry/data-sources.md` names source, event, and field |
| 2 | Rule exists | `attack/matrix.md` lists a rule with a pinned `attack.tXXXX` tag |
| 3 | Rule compiles to every target backend | `ci/convert_check.py` passes for splunk and kql |
| 4 | Telemetry proven to emit | clean baseline capture contains the required event ID and fields |
| 5 | TP fixture captured blind | `fixtures/per_rule/<id>.json` status `captured`, written without reading the rule |
| 6 | TP test asserts field values | `tests/test_rules.py` field-assertion test passes |
| 7 | Negative fixture stays quiet | `fixtures/negative/<id>.json` produces no alert |
| 8 | Sequence rule where low-signal alone | `docs/sequence-rules.md` maps the ordering |
| 9 | Severity + triage step per rule | `response/rules/<id>.md` |
| 10 | Volume measured under ceiling | `metrics/ceilings.json` with `measured: true` |

## Current state

| Capability | State |
|---|---|
| Rule authoring (Sigma/YARA) | have (31 rules, 18 distinct techniques) |
| Offline validation + duplicate-key detection | have |
| Tactic/technique split + ATT&CK pin | have |
| Coverage generation | have (techniques counted from `tags` only) |
| Telemetry definitions | have (gaps documented) |
| Sysmon config + audit policy + ETW list | have; config hash pinned in `baseline/manifest.json` |
| Per-rule positive fixtures | 31 DESIGNED stubs, 0 blind captures |
| Per-rule negative fixtures | 31 designed stubs, 0 executed |
| Backend conversion | **FAILING** - pySigma backends not installed; rules not proven deployable |
| True-positive proof | **none** - fixtures are authored from the same model as the rules |
| False-positive proof | corpus specified, not executed |
| Precision reporting | missing |
| Volume ceilings | defined, `measured: false` for all rules |
| Sample pinning | schema only — **no artifact stored** |
| PENDING ratchet | have, but PENDING=0 is no longer meaningful now that fixtures exist |
| Pipeline / OS matrix / inventory | specs only |
| Golden clean capture | **missing** - no TP result is diffable |

## Gate status

The structural stages pass. The conversion stage is red on purpose:
an unconverted rule is shelfware. A green structural gate is not a
coverage claim.

## Honest claim

This folder can author, validate, and structure-test rules. It cannot prove
detection: no pinned artifact, no blind capture, no backend conversion, no
benign corpus execution, no volume measurement. Do not report a technique as
covered on the strength of a rule or a passing structural stage.
