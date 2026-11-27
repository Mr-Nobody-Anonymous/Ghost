# Maturity model

Per technique, ten checks. A behavior is **covered** only at ten.

| # | Gate | Evidence |
|---|---|---|
| 1 | Telemetry present | `telemetry/data-sources.md` names source, event, and field |
| 2 | Rule exists | `attack/matrix.md` lists a rule with a pinned `attack.tXXXX` tag |
| 3 | Rule compiles to every target backend | `ci/convert_check.py` passes for splunk and kql |
| 4 | Telemetry proven to emit | clean baseline capture contains the required event ID and fields |
| 5 | TP fixture captured blind | `fixtures/per_rule/<id>.json` status `captured`, written without reading the rule |
| 6 | TP evaluated against a real event | `detection-as-code/evaluate.py` matches and asserts field values |
| 7 | Negative fixture stays quiet | `fixtures/negative/<id>.json` `must_not_match` produces no alert |
| 8 | Sequence rule where low-signal alone | `docs/sequence-rules.md` + sequence cases in the evaluator |
| 9 | Severity + triage step per rule | `response/rules/<id>.md`, level histogram in tests |
| 10 | Volume measured under ceiling | `metrics/ceilings.json` with `measured: true` |

## Current state

| Capability | State |
|---|---|
| Rule authoring | have (31 rules, 18 techniques) |
| Duplicate-key loader + required fields + tactic split + pin | have |
| Concrete fixtures (positive + negative with `must_not_match`) | have, 31 each, status `designed` |
| Rule evaluator (modifiers, conditions, sequence, frequency, value assertions) | have |
| Per-rule TP/FP tests | have (24 tests total) |
| Tool self-tests + mutation case | have |
| Backend conversion | **FAILING** - pySigma backends absent; correlation conversion unverified |
| Blind capture | **none** - fixtures authored from rule constraints, not captured |
| Golden clean baseline / benign corpus | **missing** - no FP proof in reality |
| Volume measurement | ceilings defined, `measured: false` |
| Sample pinning | schema + generated reference section; no artifact |
| evtx -> fixture parser | have (`tools/evtx_to_fixture.py`), not exercised on a real log |
| Status state machine | `designed -> captured -> validated -> deployed -> stale -> deprecated` enforced |
| Sigma spec version / OS / Sysmon minimums | declared per rule |
| Tarball | includes validator, evaluator, samples, emulation, analysis |

## Honest claim

The repository can now match every rule against a concrete event and assert
field values, and can prove each rule stays silent on a concrete negative
event. It still cannot prove detection on real telemetry: no blind capture, no
benign corpus execution, no backend conversion, no volume numbers. The gate's
conversion stage is deliberately red.
