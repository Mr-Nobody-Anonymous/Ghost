# Maturity model

Per technique, ten checks. A behavior is **covered** only at ten.

| # | Gate | Evidence | State |
|---|---|---|---|
| 1 | Telemetry present | `telemetry/data-sources.md` names source, event, and field; `pipeline/field_contract.py` passes | **passing** for documented fields; 7 behaviors have no source at all |
| 2 | Rule exists | `attack/matrix.md` lists a rule with a pinned `attack.tXXXX` tag | **passing** - 37 rules, 18 techniques, pin generated from the ATT&CK 20.1 bundle (706 techniques, 15 tactics) |
| 3 | Rule compiles to the *deployed* backend | `ci/convert_check.py` compares each rule's declared support to real pySigma output | **passing but partial** - splunk 37/37, elastic 31/37, kusto 31/37 |
| 4 | Telemetry proven to emit | clean baseline capture contains the required event ID and fields | **missing** - no golden capture exists |
| 5 | TP fixture captured blind | `fixtures/per_rule/<id>.json` status `captured`, written without reading the rule | **missing** - all 37 are `designed` |
| 6 | TP evaluated against a real event | `detection-as-code/evaluate.py` matches and asserts field values | **passing on generated events only** |
| 7 | Negative fixture stays quiet | `fixtures/negative/<id>.json` `must_not_match` produces no alert | **passing on generated events only** |
| 8 | Sequence rule where low-signal alone | `docs/sequence-rules.md` + correlation cases in the evaluator | **partial** - 5 correlations, all Splunk-only |
| 9 | Severity + triage step per rule | `response/rules/<id>.md`, level histogram in tests | **passing** for presence; no triage step has been exercised |
| 10 | Volume measured under ceiling | `metrics/ceilings.json` with `measured: true` | **missing** - 0 of 37 measured |

## Current state

| Capability | State |
|---|---|
| Rule authoring | have (37 rules, 18 techniques) |
| Schema validation | have - duplicate keys, Sigma status enum, repo lifecycle, required fields, ATT&CK pin, conversion claim |
| Backend conversion | **passing** - measured per rule per backend, mismatches fail the gate |
| Deployable bundle | have - `deploy/build_bundle.py` emits real query text for the backends a rule converts to |
| Correlation rules | 5, all Sigma 2.1 (`event_count` / `temporal`); convert on Splunk only |
| Concrete fixtures (positive + negative) | have, 37 each, status `designed`, generated and verified against the rule |
| Fixture realism | field-type model (`detection-as-code/fieldtypes.py`) - registry keys, paths, URIs, command lines |
| Rule evaluator | modifiers incl. `fieldref` and `|all`, condition grammar, correlation semantics |
| Per-rule TP/FP tests | have (40 tests), including a check that the generated matrix is current |
| Blind capture | **none** - `tools/capture_kit.py` prints the procedure; nobody has run it |
| Golden clean baseline / benign corpus | **missing** - no FP proof in reality |
| Volume measurement | ceilings defined, `measured: false` for all 37 |
| Sample pinning | schema + generated reference section; no artifact |

## What changed and why

The previous version of this file said backend conversion was "**FAILING** -
pySigma backends absent". That was true but misleading: the gate could never
have passed, on any machine, because it required `pysigma-backend-kql`, a
package that does not exist on PyPI (404). The gate now requires packages that
exist, and it compares each rule against its own declared support instead of
pretending every rule converts everywhere. Six rules honestly do not: five
correlations and one `fieldref` rule, all Splunk-only by pySigma's design.

The evaluator's `frequency` handling was also fictional - `frequency` is not a
Sigma 2.1 correlation type, so those rules never loaded in pySigma while the
local evaluator happily "passed" them. They are now `event_count`, and the
evaluator implements the real semantics.

## Where the coverage is thin

`attack/matrix.md` ends with a per-tactic rule count against the pinned bundle.
Three tactics have **zero** rules: exfiltration, impact, resource development.
Command and Control has 11 of the 37 rules and Collection 3, which says what this
rule set is: a C2-artifact detector with persistence coverage, not a full
lifecycle detector. That is a property of the implant being studied, and it is
stated here rather than averaged away in a coverage percentage.

## Honest claim

The repository proves that every rule parses, converts on a real backend,
matches a generated event carrying field values a Windows/Sysmon/proxy host
could actually emit, and stays silent on a generated benign event. It can be
shipped to a Splunk/Sentinel/Elastic pipeline today.

It still cannot prove detection. No event in this repository came off a
machine: there is no blind capture, no benign corpus run, no volume number, and
no sample. Every fixture saying `designed` is saying exactly that.
