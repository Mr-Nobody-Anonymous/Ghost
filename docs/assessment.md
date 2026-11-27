# What this repository is, measured

An assessment of the project as a whole, written after auditing it rather than
alongside building it. Every number here was produced by a command in the repo;
nothing is estimated.

---

## One sentence

A **defensive detection lab for one specific implant family**, whose rules are
mechanically validated end to end but have **never seen a real host** — the
engineering is provable, the detection is not.

## What exists

| Component | Count | What it is |
|---|---|---|
| Sigma rules | 38 | 33 single-event + 5 correlations, 18 ATT&CK techniques |
| Fixtures | 77 | 38 positive + 38 negative + 1 schema example, generated and verified |
| Suricata rules | 3 | custom-header C2 signatures |
| YARA rules | 1 | structural implant fingerprint, 12 strings, 6 conditions |
| Python tooling | ~4,500 lines | validator, evaluator, generator, capture kit, linters |
| Docs | 77 files / ~2,700 lines | runbook, maturity, gaps, deployment, triage per rule |
| Gate stages | 10 | each fails on its own, none can skip |
| Tests | 47 | structural, behavioural, and mutation-verified |

## What is mechanically proven

These hold every time `ci/gate.sh` runs. This is the part you can rely on.

- **Every rule parses as Sigma 2.1** and uses only real correlation types.
- **Every field a rule reads is documented**, and selections that cannot match
  (Sysmon 10 targeting a DLL, EventID 23 as a delete) are rejected by name.
- **Every rule converts to the backend it claims** — 38/38 Splunk, 32/38
  Elastic and Kusto. Over- and under-claiming both fail.
- **Every rule matches its own generated event and rejects its negative** —
  38/38 pairs. The negative is built from scratch, not mutated out of the positive.
- **Fixtures contain values a host could emit** — real registry hives, absolute
  paths, URIs, command lines — and never a constraint literal.
- **Tactic lists are derived from the ATT&CK 20.1 bundle**, not hand-written;
  a rule cannot claim a tactic its own technique does not reach.
- **Filters are reachable.** A filter that excludes nothing is a test failure.
- **Suppression travels with the bundle**: dedup key, window and a ready
  `alert.suppress` string per rule.
- **YARA match logic is asserted both ways** — five shapes must hit, three
  partial indicators must not.
- **Nothing drifts**: fixtures, coverage matrix and conversion results are all
  freshness-checked, and the gate is idempotent.

## What is *not* proven — and cannot be, from inside this repo

| Missing | Consequence |
|---|---|
| **No blind capture** (all 38 rule fixtures are `designed`) | The rules are internally consistent. That is not detection. A fixture derived from a rule cannot fail for the reason real telemetry fails. |
| **No clean baseline** | Nobody has shown the required EventIDs and fields appear on an idle host. A rule may be silently unmatched forever. |
| **No benign corpus run** | Precision is unknown. 18 of 38 rules have no filter section at all. |
| **No volume measurement** | All 38 ceilings say `measured: false`; they are budgets, not observations. |
| **No deployment performed** | `docs/deployment.md` is a procedure, not a result. |
| **No sample** | `sample_ref: PIN-0000` everywhere, by design for a defensive repo. |

## Rule-quality profile (measured, not asserted)

| Property | Value | Reading |
|---|---|---|
| Median distinct fields per rule | 3 | thin; most rules key on one object |
| Rules with a filter/allowlist | 20 / 38 (53%) | the other 18 rely entirely on the selection being rare |
| Rules selecting ≤2 fields | 18 / 38 | high false-positive risk, all rated `low`/`medium` |
| Correlations | 5 | ordering is detected; all Splunk-only |
| Level distribution | 10 high / 20 medium / 8 low | weighted toward medium, appropriate for unmeasured precision |
| ATT&CK tactics covered | 12 of 15 | zero: exfiltration, impact, resource-development |
| Rules in Command and Control | 11 | this is a C2-artifact detector, not a general EDR |

## Where the risk actually sits

1. **Field-name mapping (§5 of the deployment doc).** Sigma says `EventID`,
   Splunk says `EventCode`. Miss the alias and 32 rules evaluate against a null
   and match nothing — silently, with no error anywhere.
2. **Sysmon falling back to a default config.** The pinned config targets schema
   4.90; an older Sysmon rejects it and starts with a default that matches none
   of these rules. The failure looks like "no alerts", which looks like success.
3. **Proxy header retention.** Four C2 rules read `cs-header-X-Id`. Most proxies
   drop unknown headers. If yours does, those rules are dead and quiet.
4. **Thirty-eight queries without suppression.** The manifest now carries it, but
   nothing applies it for you; an unsuppressed deploy is a flood on day one.
5. **Precision.** 18 rules have no filter. The first week of a real deployment
   will produce false positives that no test in this repository can predict.

## How it compares to what it claims to be

| Claim | Verdict |
|---|---|
| "Sigma rules for this implant" | **true**, and unusually well-checked |
| "Coverage of the implant's behaviours" | **partial** — 18 techniques, 12 tactics, 7 behaviours with no telemetry at all |
| "Validated detections" | **false if read as detection**; true only as rule consistency |
| "Deployable" | **true for Splunk**, partial for Elastic/Kusto, with no deployment ever run |
| "Lab" | **true** — the lab procedure exists, but nobody has walked it |

## The honest summary

This is a **high-quality specification of detections**, not a proven detection
capability. Its value is that every claim it makes about itself is checkable:
38 rules convert because the gate converts them, tactics match because they are
derived from the bundle, fixtures are realistic because a field-type model
renders them, and a filter that cannot fire fails the build.

What it cannot tell you is whether any of it fires on a real attack. That takes
one VM, one Sysmon install and a day of waiting — `docs/gap-register.md` G-01
and G-02. Until then, the correct description is *"detections specified and
mechanically verified; efficacy unmeasured."*
