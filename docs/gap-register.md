# Gap register

What this repository is missing, ordered by how much it costs. "Closed" means
code enforces it and the gate fails without it. "Open" means no amount of
prose fixes it — it needs a lab machine, a sample, or an hours-long capture.

This file is the answer to "what is this missing". It is generated from a real
audit, not a wishlist: the same list drove the commits dated 2026-11-27.

---

## Closed in this pass (the things that made every other claim unreliable)

| # | Gap | Why it was worse than "missing" | Now |
|---|---|---|---|
| 1 | **No rule could reach a backend** | Every rule carried `status: designed`, which pySigma rejects with `SigmaStatusError` *before* conversion. Conversion was never going to work, on any machine. | `status` is the Sigma field; the repo lifecycle moved to `lifecycle:` |
| 2 | **The conversion gate could never pass** | It required `pysigma-backend-kql`, **404 on PyPI**. The gate was red for a reason nobody could fix, which trained everyone to ignore it. | Requires packages that exist; measures each rule's *declared* support and fails on over- and under-claiming: splunk 37/37, elastic 31/37, kusto 31/37 |
| 3 | **Correlations were not Sigma** | `type: frequency` and `type: sequence` are not Sigma 2.1 correlation types. pySigma refused to load the files while the local evaluator "passed" them — two harnesses, neither agreeing with reality. | `event_count` / `temporal`; evaluator implements the real semantics |
| 4 | **The ATT&CK pin validated itself** | It contained `T1533`, which is not a technique in ATT&CK at all, because the "pinned" list had been written from the rules. | Generated from the real STIX bundle by `tools/pin_attack_bundle.py`, hash-recorded, revocations surfaced |
| 5 | **The pin was 6 releases stale** | Pinned to 14.1 while 20.1 was current. v20 **revoked `T1562`** and split Defense Evasion into `Stealth` and `Defense Impairment`, so six rules cited a dead ID and a dead tactic. | Upgraded to **20.1** (706 techniques, 15 tactics). `T1562.001` → `T1685`. Tactic lists are now **derived** from the bundle and a test fails on any pair the bundle does not support |
| 6 | **Negative fixtures proved nothing** | They were produced by mutating the positive event, so they matched the rule for the right reason. | Built from scratch by inverting only what the rule reads; must miss every `filter*` section |
| 7 | **Fixtures held values no host emits** | Registry keys under `C:\Users\...\Software\`, URIs as file paths, `.bmp` as a directory name. | `detection-as-code/fieldtypes.py` field-type model; test-enforced |
| 8 | **Rules that could not fire on the telemetry they claimed** | Sysmon `23` for a delete (it is 26), `TargetImage` = a DLL on Sysmon 10, double-escaped path literals, a URI rule requiring a path *and* a query. | All fixed, with a field-contract check that rejects these shapes by name |
| 9 | **The Sysmon config enabled nothing useful** | Archive path did not exist; the ProcessAccess selection could never match; it claimed EID 24 was off while enabling it. | Rewritten, XML-parsed, hash-pinned in `baseline/manifest.json` |
| 10 | **No deployable artifact** | 37 rules and nothing a SIEM could ingest. | `deploy/build_bundle.py` emits real pySigma query text + manifest, refuses stale conversion results |
| 11 | **Silent skips** | A missing dependency made stages "pass". | 9-stage gate; an absent dependency is a failure |

---

## Open — ordered by cost

### P0. Nothing here has ever seen a real host (the whole point)

| ID | Gap | What closing it costs | Where |
|---|---|---|---|
| G-01 | **No blind capture.** Every one of the 37 fixtures is `designed`: derived from its rule, so it proves consistency, not detection. | One lab VM, one Sysmon install, one run of `tools/capture_kit.py` per rule. Hours, not weeks. | `docs/maturity.md` gate 5 |
| G-02 | **No golden clean baseline.** Nobody has shown that the required EventIDs and fields even appear on an idle host, so a rule could be silently unmatched forever. | 24 h of a clean VM with the pinned config. This is the cheapest P0 and it unblocks G-01. | gate 4 |
| G-03 | **No benign corpus run.** Precision is unknown. A rule that fires on every Chrome update is worse than no rule. | One business day per software class in `fixtures/benign/`. | gate 7 |
| G-04 | **No volume measurement.** Every `metrics/ceilings.json` entry says `measured: false`. The ceilings are editorial budgets. | Needs G-02 + G-03. | gate 10 |

### P1. Telemetry the implant needs and Windows does not log

These cannot be fixed with a query. They need a sensor decision.

| ID | Behavior | Why a rule cannot cover it | Cheapest option |
|---|---|---|---|
| G-05 | AMSI / ETW patching | Sysmon 10 targets *processes*; you cannot select a loaded module. ETW patching also blinds the collector. | EDR memory-write telemetry, or Kernel-ETW `Microsoft-Windows-Threat-Intelligence` (requires an ELAM-signed consumer) |
| G-06 | Keylogging (`GetAsyncKeyState` polling) | No native log; only the `kl.enc` staging file is visible. | EDR API telemetry, or a keyboard-class filter driver |
| G-07 | Clipboard capture | Sysmon 24 exists but is a firehose and is off in this config. | Sysmon 24 with a scoped window, or EDR |
| G-08 | File **reads** (DPAPI, `Local State`, SQLite copy) | Sysmon logs create/write, not read. SACL `4663` on the specific paths. | SACL + `auditpol`, already documented for the CPU key |
| G-09 | Single-instance mutex | Handle telemetry is EDR-only. | EDR, or skip — very low signal |
| G-10 | USB insertion, to pair with `autorun.inf` writes | Sysmon has no device-arrival event here. | Windows `DriverFrameworks-UserMode` 2003/2102, or EDR device control |
| G-11 | Custom HTTP header retention | The C2 rules read `cs-header-X-Id`; most proxies drop unknown headers. **Unproven, not unknown-but-fine.** | Test one request through the actual proxy before trusting 4 of 37 rules |

### P2. Analytic depth

| ID | Gap | Detail |
|---|---|---|
| G-12 | Beacon jitter is not detected | `beacon_interval_shift.yml` is a filter, not a detector. Needs inter-arrival mean/variance per host-destination pair. A fixed `count >= N in T` misses a 45 s beacon with 0.35 jitter. |
| G-13 | The stage0 → stage1 join is not implemented | A process-tree join is not expressible in Sigma; it has to be built in the SIEM. Documented, not built. |
| G-14 | Five correlations are Splunk-only | pySigma converts correlations only for Splunk. Elastic and Kusto users get the members and must build the join. |
| G-15 | No `1 of` cross-source campaign rule | Sequence *across* techniques (triage → tamper → persist) is not modelled. |
| G-16 | YARA rules have no corpus | `yara/ghost_implant_structural.yar` compiles, but nothing proves it matches a build or stays quiet on real software. |

### P3. Engineering hygiene

| ID | Gap | Detail |
|---|---|---|
| G-17 | No sample, so `sample_ref: PIN-0000` everywhere | Absence is by design (defensive repo). The pin schema is ready; nothing to pin. |
| G-21 | Captures are not reproducible | `tools/evtx_to_fixture.py` records the input hash, the config hash, and the evaluator's verdict, so a captured fixture is tied to the box it came from. Still no VM image hash. |
| G-18 | `response/rules/*.md` triage steps are untested | Generated from metadata; no alert has been worked in the lab. |
| G-19 | `attack/cache/` is 55 MB and gitignored | `--verify` prints MISSING until re-fetched. Correct, but it means CI cannot prove the pin hash without downloading. |
| G-20 | No pre-commit hook | The gate exists but nothing runs it before a commit. |

---

## How to close P0 without writing a rule

```bash
# 1. clean VM, Internal network, snapshot
# 2. install Sysmon with the pinned config, then confirm what Sysmon actually
#    loaded matches the repo copy (it silently falls back to a default config if
#    the schema version is too new, which drops every selection)
sysmon64.exe -accepteula -i telemetry/sysmon-config.xml
sysmon64.exe -c > installed.xml     # diff by eye against telemetry/sysmon-config.xml

# 3. idle 24 h on the clean box, then take the baseline - this closes G-02
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:true > baseline.xml
python3 tools/verify_baseline.py --input baseline.xml --json baseline/report.json
#    Reports per rule: EventIDs present, EventIDs missing, fields the capture
#    does not carry. A rule whose event never appears is unmatched, not quiet.

# 4. for each rule, print its capture procedure and run it - this closes G-01
python3 tools/capture_kit.py --rule <id-prefix>
```

Step 3 is one command and one day of waiting for a machine, and it is the single
highest-value thing anyone can do to this repository. Everything else here is
already mechanically verified.
