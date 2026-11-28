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
| 2 | **The conversion gate could never pass** | It required `pysigma-backend-kql`, **404 on PyPI**. The gate was red for a reason nobody could fix, which trained everyone to ignore it. | Requires packages that exist; measures each rule's *declared* support and fails on over- and under-claiming: splunk 38/38, elastic 32/38, kusto 32/38 |
| 3 | **Correlations were not Sigma** | `type: frequency` and `type: sequence` are not Sigma 2.1 correlation types. pySigma refused to load the files while the local evaluator "passed" them — two harnesses, neither agreeing with reality. | `event_count` / `temporal`; evaluator implements the real semantics |
| 4 | **The ATT&CK pin validated itself** | It contained `T1533`, which is not a technique in ATT&CK at all, because the "pinned" list had been written from the rules. | Generated from the real STIX bundle by `tools/pin_attack_bundle.py`, hash-recorded, revocations surfaced |
| 5 | **The pin was 6 releases stale** | Pinned to 14.1 while 20.1 was current. v20 **revoked `T1562`** and split Defense Evasion into `Stealth` and `Defense Impairment`, so six rules cited a dead ID and a dead tactic. | Upgraded to **20.1** (706 techniques, 15 tactics). `T1562.001` → `T1685`. Tactic lists are now **derived** from the bundle and a test fails on any pair the bundle does not support |
| 6 | **Negative fixtures proved nothing** | They were produced by mutating the positive event, so they matched the rule for the right reason. | Built from scratch by inverting only what the rule reads; must miss every `filter*` section |
| 7 | **Fixtures held values no host emits** | Registry keys under `C:\Users\...\Software\`, URIs as file paths, `.bmp` as a directory name. | `detection-as-code/fieldtypes.py` field-type model; test-enforced |
| 8 | **Rules that could not fire on the telemetry they claimed** | Sysmon `23` for a delete (it is 26), `TargetImage` = a DLL on Sysmon 10, double-escaped path literals, a URI rule requiring a path *and* a query. | All fixed, with a field-contract check that rejects these shapes by name |
| 9 | **The Sysmon config enabled nothing useful** | Archive path did not exist; the ProcessAccess selection could never match; it claimed EID 24 was off while enabling it. | Rewritten, XML-parsed, hash-pinned in `baseline/manifest.json` |
| 10 | **No deployable artifact** | 38 rules and nothing a SIEM could ingest. | `deploy/build_bundle.py` emits real pySigma query text + manifest, refuses stale conversion results |
| 11 | **Silent skips** | A missing dependency made stages "pass". | 10-stage gate; an absent dependency is a failure |
| 12 | **The staleness check could not fail** | `deploy/build_bundle.py` compared a wall clock, then a stamp derived only from the stored results. Both agreed with themselves. | Stamp is sha256 over the rule files *and* the outcomes; a test edits a rule and asserts the build exits 1 |
| 13 | **Three checks warned instead of failing** | The query lint printed `warn` for a field that does not exist and exited 0; Suricata rules had no check at all; YARA was only compiled, never matched. | Unknown hunt fields fail; `pipeline/lint_suricata.py` parses signatures, SIDs and their ATT&CK metadata; YARA match logic is asserted both ways |
| 14 | **37 rules declared suppression that nothing shipped** | `dedup_key`, `dedup_window` and `min_eval_interval` existed on every rule and were consumed by nothing, so a deploy was 38 queries with no dedup policy. | Suppression travels in the bundle manifest with a Splunk `alert.suppress` string; the arithmetic is validated |
| 15 | **`|re` selections produced unmatchable fixtures** | The generator ignored the modifier and rendered a `C:\` path for a `[D-Z]:` rule. | Pattern expansion *verified with `re.search`*, raising instead of emitting a value the rule cannot match |
| 16 | **`Source: true` in a DNS fixture** | `|exists` returned the constraint literal, not telemetry. | Field-appropriate present values; a test rejects boolean leakage |
| 17 | **An IOC with no detector** | `analysis/iocs.md` named `svc_update.exe`; no rule covered it. | `removable_media_spreader_write.yml` |
| 18 | **Dependencies were unpinned** | CI installed whatever pip resolved while the gate compared generated query text against a fixed result. | `requirements.txt` + a gate stage that fails on drift |
| 19 | **The emulator was never checked against its rules** | Running it proved nothing about whether the beacon rules match its output. | `emulation/verify_emulation.py`, which does fail when they diverge |
| 20 | **The defensive-only claim had no test** | SCOPE.md's central promise was prose; one commit could have made it false. | `tests/test_scope.py` - capability imports, calls, loopback-only, no binaries |
| 21 | **No ATT&CK Navigator layer** | Coverage existed only as a Markdown table. | `tools/export_navigator.py`; scores evidence, not rule count, so it renders at 1 |
| 22 | **No stated or tested Python floor** | `Path.is_relative_to` sets 3.9; nothing said so and CI tested only 3.11. | Floor declared and enforced in `ci/check_env.py`; CI matrixes 3.9 and 3.11; a test parses every file with 3.9 grammar |
| 23 | **The gate rewrote the tree** | Wall clock in `conversion.json` and in the matrix header made `git status` dirty after every run, which hides real changes. | Two consecutive gate runs leave the tree clean |
| 24 | **No Python correctness lint** | 4,500 lines; a lint run found two late-binding closure bugs (B023) in the test helper and a `--verbose` flag that did nothing. | `pyproject.toml` selects correctness rules only (F, B, E9, UP, PERF); gate stage 2 |
| 25 | **No alert-quality feedback loop** | `docs/tuning-log.md` was an empty table with no machine link from an alert to the rule, its ceiling, or its lifecycle. | `tuning/observations.csv` + `tools/tuning_log.py`: `--render` regenerates the doc, `--apply-ceilings` promotes a measured events/day, and `tuned` without a `keep` observation fails the gate |
| 26 | **Five correlations were dead ends on Elastic and Kusto** | `ci/convert_check.py` recorded `unsupported` and the docs said "build the join in the SIEM". A user on Elastic got five `unsupported` lines and a Markdown spec. | `deploy/build_joins.py` emits EQL `sequence`, ES|QL thresholds and Kusto joins from the rules; a gate stage keeps them current |
| 27 | **The stage0 -> stage1 join was documented, not built** | `docs/sequence-rules.md` entry 3 said "not implemented". Two rules deployed and nothing connected them. | `analytics/stage_join.py`: shared-parent join on `ParentProcessGuid`, signature/window/skew checked, one chain and four near-misses in a fixture |
| 28 | **No cross-source campaign rule** | Every correlation proved one ordering inside one source; nothing said "recon then tamper then persist then egress on one host". | `sigma/campaign_implant_sequence.yml` + `analytics/campaign.py`: 3-of-4 chains, with a 2-of-4 host in the fixture that must not fire |
| 29 | **No pre-commit hook** | The gate existed and nothing ran it before a commit; 19 commits landed with no local check. | `.githooks/pre-commit` (ruff + tests + fixture freshness) and `commit-msg`; both proven to reject bad input by `tests/test_hooks.py` |
| 30 | **No release or change discipline** | `CHANGELOG.md` was hand-maintained and stale twice; no tags, no derived version, no artifact identity. | `tools/release.py`: content digest over 196 behaviour files, derived `vYYYY.MM.DD.N`, and `--check-changelog` fails on any commit the changelog does not mention. Found 19 unrecorded commits; all now written up |
| 31 | **The YARA rule had no corpus** | It compiled, which is a syntax check; nothing proved it matched a build or stayed quiet on software. | `yara/corpus/` built by `tools/build_yara_corpus.py`: 1 implant stand-in, 6 benign files each carrying a real indicator, 5 partials. Widening one rule branch to `any of` is caught as a Defender-impersonating false positive |
| 32 | **Overlap with upstream SigmaHQ was unknown** | "Whether any rule duplicates an existing SigmaHQ rule is unknown" - and a re-invented rule inflates the coverage claim. | `tools/sigmahq_overlap.py`: 3,164-rule cached snapshot, family + product + technique + directed-coverage join. Result: **no duplicate, no divergence**; two ancestor-path artefacts recorded as artefacts. Three bugs in the check's own history are regression tests |
| 33 | **No saved-search packaging** | Importing 38 searches with schedules and suppression was manual. | `deploy/build_savedsearches.py` emits `dist/savedsearches.conf`: 33 searches, all disabled, 5m schedule floor, suppression from each rule's own `dedup_key`, unique id-suffix tags |

---

## Open — ordered by cost

### P0. Nothing here has ever seen a real host (the whole point)

| ID | Gap | What closing it costs | Where |
|---|---|---|---|
| G-01 | **No blind capture.** Every one of the 38 fixtures is `designed`: derived from its rule, so it proves consistency, not detection. | One lab VM, one Sysmon install, one run of `tools/capture_kit.py` per rule. Hours, not weeks. | `docs/maturity.md` gate 5 |
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
| G-11 | Custom HTTP header retention | The C2 rules read `cs-header-X-Id`; most proxies drop unknown headers. **Unproven, not unknown-but-fine.** | Test one request through the actual proxy before trusting 4 of 38 rules |

### P1b. Detectors that exist but are weaker than their description

| ID | Rule | Claim vs reality |
|---|---|---|
| G-23 | `screenshot_bmp_artifact.yml` | Any `.bmp` under Temp. Cannot inspect contents or confirm screen dimensions from Sysmon 11 - corrected in the description, still a weak signal. |
| G-24 | `removable_media_spreader_write.yml` | Drive-letter test cannot distinguish a USB stick from a second internal disk; Sigma cannot express `DRIVE_REMOVABLE`. Needs a SIEM-side drive-type join. |
| G-25 | `autorun_inf_writes.yml` | Windows 10 1703+ ignores AutoRun for USB media, so half the technique is historical. Kept as a spread-artifact signal, not an execution one. |
| G-26 | `ua_anomaly.yml` | A user-agent match is the weakest possible C2 signal; it is a hunt lead, not a detection, and is rated accordingly. |

### P2. Analytic depth

| ID | Gap | Detail |
|---|---|---|
| G-12 | Beacon jitter is not detected | `beacon_interval_shift.yml` is a filter, not a detector. Needs inter-arrival mean/variance per host-destination pair. A fixed `count >= N in T` misses a 45 s beacon with 0.35 jitter. **Closed - `analytics/beacon_jitter.py` (median + CV per pair, rule's domain filter applied, selftest in gate) + 10 tests, including one that asserts a regular backup *is* statistically a beacon so the limitation cannot be forgotten.** |
| G-13 | The stage0 → stage1 join is not implemented | A process-tree join is not expressible in Sigma; it has to be built in the SIEM. Documented, not built. | **Closed - `analytics/stage_join.py` + `tests/test_stage_join.py` (11 tests; four distinct near-misses each asserted separately).** |
| G-14 | Five correlations are Splunk-only | pySigma converts correlations only for Splunk. Elastic and Kusto users get the members and must build the join. | **Closed - `deploy/build_joins.py` (10 files in `deploy/joins/`) + `tests/test_joins.py` (13 tests, including a regression test for an OR/AND precedence bug the generator had).** |
| G-15 | No `1 of` cross-source campaign rule | Sequence *across* techniques (triage → tamper → persist) is not modelled. | **Closed - `sigma/campaign_implant_sequence.yml` (3-of-4) + `analytics/campaign.py` + `tests/test_campaign.py` (10 tests; lowering the threshold to 2 is asserted to change the verdict).** |
| G-16 | YARA rules have no corpus | `yara/ghost_implant_structural.yar` compiles, but nothing proves it matches a build or stays quiet on real software. | **Closed - `yara/corpus/` (12 files) + `tests/test_yara_corpus.py` (9 tests) + a gate stage; proven to catch a widened rule branch that would fire on `MpSvc.dll`.** |

### P2b. Operational path

| ID | Gap | Detail |
|---|---|---|
| G-27 | **No deployment procedure** | The repo could emit 38 queries and a manifest but said nothing about ingesting telemetry, mapping `EventCode`->`EventID`, or applying suppression. Now `docs/deployment.md` — written, never executed. |
| G-28 | **Field-name mapping is vendor-specific and undocumented per platform** | Sigma `EventID` vs Splunk `EventCode` vs ECS `event.code` vs Kusto `EventID`. A missing alias makes a rule evaluate against a null, silently. | `telemetry/field-map.json` names all 36 fields a rule reads on three platforms; `pipeline/build_field_map.py` renders `props.conf`, an Elastic ingest pipeline and Kusto views, and `--check` fails the gate when they drift. Non-rename mappings are marked (`CertificateSelfSigned` is computed; Splunk's proxy fields alias backwards). **Still not executed against a live Splunk/Elastic/Sentinel** — the names are documented ones, not read back from a deployed template. |
| G-29 | **No saved-search packaging** | The bundle is a query per rule plus JSON. Importing 38 saved searches with schedules and suppression is manual; nothing generates a `savedsearches.conf` or an API payload. | **Closed - `deploy/build_savedsearches.py` + `tests/test_savedsearches.py` (8 tests, proven to fail on enabled/fast-cron/bad-key/duplicate-name).** |
| G-30 | **No alert-quality feedback loop** | `docs/tuning-log.md` is empty and there is no link from an alert back to the rule's ceiling or triage step. | **Closed - `tools/tuning_log.py` + `tests/test_tuning_log.py` (8 tests; the tuned-without-evidence check was proven to fail when disabled).** |

### P2c. Reproducibility and scope

| ID | Gap | Detail |
|---|---|---|
| G-31 | **No dependency pinning** | CI installed unpinned pySigma and backends while the gate compares generated query text. Closed: `requirements.txt` + gate stage 0 fails on any drift. |
| G-32 | **The emulator was never checked against its rules** | `local_listener.py` + `inert_beacon.py` were documented as producing "comparable telemetry"; nothing tested it. Closed: `emulation/verify_emulation.py`, and it now does fail when the two diverge. |
| G-33 | **Fake Zeek** | Two blocks fenced as Zeek called functions Zeek does not have. Now labelled pseudocode with real log fields and a working `zeek-cut` command. |
| G-34 | **The defensive-only claim was prose** | SCOPE.md's central promise had no test. Closed: `tests/test_scope.py` fails on capability imports/calls, a non-loopback emulator, or a committed binary. |

| G-35 | **No Python linter or formatter** | 4,500 lines with no `ruff`/`black` enforcement; style drift is invisible. | **Closed - ruff correctness rules in `pyproject.toml`, pinned in `requirements.txt`, gate stage 2; 31 initial findings, 2 real closure bugs fixed.** |
| G-36 | **No release or change discipline** | `CHANGELOG.md` is hand-maintained and was stale twice. Nothing derives a version or tags a release. | **Closed - `tools/release.py` + `tests/test_release.py` (8 tests, including one that deletes a changelog line and asserts the check fails); gate stage 12; `dist/release.json` ships with the bundle.** |
| G-37 | **No upstream Sigma rule overlap check** | This repo defines 38 rules; whether any duplicates an existing SigmaHQ rule (and diverges from it) is unknown. Citation and fork management are unhandled. | **Closed - `tools/sigmahq_overlap.py` + `attack/sigmahq-overlap.json` + `tests/test_sigmahq_overlap.py` (25 tests: family join, product guard, coverage direction, and each of the three historical bugs); gate stage 12.** |


### P3. Engineering hygiene

| ID | Gap | Detail |
|---|---|---|
| G-17 | No sample, so `sample_ref: PIN-0000` everywhere | Absence is by design (defensive repo). The pin schema is ready; nothing to pin. |
| G-22 | No baseline capture has been taken | `tools/verify_baseline.py` now exists and says exactly what a capture is missing; the capture itself is still G-02. |
| G-21 | Captures are not reproducible | `tools/evtx_to_fixture.py` records the input hash, the config hash and the evaluator's verdict, so a captured fixture is tied to the box it came from - but not to an image anyone can rebuild. | `telemetry/lab-image.json` declares the intended host (Windows build, Sysmon version, required logs, audit policy, UTC clock) and every capture records which values it could report against it; a capture from a different build, or from no stated build, refuses to be filed as a fixture. **Still open for the image itself:** no VM was built from this manifest. This makes a capture attestable, not reproducible - that needs a lab. |
| G-18 | `response/rules/*.md` triage steps are untested | Generated from metadata; no alert had been worked in the lab. The steps also pointed at `rule:<id>:host:user`, an identifier that existed nowhere - so they were not just untested, they were unfollowable. | `tools/generate_playbooks.py` derives all five sections from the rule; `response/check_playbooks.py` verifies that every triage field is one the rule reads, every containment step names a real action, preservation never says delete, and a correlation playbook names its members. Gate stage 14. **No human has still worked an alert** - a playbook read by a checker is followable, not followed. That needs an incident, not a script. |
| G-19 | `attack/cache/` is 55 MB and gitignored | `--verify` prints MISSING until re-fetched, so CI could not prove the pin hash without downloading. | `tools/verify_pins.py` separates *verified from bytes* from *derived-only*: the derived data (tactic list, technique list, snapshot commit) is committed and its digest still proves internal consistency. It now catches a review measured against one upstream tree and cited after the cache moved. `--strict` fails on unhashed artifacts for anyone holding the caches. **The 55 MB still is not in Git** - that is the point, not a remaining defect. |
| G-20 | No pre-commit hook | The gate exists but nothing runs it before a commit. | **Closed - `.githooks/` + `tests/test_hooks.py` (6 tests; the hook is executed with crafted input, not inspected).** |

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
