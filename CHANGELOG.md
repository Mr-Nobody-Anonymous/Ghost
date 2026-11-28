# Changelog

## 2026-11-27

- Initial folder created: README, ATT&CK coverage map, 6 Sigma rules, 2 YARA
  rules, 3 inert emulation scripts, triage/IOC/report templates.
- Fixed a typo in `sigma/beacon_custom_headers.yml` (`cert.pem` field reference
  left over from an earlier draft) by replacing it with proxy-style field names.
- Added 4 Sigma rules: browser credential/wallet file access, `autorun.inf`
  writes, `net view`/SecurityCenter2 discovery, and a beaconing frequency
  correlation rule.
- Added `yara/pyinstaller_overlay.yar`.
- Added `detection-as-code/validate_rules.py` and its README.
- Added `hunt-queries.md` and `lab-setup.md`.

## 2026-11-27 (second expansion)

- Added `SCOPE.md` and `samples/PINS.md` (pin schema with placeholder hashes;
  no binary stored).
- Added `telemetry/`: `data-sources.md`, `sysmon-config.xml`, `auditpol.md`,
  `etw-providers.md`.
- Added `sigma/_schema.md` and `sigma/network/suricata_xid_xseq.rules`; added
  `network/ja3-x509.md`.
- Added `yara/packers/packers.yar` (UPX, Nuitka, Go, .NET single-file,
  high-entropy heuristic) and `yara/stages/stage_fingerprints.yar`.
- Added `fixtures/` with a template plus five expected-event fixtures for the
  documented gaps, and a benign false-positive corpus specification.
- Added `tools/generate_matrix.py` to generate `attack/matrix.md` from rule tags,
  plus `tests/test_rules.py`, `ci/gate.sh`, and `docs/` (runbook, tuning log,
  maturity model).

## 2026-11-27 (third expansion)

- Added 13 Sigma rules covering persistence (4), patch sequence, CPU-info read,
  stage-0 dropper, python parent/child shape, screenshot BMP, SQLite temp copy,
  keylog staging file, ipify egress, and WMI recon command.
- Added `ci/pending_ratchet.py` and wired it into `ci/gate.sh` as a hard gate.
- Added `inventory.md` (behavior-to-detection inventory), `os-matrix.md`,
  `docs/sequence-rules.md`, `docs/test-contract.md`.
- Added `pipeline/`, `deploy/`, `response/`, `metrics/`, `baseline/` READMEs and a
  benign packed YARA corpus spec.
- Added malicious fixtures for the new persistence and sequence rules, plus a
  negative-fixture template.

## 2026-11-27 (fourth expansion - defect fixes)

- Replaced the YAML loader with a duplicate-key-detecting `StrictLoader`; it
  immediately found a real duplicate `cs-uri-query|contains` key in
  `beacon_custom_headers.yml` (fixed).
- Made `level`, `falsepositives`, `references`, `dedup_key`, `author`, ISO `date`
  and lower-case UUIDv4 schema-required.
- Split tactics into a `tactics:` field; `tags:` now holds techniques only.
- Added `attack/attack-bundle-pin.json` (ATT&CK 14.1, offline technique list) and
  pinned validation of every technique ID.
- Added eight rules for previously uncovered behaviors: mutex, DGA host-side
  query burst, self-delete, self-update rewrite, `_MEI` extraction, host-side
  self-signed TLS, generic-UA anomaly, and beacon interval shift. Sysmon config
  now enables events 22 and 23.
- Added `tools/generate_fixtures.py` producing 31 positive stubs and 31 negative
  stubs; `tests/test_rules.py` now has 11 tests including per-rule field,
  negative, response, metrics, and baseline-drift checks.
- Added `ci/convert_check.py` as a hard gate; it currently FAILS because no
  pySigma backend is installed. This is intentional - conversion is unproven.
- Added `response/rules/`, `metrics/ceilings.json`, `baseline/manifest.json`,
  and updated `_schema.md` with ID namespace and deprecation policy.

## 2026-11-27 (fifth expansion - evaluator and config correctness)

- Added `detection-as-code/evaluate.py`: collection-wide loading, real Sigma
  modifiers and condition grammar, sequence/frequency correlation, value
  assertions, and per-rule failure output. All 31 rules match their positive
  fixtures and stay silent on negative ones.
- Rewrote fixture generation with concrete field values and `must_not_match`
  negative events; collapsed `fixtures/malicious/` into `fixtures/per_rule/`.
- Fixed five Sysmon config faults: System32 ProcessCreate exclusion, DNS
  no-op include, empty archive directory, invalid AMSI `TargetImage` selection,
  and unfiltered high-volume FileCreate; added `HashAlgorithms` and Sysmon 13+
  pin. CPU-key access match changed from substring `0x1` to anchored regex.
- Fixed correlation logsource mismatch (`services: [security, sysmon, edr]`).
- Added 24 tests including evaluator semantics, out-of-window sequence, mutation
  case, gate-component tests, level histogram, sample_ref resolution, and status
  state machine. PyYAML absence is now a hard fail.
- Rewrote `convert_check.py` to load the whole collection and require all
  backends; wired the full gate into the CI workflow and fixed the tarball manifest.
- Added `NOTICE`, Sigma spec version, `sample_ref`, dedup windows, min eval
  intervals, OS/Sysmon minimums, generated PINS references, an evtx->fixture
  parser, an emulation fidelity table, and removed the analysis/response overlap.

## Scope note

The implant implementation supplied with the request remains excluded. There is
no `implant/` directory and no compiled sample in `samples/`. Every file here is
detection content, inert telemetry generation, or analysis tooling. No EDR
patching, credential access, persistence, or external C2 code is present.

## 2026-11-27 (sixth expansion - defect audit)

This pass was a correctness audit, not a feature pass. The gate was green for
stages that could not fail and red for a reason that could never be fixed.

### Conversion was impossible, and the reason given was wrong

- `ci/convert_check.py` required `pysigma-backend-kql`, which does not exist on
  PyPI (404). No machine could ever pass it. Dependencies now resolve, and the
  gate measures every rule's declared `conversion:` support against real
  pySigma output, failing on over- and under-claims. Result: splunk 38/38,
  elastic 31/37, kusto 31/37.
- Correlation rules declared `type: frequency` and `type: sequence`, neither of
  which is a Sigma 2.1 correlation type; pySigma refused to load them while the
  local evaluator "passed" them. Rewritten as `event_count` / `temporal`, and
  the evaluator now implements the real semantics (group-by, timespan, order,
  one match per member).
- Five rules used the deprecated `selection | count() by X > N` pipe syntax.

### Schema fault: `status` was not a Sigma field

- Every rule carried `status: designed` or `deployed`, which pySigma rejects
  with `SigmaStatusError` before conversion. `status` now holds a Sigma value and
  the repo's own lifecycle moved to `lifecycle:`. This single fault blocked all
  38 rules from ever reaching a backend.

### Rules that could not fire on the telemetry they claimed

- `self_delete.yml` selected Sysmon EventID 23 (FileDelete archive); FileDelete
  is 26. Rewritten with `fieldref` so the image and the deleted file are compared.
- Path literals were double-escaped (two real backslashes)
  (`'\\\\autorun.inf'`) in `autorun_inf_writes.yml`, `credential_file_access.yml`
  and `net_view_recon.yml` - a value that cannot occur in a Windows path.
- `beacon_custom_headers.yml` required `cs-uri-stem|endswith: /poll` AND a query
  string containing both `id=` and `seq=` under a conjunctive OR, so the
  `/poll?id=&seq=` shape it was written for never matched.
- `credential_file_access.yml` read `TargetFilename` from Sysmon 10, which is
  ProcessAccess and has no such field.
- `python_parent_child_shape.yml` matched `\pythonw.exe` and `\_MEI` as
  substrings of a full `ParentImage` path.
- `dropper_unsigned_temp_exec.yml` and `self_update_rewrite.yml` could not
  distinguish "unsigned" or match a real install path; both now use the
  `Signature` / `IntegrityLevel` fields and per-user install directories.
- Correlations grouped on join keys their members never selected (`ProcessId`
  across Security and Sysmon, `User` on a bare `EventID: 19` selection). Join
  keys are now `Computer` / `ProcessGuid` / `Source`, and a test enforces that
  every member can produce them.

### Rules, telemetry, config

- WMI triple correlation split into three standalone member rules.
- Added `security_component_tamper.yml` and `dns_random_label_query.yml` as
  correlation members, plus `nxdomain_long_label.yml` as a rule rather than a
  shadow of its own correlation ID.
- Sysmon config: removed the impossible `TargetImage: amsi.dll` ProcessAccess
  selection, fixed the non-existent `C:\SysmonArchive\` archive path, stopped
  claiming event 24 was enabled while enabling it, added the file/registry paths
  the rules actually read, and corrected event 23 vs 26.
- ATT&CK pin contained `T1533`, which is not a technique in ATT&CK 14.1 at all -
  the "pinned" list was hand-written from the rules, so it validated itself.
  Regenerated from the real STIX bundle (`tools/pin_attack_bundle.py`), hash
  recorded, revoked/deprecated techniques excluded, `T1533` replaced with `T1005`.

### Harness that could not fail

- Negative fixtures were built by mutating the positive event, so they matched
  the rule "for the right reason" and proved the opposite of a true negative.
- Fixtures contained values no host emits (`C:\Users\lab\Software\...` for
  registry keys, `id=\seq=` for query strings). Added
  `detection-as-code/fieldtypes.py`.
- `tools/generate_fixtures.py` emitted a non-existent fixture path convention;
  `tools/generate_matrix.py` read the deleted `fixtures/malicious/`.
- A test asserted every field of every OR-branch appears in one event, which
  forced fixture values to be concatenations of every alternative.
- Correlation fixtures now embed their member rules so they can be evaluated
  alone.

### New capability (only where it closes a named gap)

- `tools/capture_kit.py` - per-rule procedure to turn a `designed` fixture into
  a captured one.
- `pipeline/field_contract.py` - fails the gate when a rule reads an
  undocumented field, or a selection that cannot match (`TargetImage` = DLL on
  Sysmon 10, EventID 23 as a delete).
- `pipeline/lint_queries.py` - hunt queries are now checked.
- `deploy/build_bundle.py` - emits real query text for rules that convert, and
  refuses to build if conversion results are stale.
- 9-stage gate; workflow installs packages that exist.

### ATT&CK pin upgraded 14.1 -> 20.1

- v20 **revoked `T1562`** and split Defense Evasion into `Stealth` and
  `Defense Impairment`. Six rules cited `T1562.001`, a dead ID; every one of
  their `tactics:` lists named a tactic that no longer exists.
- Migrated `T1562.001` -> `T1685` and made `tactics:` **derived** from the
  bundle rather than editorial: the pin now carries technique -> kill-chain
  phases, `validate_rules.py` rejects an unreachable tactic, and a test asserts
  the exact set.
- The pin tool now reports techniques in use that upstream revoked instead of
  silently dropping them, which is how `T1562.001` surfaced at all.

### Capture path corrected

`tools/evtx_to_fixture.py` wrote `status: captured` without ever checking that
the rule fired, overwrote the generated fixture, and replaced `Computer` -
the correlation join key - with a placeholder. Rewritten: it evaluates the
capture first and refuses to write a "captured" fixture on a non-match
(`--allow-no-match` records the honest status `unmatched`), writes to
`fixtures/captured/`, masks identity fields only, and records the input and
config hashes.

Added `tools/verify_baseline.py`: gate 4 of the maturity model, which nothing
could check before. Given a clean capture it reports per rule which EventIDs
are absent and which fields the capture does not carry, and it fails rather
than calling a one-event capture a baseline.

Added `docs/gap-register.md`: the prioritized list of what this repo lacks,
with the P0 items (blind capture, clean baseline, benign corpus, volume) stated
as costs rather than as wishes.

### Conversion results are content-addressed, not clocked

`attack/conversion.json` carried a wall-clock `generated_utc`, so every gate run
dirtied the tree, and the staleness check in `deploy/build_bundle.py` compared
mtimes against it - which a fresh checkout or a `git checkout` breaks silently.
The stamp is now a sha256 over the rule files **and** their measured outcomes.

The first attempt at this hashed only the stored result, which made the stamp
agree with itself forever and could not detect an edited rule. A test now
proves `build_bundle.py` exits 1 when a rule is changed after conversion; the
self-referential version passed that test's inverse.

### Regex selections, exists guards, and a missing detector

- `fieldtypes.render` ignored the `|re` modifier entirely and fell through to
  the path renderer, so a rule matching `^[D-Z]:\...` was handed
  `C:\Users\lab\artifact.bin` and could never match. It now expands the
  pattern and *verifies the result with re.search*, raising rather than
  emitting a value the rule cannot match.
- `Source|exists: true` rendered as `Source: true` - the constraint literal, not
  telemetry. `exists` now produces a field-appropriate present value, and a test
  rejects any boolean leaking into a fixture.
- `analysis/iocs.md` listed `svc_update.exe` and no rule detected it. Added
  `removable_media_spreader_write.yml` (T1091/T1105): executable or autorun.inf
  written to a non-system volume, with the AutoRun deprecation stated rather
  than assumed.
- `screenshot_bmp_artifact.yml` claimed a 54-byte BITMAPINFOHEADER and
  screen-resolution dimensions; Sysmon 11 carries no file contents. The
  description now says that and points at the YARA BMP module for the stronger
  claim.
- YARA: the canonical AMSI patch (patch bytes + the symbol overwritten) did not
  match, because the condition demanded two of three unrelated strings. Fixed,
  meta tag moved off the revoked T1562.001, and a test now asserts five intended
  shapes fire and three partial indicators do not.

### Reproducibility, emulation and scope

- **No dependency pinning.** CI installed unpinned pySigma and backends while
  the gate compares generated query text against `attack/conversion.json`, so
  the "measured" result was reproducible only on the day it was measured. Added
  `requirements.txt` and a gate stage that fails on any version drift.
- **The emulator was never checked against the rules it claims to exercise.**
  Added `emulation/verify_emulation.py`: it parses `emulator_traffic.log` into
  proxy-shaped events and runs the beacon rules over them, failing when the two
  diverge. Its first draft reported two false failures - it ran every proxy rule
  including one that needs an egress the emulator never makes, and one keyed on
  the absence of a header a synthetic event should not fake.
- **Two Zeek blocks were not Zeek.** `network/ja3-x509.md` fenced pseudocode as
  a script, calling `ja3_hash()` and `is_known_python_host()` - neither exists in
  Zeek - and indexing a set never defined. Both are now labelled pseudocode with
  real log fields and a `zeek-cut` command that works as written.
- **The defensive-only claim had no test.** SCOPE.md's central promise was prose.
  `tests/test_scope.py` now fails on capability-bearing imports or calls, on an
  emulator that is not loopback-only, and on a committed binary.
- **Coverage existed only as a table.** `tools/export_navigator.py` emits an
  ATT&CK Navigator layer whose score comes from the fixture lifecycle, not the
  rule count - so with nothing captured, every technique renders at 1.

### Still not done

No blind capture, no benign-corpus run, no measured volume, no sample. Nothing
in this changelog changes that: every fixture still says `designed`.

## Release 2026.11.27 (first recorded release)

The first release with a derived version, a content digest and a changelog
check that fails on an unrecorded commit. Every commit below predates that
check, so this entry is written after the fact from the commit log; the
`tools/release.py --check-changelog` gate keeps it from drifting again.

- **Fix blocking defects, close harness gaps, add capture workflow** (`c5156e2`). Blocking defects: `status: designed` made every rule unloadable by pySigma, the conversion gate required a package that does not exist on PyPI, and correlations used types Sigma does not have. Adds the capture workflow.
- **Upgrade ATT&CK pin to 20.1, derive tactics, make capture honest** (`a0ee5fa`). ATT&CK pin 14.1 -> 20.1. v20 revoked T1562 and split Defense Evasion into Stealth and Defense Impairment, so six rules cited a dead technique and a dead tactic. The pin is now generated from the STIX bundle with a hash, and tactic lists are derived from it.
- **Content-address conversion results, make the gate idempotent** (`bf5d764`). Conversion results are content-addressed over the rule files and the outcomes, so the staleness check can fail. Two consecutive gate runs leave the tree clean.
- **Register the stale-check defect and the idempotency fix** (`7cc4409`). Gap register records the stale-check defect and the idempotency fix.
- **Make the advisory checks fail, lint Suricata, ship suppression** (`ed0c013`). Three checks that printed `warn` and exited 0 now fail: unknown hunt fields, Suricata signatures, YARA matching. Suppression travels in the bundle manifest.
- **Fix the generator's regex and exists handling, add the missing spreader rule** (`38685fd`). Fixture generator expands `|re` patterns and verifies the expansion with `re.search` instead of emitting a value the rule cannot match. Adds `removable_media_spreader_write.yml`, which closes an IOC with no detector.
- **Register the advisory-check, suppression and generator gaps** (`baeea67`). Gap register records the advisory-check, suppression and generator gaps.
- **Add the deployment procedure the repo never had** (`a4dd3b0`). `docs/deployment.md`: telemetry prerequisites, field mapping per platform, suppression, and the enable-one-severity-band-at-a-time procedure.
- **Find dead filters with a test, and kill the two that were there** (`b90f1a2`). A test now proves a filter disjoint from its selection can never fire; two rules had exactly that and are fixed.
- **Add the measured assessment of the repository as a whole** (`48bb00d`). `docs/assessment.md`: what the repository can and cannot support, measured rather than asserted.
- **Pin dependencies, verify the emulator against its rules, fix fake Zeek** (`5dfa06e`). Dependencies pinned in `requirements.txt` with a gate stage that fails on drift. The beacon emulator is verified against the rules it feeds, and fails when both OR branches diverge. Two fenced blocks that called nonexistent Zeek functions are relabelled pseudocode.
- **Pin deps, test the defensive-only claim, export a Navigator layer** (`252dc71`). `tests/test_scope.py` enforces the defensive-only claim: no capability imports or calls, loopback-only emulators, no tracked binaries. `tools/export_navigator.py` scores evidence rather than rule count, so the layer renders at 1, not green.
- **Declare and enforce the Python floor** (`369bb5d`). The Python floor is 3.9 because of `Path.is_relative_to`; it is declared in `ci/check_env.py`, enforced by a grammar parse test, and CI matrixes 3.9 and 3.11.
- **Update the assessment with the pinned environment, emulator check and scope tests** (`7a69b58`). `docs/assessment.md` updated for the pinned environment, the emulator check, and the scope tests.
- **Add correctness lint (G-35) and importable Splunk saved searches (G-29)** (`1b565e2`). ruff correctness rules (two real late-binding closure bugs and a `--verbose` flag that did nothing). `deploy/build_savedsearches.py` emits an installable `savedsearches.conf`: 33 searches, all disabled, five-minute schedule floor, suppression from each rule's own `dedup_key`.
- **Close the alert-quality loop (G-30)** (`fab7c11`). `tuning/observations.csv` plus `tools/tuning_log.py`: the Markdown log is generated from the CSV, a measured events/day promotes a ceiling, and `lifecycle: tuned` without a `keep` observation fails the gate.
- **Implement the beacon jitter job the docs said was not implemented (G-12)** (`400086a`). `analytics/beacon_jitter.py` implements the inter-arrival distribution job the docs called unimplemented: median and coefficient of variation per source/destination pair, with the rule's local-domain filter applied and the limitation asserted in a test.
- **Add Sigma evaluator, concrete fixtures, config fixes, gate hardening, governance** (`16e07b8`). The evaluator that made rule testing possible offline: Sigma condition parsing, fixture evaluation, the Sysmon config rewrite, and the governance files (`SCOPE.md`, `SECURITY.md`, `CONTRIBUTING.md`).
- **Build the joins that were only specified, and add the campaign layer (G-13, G-14, G-15)** (`265397d`). `deploy/build_joins.py` generates EQL, ES|QL and Kusto forms of the five correlations pySigma will not convert. `analytics/stage_join.py` implements the stage0->stage1 shared-parent join. `sigma/campaign_implant_sequence.yml` plus `analytics/campaign.py` add a 3-of-4 cross-source campaign.

## 2026-11-28

- **Add a pre-commit hook and a commit-message check** (`G-20`). `.githooks/`
  runs ruff, the tests and the fixture-freshness check on any commit that
  touches code, rules or fixtures, and rejects a subject like `fix` or `wip`.
  Install with `git config core.hooksPath .githooks`. `tests/test_hooks.py`
  executes the scripts with crafted input rather than inspecting them, because a
  hook that is a readable file but not executable is worse than no hook.
- **Derive a release identity from the tree** (`G-36`). `tools/release.py`
  computes a content digest over 196 behaviour-relevant files, derives the
  version from the date and existing tags, and fails the gate on any commit the
  changelog does not mention. It found 19 unrecorded commits, all now written up
  above. `dist/release.json` ships inside the bundle so a consumer can say what
  they have.

- **Add local hooks and derive a release identity from the tree** (`G-20`, `G-36`).
  `.githooks/pre-commit` runs ruff, the tests and the fixture check;
  `commit-msg` rejects `fix`/`wip`. `tools/release.py` computes a content digest
  over 196 behaviour files, derives `vYYYY.MM.DD.N`, and fails the gate on any
  commit the changelog does not mention - it found 19 and this list is the
  result. `dist/release.json` ships inside the bundle.
- **Give the YARA rule a corpus** (`G-16`). `yara/corpus/` (generated, not committed) holds one synthetic
  implant stand-in, six benign files that each carry a *real* indicator
  (`AmsiScanBuffer` in a Defender-like binary, `_MEI` in a genuine PyInstaller
  app, `X-Id` in a browser updater), and five partials. Built deterministically
  by `tools/build_yara_corpus.py`, checked for staleness by a gate stage.
  Widening one branch of the rule to `any of` is caught immediately as a
  false positive on the Defender-shaped file. The corpus files are generated,
  never committed: the defensive-only claim includes no binary artifacts in git,
  and determinism makes committing them unnecessary.

- **Give the YARA rule a corpus of near-misses** (`G-16`). `yara/corpus/` is
  generated by `tools/build_yara_corpus.py`: one implant stand-in, six benign
  files that each carry a real indicator for a real reason (a Defender-shaped
  binary naming `AmsiScanBuffer` because it calls it, a genuine PyInstaller app
  with `_MEI`, a browser updater with an `X-Id` header enum), and five partials.
  Widening the rule's `2 of (amsi, etw, vp)` branch to `any of` fires on the
  Defender-shaped file, which is the regression the corpus exists to catch. The
  corpus is generated, not committed: the no-binary-artifacts claim in
  `tests/test_scope.py` outranks the convenience of storing twelve small files.
- **Measure rule overlap with upstream SigmaHQ** (`G-37`). `tools/sigmahq_overlap.py`
  caches a 3,164-rule snapshot of `SigmaHQ/sigma` at a pinned commit and compares
  event families, products, ATT&CK techniques and selection coverage. The
  headline finding: **no duplicate and no divergent rule** - the two `near`
  relationships it reports are both ancestor-path artefacts of the metric, and
  the record says so. This check was wrong three times before it was right (a
  literal logsource comparison, an exact-path comparison, and a normaliser that
  doubled every backslash), each time printing "0 relationships" and reading as
  "unique"; those three bugs are now regression tests.

- **Name every field on every platform** (`G-28`). `telemetry/field-map.json`
  holds one canonical Sigma field -> Splunk / Elastic / Kusto name, and
  `pipeline/build_field_map.py` writes the three configs from it: a `props.conf`
  of `FIELDALIAS` lines, an Elastic ingest pipeline, and Kusto views. The point
  is not the files. It is that a rule reading `EventID` on Splunk, where the
  field is `EventCode`, matches a null and *looks quiet* - the failure has no
  symptom. Two of the mappings are not renames and say so: `CertificateSelfSigned`
  is `subject == issuer` and must be computed, and Splunk's `cs_user_agent` has
  to be aliased back to the hyphenated `cs-user-agent` the proxy rules use.
  `pipeline/field_contract.py` already proved every field a rule reads is
  documented; this proves every documented field has a name everywhere.

- **Verify pins without downloading them** (`G-19`). The ATT&CK bundle and the
  SigmaHQ snapshot are gitignored, so `--verify` said `MISSING` everywhere except
  on the machine that fetched them. `tools/verify_pins.py` separates the two
  claims that were being conflated: *verified from bytes* when the cache is
  present and hashes correctly, and *derived-only* when it is not - because the
  derived data (tactic list, technique list, snapshot commit) is small and
  committed, and its digest still proves the repo is internally consistent.
  What it now catches that nothing caught before: a review measured against one
  upstream tree and still cited after the cache moved. `--strict` turns
  "unhashed" into a failure for anyone who does have the caches.

- **Tie a capture to the machine it came from** (`G-21`). A captured fixture is
  evidence about one host: this build, this Sysmon version, this audit policy.
  `telemetry/lab-image.json` now declares the intended host and
  `tools/evtx_to_fixture.py` records which of those values the capture could
  report. A capture with no stated build, or from a different one, is refused
  rather than filed as a fixture. `docs/runbook.md` also told the operator to
  write captures over `fixtures/per_rule/`, which destroys the record of what
  the rule was meant to match - the tool had already fixed that and the runbook
  never followed. **The gap stays partly open:** no VM image was built from the
  manifest, so captures are now attestable but still not reproducible.

- **Make the response playbooks followable** (`G-18`). All 39 told the analyst
  to check `rule:<id>:host:user`, an identifier that exists nowhere in the
  repository, in a single sentence. `tools/generate_playbooks.py` now derives
  five sections from each rule - what fired, triage over the fields *that rule*
  reads, a containment action from a fixed vocabulary, artifacts to preserve by
  technique family, and the benign behaviour that looks the same - and
  `response/check_playbooks.py` reads all 39 to prove it. Two of the findings
  were structural: six correlation rules got an empty triage list because they
  have no `detection` block (their fields are `group-by` keys), and every
  playbook shared one boilerplate triage paragraph about registry run keys,
  including the DNS rules. **Still not worked by a human** - followable is not
  followed, and every file says so.

- **Generate the SACL script that 4663 rules depend on** (`G-08`).
  `telemetry/auditpol.md` said "use Set-Acl / subinacl / your EDR's tooling" -
  three options and no command, for a step that has to be exact or the rule
  never fires and never says why. `tools/build_sacl_script.py` now derives the
  targets from the rules that actually read a 4663 field and emits
  `deploy/telemetry/set-sacls.ps1`: backup, apply, read the SACL back to prove
  it stuck, `-Rollback` to undo. Writing it found that the hand-written list had
  four targets and **one** was needed - two served rules that read Sysmon 11 or
  only mentioned 4663 in prose, and `C:\Users` would have produced millions of
  events a day for a rule that was never listening. Also `verify_baseline.py
  --repin`, because the manifest hash had no regeneration path and the only
  alternative was pasting a new hash until the drift test went green.
- **Keep the gap register's own arithmetic honest** (`tests/test_gap_register.py`).
  Twice a row was rewritten to describe a fix while staying in the Open section,
  so the document read as both. The test fails on a gap listed twice, a gap that
  vanished, a "closed" gap with no code behind it, and an "open" gap whose row
  does not say what it is waiting for. It immediately caught four wrong rows.

- **Execute the checkable half of the deployment procedure** (`G-27`).
  `docs/deployment.md` was honest that it had never run; it was not honest about
  the repository it described. It said 38 rules when there were 39, quoted
  per-backend conversions out of 38 rather than 39, and sent the reader to
  `response/rules/<id>.md`, which is a pattern, not a file. `tools/check_deployment_doc.py` now verifies every path
  it names, every count it asserts - read from `conversion.json`, not from the
  generated matrix - and runs the four commands that depend only on this
  repository. The seven steps that need Splunk, Elastic, Sentinel or Windows are
  printed as unverified rather than passing quietly.
- **A checker that rewrites what it checks is not a checker.** The first version
  of `check_deployment_doc.py` ran the Splunk-only `convert_check.py` line the
  doc shows, and that command writes `attack/conversion.json` as a side effect:
  the file came back with elastic and kusto blank, the matrix was regenerated
  from it, and `test_matrix_is_current` failed two stages later with no visible
  link to the cause. It now runs all three backends and restores the file via
  git; both facts are tests.

- **Sweep the stale rule counts out of every document.** The 39th rule landed
  two commits ago; six files still said 38, including a README line claiming
  `38/38` conversions. All of them read correctly as prose, which is why they
  survived. `tools/check_deployment_doc.py` now checks every document that
  quotes a total, and it distinguishes a *total* ("38/38 rules") from a true
  subset ("32 of the 39 rules evaluate against a null") - flagging subsets would
  teach the reader to ignore the check.
- **G-33 and G-08 were fixed but still listed as open**; the register's own test
  caught both.

- **Find four more stale counts, in the table cells.** The README's
  own summary table still said "38 Sigma rules (33 single-event + 5
  correlations)" and "37 pairs"; `docs/assessment.md` said "all 38 rule
  fixtures". The sweep now covers bare counts in table cells, not just `N/N`
  ratios. `39` rules is `34` single-event plus `5` correlations, and there are
  `39` fixture pairs.

- **The changelog needle was a 40-character trap.** `tools/release.py` matched
  each commit by the first 40 characters of its subject. Truncation can land
  mid-word: a line beginning `**Find four more stale counts, in the table
  cells.**` carries `...in the tabl` immediately followed by `e cells`, so the
  needle missed a line that opens with the subject in bold — the natural way to
  write it. Now 24 characters, which is still specific and no longer depends on
  where the cut falls.

- **Stop the changelog needle from depending on where truncation lands.**
  `tools/release.py` identified each commit by the first 40 characters of its
  subject. That is a trap when the cut falls mid-word: a line beginning
  `**Find four more stale counts, in the table cells.**` yields
  `...in the tabl` followed by `e cells`, so a commit failed the gate while its
  changelog line was sitting there in bold. 24 characters now — still specific,
  and far less likely to end inside a word the changelog splits.

## Versioning

`tools/release.py` derives the version from the date and the existing tags
(`vYYYY.MM.DD.N`) and computes a **content digest**: sha256 over every
behaviour-relevant tracked file. The digest, not the version string, is the real
identity - two trees with the same digest have the same rules, fixtures, gate and
tooling. `--verify <tag>` re-hashes the tagged tree and fails if it no longer
matches.

A version here is a name for an exact tree, not a claim about its quality.
