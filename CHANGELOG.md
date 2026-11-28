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
