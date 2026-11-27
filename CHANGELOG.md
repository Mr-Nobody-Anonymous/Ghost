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

## Scope note

The implant implementation supplied with the request remains excluded. There is
no `implant/` directory and no compiled sample in `samples/`. Every file here is
detection content, inert telemetry generation, or analysis tooling. No EDR
patching, credential access, persistence, or external C2 code is present.
