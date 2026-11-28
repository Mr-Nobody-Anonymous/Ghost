#!/usr/bin/env bash
# CI gate: validate -> tests -> evaluate -> fixtures -> contract -> ratchet
#          -> conversion -> coverage -> package.
#
# Failure semantics are per stage; later stages do not run after a failure.
# Every stage here is a real check with a real failure mode. Nothing in this
# file is allowed to "pass because it could not run" - an absent dependency is
# a failure, not a skip.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[0/14] environment matches requirements.txt (pinned pySigma + backends)"
python3 ci/check_env.py

echo "[1/14] structural validation (schema, Sigma status, ATT&CK pin, conversion claims)"
python3 detection-as-code/validate_rules.py

echo "[2/14] python correctness lint (ruff: undefined names, closures, unused)"
python3 -m ruff check .

echo "[3/14] rule and contract tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[4/14] rule evaluation against concrete fixtures (TP/FP/sequence/frequency)"
python3 detection-as-code/evaluate.py

echo "[5/14] fixtures match their rules (stale fixture = failing test)"
python3 tools/generate_fixtures.py --check

echo "[6/14] emulation: descriptors verify, and the beacon emulator feeds its rules"
python3 emulation/emit_expected_events.py >/dev/null
python3 emulation/verify_emulation.py --dry-run
python3 tools/generate_fixtures.py --check

echo "[7/14] telemetry field contract (every field a rule reads is documented)"
python3 pipeline/field_contract.py --strict

echo "[8/14] query + Suricata lint (hunt queries, signatures, SIDs, ATT&CK metadata)"
python3 pipeline/lint_queries.py
python3 pipeline/lint_suricata.py

echo "[9/14] tuning loop: observations valid, no rule claims tuning it cannot prove"
python3 tools/tuning_log.py --check --render

echo "[10/14] PENDING ratchet"
python3 ci/pending_ratchet.py main

echo "[11/14] backend conversion: every rule's declared support is measured"
python3 ci/convert_check.py --backends splunk elastic kusto --quiet

echo "[12/14] coverage + deployable bundle + package"
python3 tools/generate_matrix.py
python3 tools/export_navigator.py
python3 deploy/build_bundle.py --backend splunk --out dist/splunk-queries.spl \
  --manifest dist/splunk-manifest.json
python3 deploy/build_savedsearches.py

echo "[13/14] saved searches: installable, disabled, uniquely named"
python3 -m unittest tests.test_savedsearches

mkdir -p dist
tar --exclude=dist --exclude=__pycache__ --exclude='*.pyc' --exclude=attack/cache \
  -czf dist/detection-lab.tgz \
  README.md SCOPE.md CHANGELOG.md LICENSE SECURITY.md CODE_OF_CONDUCT.md \
  CONTRIBUTING.md NOTICE inventory.md os-matrix.md hunt-queries.md lab-setup.md \
  sigma yara attack fixtures telemetry tests tools network docs tuning \
  pipeline deploy response metrics baseline ci detection-as-code emulation analysis samples
echo "OK: dist/detection-lab.tgz"
