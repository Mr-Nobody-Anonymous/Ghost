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

echo "[1/9] structural validation (schema, Sigma status, ATT&CK pin, conversion claims)"
python3 detection-as-code/validate_rules.py

echo "[2/9] rule and contract tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[3/9] rule evaluation against concrete fixtures (TP/FP/sequence/frequency)"
python3 detection-as-code/evaluate.py

echo "[4/9] fixtures match their rules (stale fixture = failing test)"
python3 tools/generate_fixtures.py --check

echo "[5/9] telemetry field contract (every field a rule reads is documented)"
python3 pipeline/field_contract.py --strict

echo "[6/9] query lint (hunt queries parse and use documented fields)"
python3 pipeline/lint_queries.py

echo "[7/9] PENDING ratchet"
python3 ci/pending_ratchet.py main

echo "[8/9] backend conversion: every rule's declared support is measured"
python3 ci/convert_check.py --backends splunk elastic kusto --quiet

echo "[9/9] coverage + deployable bundle + package"
python3 tools/generate_matrix.py
python3 deploy/build_bundle.py --backend splunk --out dist/splunk-queries.spl
mkdir -p dist
tar --exclude=dist --exclude=__pycache__ --exclude='*.pyc' --exclude=attack/cache \
  -czf dist/detection-lab.tgz \
  README.md SCOPE.md CHANGELOG.md LICENSE SECURITY.md CODE_OF_CONDUCT.md \
  CONTRIBUTING.md NOTICE inventory.md os-matrix.md hunt-queries.md lab-setup.md \
  sigma yara attack fixtures telemetry tests tools network docs \
  pipeline deploy response metrics baseline ci detection-as-code emulation analysis samples
echo "OK: dist/detection-lab.tgz"
