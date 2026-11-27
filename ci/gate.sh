#!/usr/bin/env bash
# CI gate: validate -> tests -> evaluator -> ratchet -> conversion -> coverage -> package.
# Failure semantics are per stage; later stages do not run after a failure.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/7] structural validation"
python3 detection-as-code/validate_rules.py

echo "[2/7] rule and contract tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[3/7] rule evaluation against concrete fixtures (TP/FP/sequence)"
python3 detection-as-code/evaluate.py

echo "[4/7] PENDING ratchet"
python3 ci/pending_ratchet.py main

echo "[5/7] backend conversion (hard gate - all backends required)"
python3 ci/convert_check.py --backends splunk kql

echo "[6/7] coverage generation"
python3 tools/generate_matrix.py

echo "[7/7] package (validator and evaluator included so a consumer can reproduce the gate)"
mkdir -p dist
tar --exclude=dist --exclude=__pycache__ --exclude='*.pyc' -czf dist/detection-lab.tgz \
  README.md SCOPE.md CHANGELOG.md LICENSE SECURITY.md CODE_OF_CONDUCT.md \
  CONTRIBUTING.md NOTICE inventory.md os-matrix.md hunt-queries.md lab-setup.md \
  sigma yara attack fixtures telemetry tests tools network docs \
  pipeline deploy response metrics baseline ci detection-as-code emulation analysis samples
echo "OK: dist/detection-lab.tgz"
