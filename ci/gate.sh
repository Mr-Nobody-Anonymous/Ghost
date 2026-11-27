#!/usr/bin/env bash
# CI gate: validate -> compile -> test -> generate coverage.
# Failure semantics are per stage; later stages do not run after a failure.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/6] structural validation"
python3 detection-as-code/validate_rules.py

echo "[2/6] rule compile + fixture tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[3/6] PENDING ratchet"
python3 ci/pending_ratchet.py main

echo "[4/6] backend conversion (hard gate)"
python3 ci/convert_check.py --backends splunk kql

echo "[5/6] coverage generation"
python3 tools/generate_matrix.py

echo "[6/6] package"
mkdir -p dist
tar --exclude=dist --exclude=__pycache__ -czf dist/detection-lab.tgz \
  README.md SCOPE.md inventory.md os-matrix.md sigma yara attack fixtures \
  telemetry tests tools network docs pipeline deploy response metrics baseline ci
echo "OK: dist/detection-lab.tgz"
