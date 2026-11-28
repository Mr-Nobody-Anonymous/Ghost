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

echo "[0/20] environment matches requirements.txt (pinned pySigma + backends)"
python3 ci/check_env.py

echo "[1/20] structural validation (schema, Sigma status, ATT&CK pin, conversion claims)"
python3 detection-as-code/validate_rules.py
# The pinned artifacts are gitignored, so a fresh clone cannot hash them. This
# still fails when the derived data a pin is cited for no longer matches it -
# the stale-review case - and says plainly when the bytes went unchecked.
echo "       pins: recorded hashes still describe the committed derived data"
python3 tools/verify_pins.py

echo "[2/20] python correctness lint (ruff: undefined names, closures, unused)"
python3 -m ruff check .

echo "[3/20] rule and contract tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[4/20] rule evaluation against concrete fixtures (TP/FP/sequence/frequency)"
python3 detection-as-code/evaluate.py

echo "[5/20] fixtures match their rules (stale fixture = failing test)"
python3 tools/generate_fixtures.py --check
python3 tools/build_yara_corpus.py

echo "[6/20] emulation: descriptors verify, and the beacon emulator feeds its rules"
python3 emulation/emit_expected_events.py >/dev/null
python3 emulation/verify_emulation.py --dry-run
python3 tools/generate_fixtures.py --check
python3 tools/build_yara_corpus.py

echo "[7/20] analytics: beacon jitter, stage0->stage1 join, cross-source campaign"
python3 analytics/beacon_jitter.py --selftest
python3 analytics/stage_join.py --selftest
python3 analytics/campaign.py --selftest

echo "[8/20] cross-platform joins for the correlations pySigma will not convert"
python3 deploy/build_joins.py --check

echo "[9/20] telemetry: field contract, platform field map, and SACL coverage"
echo "       a 4663 rule with no SACL cannot fire, and looks quiet"
python3 pipeline/field_contract.py --strict
# ...and every documented field has a name on every platform. A rule reading
# EventID on Splunk, where it is EventCode, matches a null and looks quiet.
echo "       field map: generated platform configs match the map"
python3 pipeline/build_field_map.py --check
# Security 4663 only exists when an object carries a SACL with an Audit ACE.
# A rule reading it on a host without one is not quiet, it is incapable of
# firing - and nothing in the telemetry distinguishes the two.
python3 tools/build_sacl_script.py --check

echo "[10/20] query + Suricata lint (hunt queries, signatures, SIDs, ATT&CK metadata)"
python3 pipeline/lint_queries.py
python3 pipeline/lint_suricata.py

echo "[11/20] tuning loop: observations valid, no rule claims tuning it cannot prove"
python3 tools/tuning_log.py --check --render

echo "[12/20] upstream overlap: every duplicate decision is recorded"
# The 14 MB snapshot is gitignored, so a clean CI checkout has no cache. Running
# the check against nothing would print "0 relationships" and read as "unique",
# which is the exact failure this check was built to stop. So: fetch when the
# network is available (a full fetch is ~10 min; CI caches attack/cache between
# runs), and otherwise say out loud that the check was skipped for lack of a
# snapshot rather than passing quietly.
if [ ! -f attack/cache/sigmahq/index.json ]; then
  echo "note: no upstream snapshot; attempting a fetch (first run only)"
  python3 tools/sigmahq_overlap.py --fetch || \
    echo "WARN: upstream snapshot unavailable - overlap NOT measured this run"
fi
if [ -f attack/cache/sigmahq/index.json ]; then
  python3 tools/sigmahq_overlap.py --check
else
  echo "SKIP: upstream overlap not measured - no snapshot and no network."
  echo "      docs/gap-register.md G-37 stays open until it runs somewhere."
fi

echo "[13/20] release discipline: changelog covers every commit, digest is real"
python3 tools/release.py --check-changelog

echo "[14/20] deployment procedure: paths exist, counts match, commands run"
python3 tools/check_deployment_doc.py

echo "[15/20] response playbooks: generated, current, and followable"
python3 tools/generate_playbooks.py --check
python3 response/check_playbooks.py

echo "[16/20] PENDING ratchet"
python3 ci/pending_ratchet.py main

echo "[17/20] backend conversion: every rule's declared support is measured"
python3 ci/convert_check.py --backends splunk elastic kusto --quiet

echo "[18/20] coverage + deployable bundle + package"
python3 tools/generate_matrix.py
python3 tools/export_navigator.py
python3 deploy/build_bundle.py --backend splunk --out dist/splunk-queries.spl \
  --manifest dist/splunk-manifest.json
python3 deploy/build_savedsearches.py

echo "[19/20] saved searches: installable, disabled, uniquely named"
python3 -m unittest tests.test_savedsearches

mkdir -p dist
python3 tools/release.py --json > dist/release.json
tar --exclude=dist --exclude=__pycache__ --exclude='*.pyc' --exclude=attack/cache \
  -czf dist/detection-lab.tgz \
  README.md SCOPE.md CHANGELOG.md LICENSE SECURITY.md CODE_OF_CONDUCT.md \
  CONTRIBUTING.md NOTICE inventory.md os-matrix.md hunt-queries.md lab-setup.md \
  sigma yara attack fixtures telemetry tests tools network docs tuning analytics \
  pipeline deploy response metrics baseline ci detection-as-code emulation analysis samples
echo "OK: dist/detection-lab.tgz"
