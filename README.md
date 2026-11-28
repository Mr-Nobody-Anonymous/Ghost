# Ghost detection lab

A detection-engineering repository. It holds **39 Sigma rules**, the telemetry
they need to work, and the checks that keep them honest - and it holds no
software that attacks anything.

The question it exists to answer: *if someone ran this implant, would our logs
catch it - and would the rule stay quiet on a normal Tuesday?* Every rule
describes behaviour, never code. Nothing here drops a file, calls out to a
server, reads a credential, or patches a security product.

It is a **specification with a test harness**, not a validated detection
library. Rules are checked against fixtures derived from the rules themselves;
none has fired on a machine, and precision is unmeasured. `docs/assessment.md`
says exactly how far each claim goes, and `docs/gap-register.md` lists what is
missing and what it would cost to close.

## What is here

| Path | Purpose |
|---|---|
| `sigma/` | 39 Sigma rules (34 single-event + 5 correlations) + schema + Suricata header rules |
| `yara/` | Structural rules: packers, stage fingerprints, config artifacts |
| `telemetry/` | Data-source map, Sysmon config, audit policy + SACLs, ETW provider list |
| `fixtures/` | Generated positive/negative fixture per rule (39 pairs); benign FP corpus spec |
| `tools/benign_corpus.py` | **Measures per-rule precision** against collected benign telemetry; `--classes` lists what a full run needs |
| `tests/`, `ci/`, `tools/` | Rule/fixture tests, CI gate, coverage generator |
| `samples/` | Sample pin **schema** — no binary stored |
| `network/`, `docs/`, `analysis/` | Fingerprint detections, runbook/tuning/maturity, triage templates |
| `docs/assessment.md` | **What this is, measured** - what is proven and what is not |
| `docs/gap-register.md` | What is missing, ordered by cost |
| `docs/deployment.md` | Host -> index -> scheduled search, with the silent failure modes |
| `docs/technique-lab-guide.md` | **How each technique works and the safe test for it** - mechanism, expected event IDs, cleanup, and what the test does *not* prove |
| `hunt-queries.md`, `lab-setup.md`, `inventory.md`, `os-matrix.md` | Hunting queries, lab build, behavior inventory, OS support |
| `attack/` | Coverage matrix, Navigator layer (`navigator-layer.json`), per-rule conversion results (`conversion.json`) |

## What is deliberately NOT here

The implant implementation — dropper, C2 client, evasion patching, persistence
installer, credential/browser/wallet collectors, keylogger, screen/clipboard
capture, spreading module, and operator server — is **not included**, in whole or
in part. There is no `implant/` directory and no `builds/` artifact. Detection
signatures reference behavior and indicator strings; they do not reproduce the
malicious code paths. The emulation scripts use canary markers and a loopback
listener; they perform no EDR patching, no credential access, no real
persistence, and no external network calls.

## Repository policy

This is a defensive-only repository. See `SECURITY.md` for the security policy
and vulnerability reporting, `LICENSE` for the MIT license,
`CODE_OF_CONDUCT.md` for community standards, and `CONTRIBUTING.md` for what is
allowed in a pull request. No implant, exploit, C2, or evasion implementation is
included or accepted. All emulation is loopback-only and inert.

## Quick start

```bash
bash ci/gate.sh                       # 20 stages: validate, lint, build, test, evaluate,
                                     # fixtures, emulation, analytics, precision harness,
                                     # joins, telemetry, lint, tuning, overlap, release,
                                     # deployment, playbooks, ratchet, convert, package
python3 detection-as-code/evaluate.py # TP/FP/sequence/frequency against fixtures
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/capture_kit.py --rule <id-prefix>   # how to capture this rule for real
python3 tools/evtx_to_fixture.py --input captured.xml --rule-id <id> \
  --sample-ref PIN-0001     # writes fixtures/captured/ and refuses if the rule
                            # does not fire on the capture
python3 deploy/build_bundle.py --backend splunk --out dist/splunk-queries.spl
python3 tools/export_navigator.py     # attack/navigator-layer.json for ATT&CK Navigator
```

The gate passes today: 38/39 rules convert to Splunk, 32/39 to Elastic and Kusto
(the correlations and one `fieldref` rule are Splunk-only in pySigma), every
rule matches its generated fixture and stays silent on its negative fixture.

What it does **not** prove: no event in this repository came off a machine.
There is no blind capture, no benign-corpus run, no volume measurement. See
`docs/maturity.md` - every fixture marked `designed` is saying exactly that.

## Safe use

1. Run all emulation inside a disposable, isolated lab VM (Internal or Host-only
   network, snapshot taken first).
2. Start `emulation/local_listener.py`, then run the generators. All traffic stays
   on `127.0.0.1`.
3. Compare the telemetry your SIEM/EDR actually produced against
   `ATT&CK-coverage.md` and `inventory.md`.
4. Clean up marker files and stop the listener; restore the snapshot.

Do not run any of this against a system you do not own or an in-scope lab.

## Rule tuning note

Sigma field names differ between Sysmon, Windows Event Log, Zeek, and proxy/SWG
exports. The rules here use common field names and include `falsepositives` and
comments mapping the alternatives. Validate with `sigma check` / `sigma convert`
against your own pipeline before deployment.
