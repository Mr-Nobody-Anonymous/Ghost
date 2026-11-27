# Ghost detection lab

Defensive counterpart to the implant design described in the request. This folder
contains **detection content and inert lab tooling only**. It answers:
"would our telemetry catch this behavior, and would it stay quiet?"

## What is here

| Path | Purpose |
|---|---|
| `sigma/` | Detection rules (Systematic 10 rules + schema + Suricata header rules) |
| `yara/` | Structural rules: packers, stage fingerprints, config artifacts |
| `telemetry/` | Data-source map, Sysmon config, audit policy + SACLs, ETW provider list |
| `fixtures/` | Expected-event fixtures for five gap techniques; benign FP corpus spec |
| `tests/`, `ci/`, `tools/` | Rule/fixture tests, CI gate, coverage generator |
| `samples/` | Sample pin **schema** — no binary stored |
| `network/`, `hunting/`, `docs/`, `analysis/` | Fingerprint detections, hunting queries, runbook/tuning/maturity, triage |
| `attack/`, `reports/` | Generated coverage matrix and precision reports |

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
bash ci/gate.sh          # validate -> test -> ratchet -> convert -> matrix -> package
python3 tools/generate_matrix.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

The gate currently **fails at stage 4 (backend conversion)**: pySigma's Splunk
and KQL backends are not installed, so no rule is proven deployable. That is a
real failure, not a glitch. See `docs/maturity.md` for the full honesty check.

## Safe use

1. Run all emulation inside a disposable, isolated lab VM (Internal or Host-only
   network, snapshot taken first).
2. Start `emulation/local_listener.py`, then run the generators. All traffic stays
   on `127.0.0.1`.
3. Compare the telemetry your SIEM/EDR actually produced against
   `ATT&CK-coverage.md`.
4. Clean up marker files and stop the listener; restore the snapshot.

Do not run any of this against a system you do not own or an in-scope lab.

## Rule tuning note

Sigma field names differ between Sysmon, Windows Event Log, Zeek, and proxy/SWG
exports. The rules here use common field names and include `falsepositives` and
comments mapping the alternatives. Validate with `sigma check` / `sigma convert`
against your own pipeline before deployment.
