# Security policy

## Repository scope (read first)

This repository is a **defensive detection laboratory**. It contains:

- Sigma and YARA detection rules
- Telemetry source definitions, Sysmon/audit-policy configuration, ETW provider lists
- Inert expected-event fixtures and loopback-only emulation scripts
- Test harnesses, CI gates, coverage generation, and analysis documentation

It deliberately contains **no implant, no exploit, no C2 client, no credential
stealer, no persistence installer, and no evasion implementation**. Nothing in
this repository executes a payload, patches EDR, opens a network socket to a
third party, or modifies system state. The "malicious" fixtures are JSON
descriptions of events, and all emulation binds to `127.0.0.1`.

This project is intended for authorized blue-team work: building, validating,
and tuning detections in an isolated lab you own.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| tags older than `main` | No - upgrade to `main` |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting on this repository
("Security" tab -> "Report a vulnerability"), or contact the maintainers
through the profile listed in the repository owner information.

Include:

- affected file path and rule ID (if any)
- reproduction steps in an isolated lab
- impact (for example: a rule that fails to compile, a false-negative pattern, or an unsafe example)
- suggested remediation

You should receive an acknowledgement within 7 days and a status update within
30 days. We will credit reporters who wish to be named.

## Out of scope

- Reports about the behavior of the unrelated software described in the
  detection rules (those are vendor issues)
- Requests to add offensive tooling, working exploits, or deployable malware
  to this repository
- Reports that require running code against systems you do not own

## Safe testing

Any validation must run in a disposable, isolated VM with a snapshot taken
first. Do not run any emulator or rule test against production systems.
