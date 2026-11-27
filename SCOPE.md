# Scope

This folder is a **detection laboratory**. It contains rules, telemetry
definitions, inert fixtures, test harnesses, and documentation.

## In scope

- Sigma and YARA rule authoring and validation
- Telemetry source definitions (Sysmon, audit policy, ETW)
- Inert expected-event fixtures for malicious and benign behavior
- Rule compile / true-positive / false-positive tests and CI gates
- Coverage generation from rule metadata
- Sample **pinning metadata** for samples obtained through legitimate channels

## Out of scope

- No implant source, build recipe, or compiled payload is stored here
- No AMSI/ETW patching, process injection, persistence, credential access, or C2
  implementation code
- No live traffic to any system outside an isolated lab VM
- No real credentials, real user data, or external callback infrastructure

## Why there is no `implant/` directory

A pinned sample is only meaningful if it is an immutable artifact you legitimately
hold. This lab holds no such artifact. `samples/PINS.md` defines the pin format and
leaves every hash field as a placeholder. If you obtain a sample through a threat
intel feed, a sandbox submission, or your own IR case, fill in those fields there —
without adding the sample to this repository unless your policy expressly permits
it and the storage is access-controlled.
