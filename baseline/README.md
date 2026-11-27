# Clean baseline

A golden capture of a clean lab host, before any fixture is run.

## Contents to capture

- Sysmon events over 24 hours with the config in `telemetry/sysmon-config.xml`.
- Security events with the audit policy in `telemetry/auditpol.md`.
- Zeek DNS/HTTP/SSL logs and proxy request logs.
- ETW provider availability list for the OS build in `os-matrix.md`.

## Purpose

1. Prove the config emits the event IDs and fields each rule reads.
2. Establish the normal volume baseline for `metrics/`.
3. Give FP tuning a reference point.

## Rule

The baseline is captured once per OS build and toolchain version. If either
changes, recapture. A rule whose required event ID or field does not appear in
the baseline is reported as a telemetry gap, not as a rule that passed.
