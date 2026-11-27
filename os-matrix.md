# OS support matrix

Sysmon event IDs and ETW providers differ by Windows version. A rule validated
on one build may silently fail on another.

| OS build | Sysmon config version | EIDs available | ETW providers | Notes |
|---|---|---|---|---|
| Windows 10 21H2 | 4.90 | 1, 10, 11, 12-14, 19-21, 24 | Kernel-Process, Win32k, DFM | Baseline not captured |
| Windows 11 23H2 | 4.90 | 1, 10, 11, 12-14, 19-21, 24 | same, manifest may differ | Validate Event 24 noise |
| Server 2019 | verify | verify | verify | Provider manifests differ |

## Required checks before deployment

1. Confirm the deployed Sysmon config hash matches `telemetry/sysmon-config.xml`.
2. Confirm each rule's event ID and field exists in a clean baseline capture.
3. Confirm ETW providers are enabled and the collector is not blinded by patching.
4. Record the OS build in the fixture `captured_utc` context.

Missing builds are gaps, not assumptions.
