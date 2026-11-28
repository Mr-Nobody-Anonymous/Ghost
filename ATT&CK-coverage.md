# ATT&CK coverage map

Coverage of the behaviors in the described implant design. "Primary telemetry" is
the data source a detection needs; "Rule" points at the file in this folder.

| Behavior | ATT&CK | Primary telemetry | Rule | Coverage |
|---|---|---|---|---|
| AMSI function patch (`AmsiScanBuffer`) | T1685 | EDR memory scan (Sysmon 10 **cannot** see loaded modules) | `sigma/amsi_etw_patch.yml` | **Gap for Sysmon** — needs EDR memory-write telemetry |
| ETW function patch (`EtwEventWrite`) | T1685 | Same, with `ntdll.dll` as target | `sigma/amsi_etw_patch.yml` | Partial — ETW silencing can also blind the collector itself |
| VM/sandbox triage (sleep skew, CPU/RAM/disk checks) | T1497.001 | Process behavior, timing anomalies, EDR self-protection | `sigma/windows/registry/cpu_info_read.yml` (CPU key read only) | **Partial** — tick skew and debugger checks have no telemetry |
| Single-instance mutex | T1547 / T1190-adjacent | Object handles, EDR | `sigma/windows/process/mutex_single_instance.yml` | **Gap** — rule exists, no telemetry produces it |
| Run-key persistence | T1547.001 | Sysmon 12/13/14, Security 4656/4663 on SAM | `sigma/runkey_schtask_startup_persistence.yml` | Good |
| Scheduled task persistence | T1053.005 | Sysmon 1 (`schtasks.exe /Create`), Security 4698/4699/4702 | `sigma/runkey_schtask_startup_persistence.yml` | Good |
| WMI event subscription persistence | T1546.003 | Sysmon 19/20/21, `root\subscription` changes, Security 4662/5136 | `sigma/wmi_event_subscription_persistence.yml` | Good |
| Startup folder persistence | T1547.001 | Sysmon 11 file create in Startup path | `sigma/runkey_schtask_startup_persistence.yml` | Good |
| PyInstaller onefile staging (`_MEIxxxx`) | T1027.002 | Sysmon 1 from `%TEMP%\_MEI*` | `sigma/pyinstaller_onefile_execution.yml` | Good |
| Encrypted string constants / CTR+HMAC config | T1027 | Static only; no runtime telemetry | `yara/ghost_implant_structural.yar` | Partial — static detection, evades once packed/rebuilt |
| DGA domain fallback | T1568.002 | DNS logs (Zeek/Windows DNS), NXDOMAIN volume, label entropy | `sigma/dga_high_entropy_dns.yml` | Good with DNS telemetry; **gap** without it |
| Authenticated C2 over HTTPS with `X-Id`/`X-Seq` | T1071.001 | Proxy/SWG headers, TLS SNI, JA3/JA4, netflow | `sigma/beacon_custom_headers.yml` | Partial — depends on header visibility |
| Jittered long-poll beacon | T1071.001 / T1102 | Netflow periodicity, proxy request timing | `sigma/beaconing_frequency.yml` | Partial — Sigma correlation support varies by backend; validate before deploy |
| Browser DPAPI/CNG credential access | T1555.003 | Sysmon 10 access to `Local State`/`Login Data`, EDR file access | `sigma/credential_file_access.yml`, `yara/browser_credential_artifacts.yar` | Partial — rule needs Sysmon process-access telemetry enabled |
| Wallet file collection | T1555 / T1005 | File access telemetry in wallet paths | `sigma/credential_file_access.yml` | Partial — covers Exodus/Electrum/Ledger paths; extension vaults need tuning |
| Keylogger (`GetAsyncKeyState` polling) | T1056.001 | EDR API telemetry / process behavior | `sigma/windows/file/keylog_encrypted_file.yml` | **Partial** - the staging file, not the polling |
| Clipboard capture | T1115 | EDR API telemetry | — | **Gap** - Sysmon 24 not enabled in the lab config |
| Screenshot capture (GDI `BitBlt`) | T1113 | EDR behavioral detection, file creation of BMP | `sigma/windows/file/screenshot_bmp_artifact.yml` | **Partial** - the BMP artifact only; the API call leaves no log |
| Removable-media spread / `autorun.inf` | T1091 / T1547.001 | Sysmon 11 on removable volumes, USB events | `sigma/autorun_inf_writes.yml` | Partial — detects the file write; USB insertion telemetry still needed |
| SMB share enumeration (`net view`) | T1135 | Sysmon 1 `net.exe`, 4624 type 3 | `sigma/net_view_recon.yml` | Good |

## Priority order for remaining gaps

1. Keylogger/clipboard/screenshot: EDR API telemetry — no practical log-only rule.
2. VM/sandbox triage and sleep-skew: behavioral/anti-evasion EDR only.
3. EDR memory-protection alerts for `VirtualProtect`/`NtProtectVirtualMemory`
   on `ntdll.dll` and `amsi.dll` (the Sigma rule depends on this telemetry).
4. DNS entropy + NXDOMAIN burst correlation per host.
5. USB device insertion telemetry to pair with the `autorun.inf` write.

See `hunt-queries.md` for manual queries covering several of these.

## How to read this table

"Telemetry" is what would have to exist. A rule in the Rule column converts and
is tested against a generated fixture; that is not the same as that telemetry
existing. `inventory.md` states per behavior whether the rule, the telemetry, or
neither has been proven. Nothing here has been captured from a live host yet.
