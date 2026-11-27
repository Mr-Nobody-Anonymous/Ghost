# Attack matrix (generated)

Generated 2026-11-27T13:26:56.159698+00:00 from `sigma/` rule tags. Do not edit by hand.

| Technique | Rule | Status | Level | Fixture | Sample pin |
|---|---|---|---|---|---|
| T1027.002 | [PyInstaller Onefile Staging Directory Execution](sigma/pyinstaller_onefile_execution.yml) | experimental | medium | MISSING | none |
| T1027.002 | [Unsigned Executable Launched from User-Writable Path with No DNS](sigma/windows/process/dropper_unsigned_temp_exec.yml) | experimental | medium | MISSING | none |
| T1053.005 | [Run Key, Scheduled Task, or Startup Folder Persistence](sigma/runkey_schtask_startup_persistence.yml) | experimental | medium | automatic | none |
| T1053.005 | [Scheduled Task Created at Logon by Unusual Parent](sigma/windows/persistence/schtask_onlogon.yml) | experimental | high | fixtures/malicious/T1053.005.json | none |
| T1053.005 | [Python Interpreter Spawning Shell or Task Tools](sigma/windows/process/python_parent_child_shape.yml) | experimental | medium | automatic | none |
| T1056.001 | [Encrypted Keylog Staging File Appended in Temp](sigma/windows/file/keylog_encrypted_file.yml) | experimental | low | fixtures/malicious/T1056.001.json | none |
| T1059 | [Python Interpreter Spawning Shell or Task Tools](sigma/windows/process/python_parent_child_shape.yml) | experimental | medium | MISSING | none |
| T1071.001 | [Beacon with Custom X-Id / X-Seq Headers](sigma/beacon_custom_headers.yml) | experimental | high | MISSING | none |
| T1071.001 | [Beaconing - High Request Frequency with Regular Intervals](sigma/beaconing_frequency.yml) | experimental | medium | MISSING | none |
| T1091 | [autorun.inf Written Outside Trusted Install Paths](sigma/autorun_inf_writes.yml) | experimental | high | automatic | none |
| T1105 | [Unsigned Executable Launched from User-Writable Path with No DNS](sigma/windows/process/dropper_unsigned_temp_exec.yml) | experimental | medium | MISSING | none |
| T1113 | [Screen-Sized BMP Written to Temp Directory](sigma/windows/file/screenshot_bmp_artifact.yml) | experimental | medium | fixtures/malicious/T1113.json | none |
| T1135 | [Internal Reconnaissance via net view and SecurityCenter2 Queries](sigma/net_view_recon.yml) | experimental | medium | MISSING | none |
| T1497 | [Anti-Analysis Triage Followed by AMSI or ETW Patch](sigma/windows/defense-evasion/patch_sequence.yml) | experimental | high | fixtures/malicious/T1562.001-sequence.json | none |
| T1497 | [ProcessorNameString Registry Read via Object Access Audit](sigma/windows/registry/cpu_info_read.yml) | experimental | low | fixtures/malicious/T1497.json | none |
| T1533 | [Access to Browser Credential Stores and Wallet Vaults](sigma/credential_file_access.yml) | experimental | medium | MISSING | none |
| T1546.003 | [WMI Event Subscription Triple Create](sigma/windows/persistence/wmi_subscription_triple.yml) | experimental | high | fixtures/malicious/T1546.003.json | none |
| T1546.003 | [WMI Event Subscription Persistence](sigma/wmi_event_subscription_persistence.yml) | stable | high | automatic | none |
| T1547.001 | [autorun.inf Written Outside Trusted Install Paths](sigma/autorun_inf_writes.yml) | experimental | high | MISSING | none |
| T1547.001 | [Run Key, Scheduled Task, or Startup Folder Persistence](sigma/runkey_schtask_startup_persistence.yml) | experimental | medium | MISSING | none |
| T1547.001 | [Run Key Write by Non-Installer Process](sigma/windows/persistence/run_key_write.yml) | experimental | high | fixtures/malicious/T1547.001-runkey.json | none |
| T1547.001 | [Script Written to User Startup Folder](sigma/windows/persistence/startup_folder_cmd.yml) | experimental | medium | fixtures/malicious/T1547.001-startup.json | none |
| T1555.003 | [Access to Browser Credential Stores and Wallet Vaults](sigma/credential_file_access.yml) | experimental | medium | MISSING | none |
| T1555.003 | [SQLite Database Copied to Random Temp Filename](sigma/windows/file/sqlite_temp_copy.yml) | experimental | medium | fixtures/malicious/T1555.003.json | none |
| T1562.001 | [AMSI or ETW Function Patch (Process Access to ntdll/amsi)](sigma/amsi_etw_patch.yml) | experimental | high | MISSING | none |
| T1562.001 | [Anti-Analysis Triage Followed by AMSI or ETW Patch](sigma/windows/defense-evasion/patch_sequence.yml) | experimental | high | fixtures/malicious/T1562.001-sequence.json | none |
| T1568.002 | [Possible DGA - High Entropy Labels and NXDOMAIN Burst](sigma/dga_high_entropy_dns.yml) | experimental | medium | MISSING | none |
| T1592.002 | [Internal Reconnaissance via net view and SecurityCenter2 Queries](sigma/net_view_recon.yml) | experimental | medium | MISSING | none |
| T1592.002 | [Public IP Discovery Service Egress from Unexpected Process](sigma/windows/network/ipify_egress.yml) | experimental | medium | MISSING | none |
| T1592.002 | [Security Product Enumeration via SecurityCenter2](sigma/windows/process/wmi_recon_command.yml) | experimental | medium | fixtures/malicious/T1592.002.json | none |

## Techniques with rules but no recorded fixture are unproven. See `docs/maturity.md`.
