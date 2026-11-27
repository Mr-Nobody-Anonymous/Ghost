# Attack matrix (generated)

Generated from rule metadata and attack/conversion.json. Do not edit by hand - run tools/generate_matrix.py.

Rules: 38 | distinct techniques: 18 | tactics used: 12 of the pinned set (not counted as techniques)

| Technique | Rule | Source | Lifecycle | Level | Fixture | Pin | Flags |
|---|---|---|---|---|---|---|---|
| T1005 | [Access to Browser Credential Stores and Wallet Vaults](sigma/credential_file_access.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1027.002 | [PyInstaller Onefile Staging Directory Execution](sigma/pyinstaller_onefile_execution.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1027.002 | [PyInstaller _MEI Extraction Directory Created](sigma/windows/file/mei_extraction_dir.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1027.002 | [Executable Launched from User-Writable Path with No Signer](sigma/windows/process/dropper_unsigned_temp_exec.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1053.005 | [Run Key, Scheduled Task, or Startup Folder Persistence](sigma/runkey_schtask_startup_persistence.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1053.005 | [Scheduled Task Created at Logon by Unusual Parent](sigma/windows/persistence/schtask_onlogon.yml) | host | experimental | high | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a02.json | PIN-0000 | - |
| T1053.005 | [Python Interpreter Spawning Shell or Task Tools](sigma/windows/process/python_parent_child_shape.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1056.001 | [Encrypted Keylog Staging File Appended in Temp](sigma/windows/file/keylog_encrypted_file.yml) | host | experimental | low | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a0a.json | PIN-0000 | - |
| T1059 | [Python Interpreter Spawning Shell or Task Tools](sigma/windows/process/python_parent_child_shape.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1070.004 | [Self-Deleting Executable](sigma/windows/file/self_delete.yml) | host | experimental | high | MISSING | PIN-0000 | - |
| T1071.001 | [Beacon with Custom X-Id / X-Seq Headers](sigma/beacon_custom_headers.yml) | network | experimental | high | MISSING | PIN-0000 | single-sourced |
| T1071.001 | [Beaconing - High Request Frequency with Regular Intervals](sigma/beaconing_frequency.yml) | network | experimental | medium | MISSING | PIN-0000 | single-sourced, conversion-risk |
| T1071.001 | [Beacon Interval Shift After Configuration Change](sigma/network/netflow/beacon_interval_shift.yml) | host | experimental | low | MISSING | PIN-0000 | - |
| T1071.001 | [Generic Browser UA with No Accept-Language or Cookie Header](sigma/network/proxy/ua_anomaly.yml) | network | experimental | medium | MISSING | PIN-0000 | single-sourced |
| T1071.001 | [Process TLS Session to Self-Signed Certificate on 443](sigma/windows/network/host_selfsigned_tls.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1091 | [autorun.inf Written Outside Trusted Install Paths](sigma/autorun_inf_writes.yml) | host | experimental | high | MISSING | PIN-0000 | - |
| T1091 | [Removable-Media Spreader Writes Executable and autorun.inf](sigma/windows/process/removable_media_spreader_write.yml) | host | experimental | low | fixtures/per_rule/3570d46e-6cdb-4c0b-8886-972ce382f63a.json | PIN-0000 | - |
| T1105 | [Executable Overwritten in a User-Writable Install Directory](sigma/windows/file/self_update_rewrite.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1105 | [Executable Launched from User-Writable Path with No Signer](sigma/windows/process/dropper_unsigned_temp_exec.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1105 | [Removable-Media Spreader Writes Executable and autorun.inf](sigma/windows/process/removable_media_spreader_write.yml) | host | experimental | low | fixtures/per_rule/3570d46e-6cdb-4c0b-8886-972ce382f63a.json | PIN-0000 | - |
| T1113 | [Screen-Sized BMP Written to Temp Directory](sigma/windows/file/screenshot_bmp_artifact.yml) | host | experimental | medium | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a08.json | PIN-0000 | - |
| T1135 | [Internal Reconnaissance via net view and SecurityCenter2 Queries](sigma/net_view_recon.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1497 | [CPU Information Enumeration Followed by Security Tool Tampering](sigma/windows/defense-evasion/patch_sequence.yml) | host | experimental | medium | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a05.json | PIN-0000 | conversion-risk |
| T1497 | [ProcessorNameString Registry Read via Object Access Audit](sigma/windows/registry/cpu_info_read.yml) | host | experimental | low | fixtures/per_rule/4663b1a0-0000-4000-8000-000000000001.json | PIN-0000 | - |
| T1546.003 | [WMI Filter-to-Consumer Binding Created Under root\subscription](sigma/windows/persistence/wmi_binding_create.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1546.003 | [WMI Command-Line Event Consumer Created Under root\subscription](sigma/windows/persistence/wmi_consumer_create.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1546.003 | [WMI Event Filter Created Under root\subscription](sigma/windows/persistence/wmi_filter_create.yml) | host | experimental | low | MISSING | PIN-0000 | - |
| T1546.003 | [WMI Event Subscription Triple Create](sigma/windows/persistence/wmi_subscription_triple.yml) | host | experimental | high | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a03.json | PIN-0000 | conversion-risk |
| T1546.003 | [WMI Event Subscription Persistence](sigma/wmi_event_subscription_persistence.yml) | host | experimental | high | MISSING | PIN-0000 | - |
| T1547.001 | [autorun.inf Written Outside Trusted Install Paths](sigma/autorun_inf_writes.yml) | host | experimental | high | MISSING | PIN-0000 | - |
| T1547.001 | [Run Key, Scheduled Task, or Startup Folder Persistence](sigma/runkey_schtask_startup_persistence.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1547.001 | [Run Key Write by Non-Installer Process](sigma/windows/persistence/run_key_write.yml) | host | experimental | high | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a01.json | PIN-0000 | - |
| T1547.001 | [Script Written to User Startup Folder](sigma/windows/persistence/startup_folder_cmd.yml) | host | experimental | medium | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a04.json | PIN-0000 | - |
| T1547.001 | [Named Mutex Created by Unsigned Temp Process](sigma/windows/process/mutex_single_instance.yml) | host | experimental | low | MISSING | PIN-0000 | - |
| T1555.003 | [Access to Browser Credential Stores and Wallet Vaults](sigma/credential_file_access.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1555.003 | [SQLite Database Copied to Random Temp Filename](sigma/windows/file/sqlite_temp_copy.yml) | host | experimental | medium | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a09.json | PIN-0000 | - |
| T1568.002 | [Possible DGA - High Entropy Labels and NXDOMAIN Burst](sigma/dga_high_entropy_dns.yml) | host | experimental | medium | MISSING | PIN-0000 | conversion-risk |
| T1568.002 | [NXDOMAIN Response for a Long High-Entropy Label](sigma/network/dns/nxdomain_long_label.yml) | network | experimental | low | MISSING | PIN-0000 | single-sourced |
| T1568.002 | [Host Process Resolving Many Random Labels](sigma/windows/process/dns_query_burst_host.yml) | host | experimental | medium | MISSING | PIN-0000 | conversion-risk |
| T1568.002 | [Process Resolves a Random-Looking Label](sigma/windows/process/dns_random_label_query.yml) | host | experimental | low | MISSING | PIN-0000 | - |
| T1592.002 | [Internal Reconnaissance via net view and SecurityCenter2 Queries](sigma/net_view_recon.yml) | host | experimental | medium | MISSING | PIN-0000 | - |
| T1592.002 | [Public IP Discovery Service Egress from Unexpected Process](sigma/windows/network/ipify_egress.yml) | network | experimental | medium | MISSING | PIN-0000 | single-sourced |
| T1592.002 | [Security Product Enumeration via SecurityCenter2](sigma/windows/process/wmi_recon_command.yml) | host | experimental | medium | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a0c.json | PIN-0000 | - |
| T1685 | [AMSI or ETW Function Patch (Process Access to ntdll/amsi)](sigma/amsi_etw_patch.yml) | host | experimental | high | MISSING | PIN-0000 | - |
| T1685 | [CPU Information Enumeration Followed by Security Tool Tampering](sigma/windows/defense-evasion/patch_sequence.yml) | host | experimental | medium | fixtures/per_rule/1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a05.json | PIN-0000 | conversion-risk |
| T1685 | [Security Component Stopped or Unregistered by Command Line](sigma/windows/defense-evasion/security_component_tamper.yml) | host | experimental | high | MISSING | PIN-0000 | - |

A technique is covered only when telemetry, rule, compilation, TP fixture, and FP corpus all pass. See `docs/maturity.md`.

## Tactic coverage against ATT&CK 20.1

12 of 15 pinned tactics have at least one rule. A tactic with no rule is a blind spot, not a gap in the rule set's quality.

| Tactic | Rules |
|---|---|
| collection | 3 |
| command-and-control | 12 |
| credential-access | 3 |
| defense-impairment | 3 |
| discovery | 3 |
| execution | 3 |
| exfiltration | **0** |
| impact | **0** |
| initial-access | 2 |
| lateral-movement | 2 |
| persistence | 12 |
| privilege-escalation | 12 |
| reconnaissance | 3 |
| resource-development | **0** |
| stealth | 6 |

## Deployability (generated from ci/convert_check.py)

Conversion stamp: sha256:81769166669d8a69. A rule is only deployable where the backend is `supported`.

| Rule | splunk | elastic | kusto |
|---|---|---|---|
| [sigma/amsi_etw_patch.yml](sigma/amsi_etw_patch.yml) | yes | yes | yes |
| [sigma/autorun_inf_writes.yml](sigma/autorun_inf_writes.yml) | yes | yes | yes |
| [sigma/beacon_custom_headers.yml](sigma/beacon_custom_headers.yml) | yes | yes | yes |
| [sigma/beaconing_frequency.yml](sigma/beaconing_frequency.yml) | yes | **no** | **no** |
| [sigma/credential_file_access.yml](sigma/credential_file_access.yml) | yes | yes | yes |
| [sigma/dga_high_entropy_dns.yml](sigma/dga_high_entropy_dns.yml) | yes | **no** | **no** |
| [sigma/net_view_recon.yml](sigma/net_view_recon.yml) | yes | yes | yes |
| [sigma/network/dns/nxdomain_long_label.yml](sigma/network/dns/nxdomain_long_label.yml) | yes | yes | yes |
| [sigma/network/netflow/beacon_interval_shift.yml](sigma/network/netflow/beacon_interval_shift.yml) | yes | yes | yes |
| [sigma/network/proxy/ua_anomaly.yml](sigma/network/proxy/ua_anomaly.yml) | yes | yes | yes |
| [sigma/pyinstaller_onefile_execution.yml](sigma/pyinstaller_onefile_execution.yml) | yes | yes | yes |
| [sigma/runkey_schtask_startup_persistence.yml](sigma/runkey_schtask_startup_persistence.yml) | yes | yes | yes |
| [sigma/windows/defense-evasion/patch_sequence.yml](sigma/windows/defense-evasion/patch_sequence.yml) | yes | **no** | **no** |
| [sigma/windows/defense-evasion/security_component_tamper.yml](sigma/windows/defense-evasion/security_component_tamper.yml) | yes | yes | yes |
| [sigma/windows/file/keylog_encrypted_file.yml](sigma/windows/file/keylog_encrypted_file.yml) | yes | yes | yes |
| [sigma/windows/file/mei_extraction_dir.yml](sigma/windows/file/mei_extraction_dir.yml) | yes | yes | yes |
| [sigma/windows/file/screenshot_bmp_artifact.yml](sigma/windows/file/screenshot_bmp_artifact.yml) | yes | yes | yes |
| [sigma/windows/file/self_delete.yml](sigma/windows/file/self_delete.yml) | yes | **no** | **no** |
| [sigma/windows/file/self_update_rewrite.yml](sigma/windows/file/self_update_rewrite.yml) | yes | yes | yes |
| [sigma/windows/file/sqlite_temp_copy.yml](sigma/windows/file/sqlite_temp_copy.yml) | yes | yes | yes |
| [sigma/windows/network/host_selfsigned_tls.yml](sigma/windows/network/host_selfsigned_tls.yml) | yes | yes | yes |
| [sigma/windows/network/ipify_egress.yml](sigma/windows/network/ipify_egress.yml) | yes | yes | yes |
| [sigma/windows/persistence/run_key_write.yml](sigma/windows/persistence/run_key_write.yml) | yes | yes | yes |
| [sigma/windows/persistence/schtask_onlogon.yml](sigma/windows/persistence/schtask_onlogon.yml) | yes | yes | yes |
| [sigma/windows/persistence/startup_folder_cmd.yml](sigma/windows/persistence/startup_folder_cmd.yml) | yes | yes | yes |
| [sigma/windows/persistence/wmi_binding_create.yml](sigma/windows/persistence/wmi_binding_create.yml) | yes | yes | yes |
| [sigma/windows/persistence/wmi_consumer_create.yml](sigma/windows/persistence/wmi_consumer_create.yml) | yes | yes | yes |
| [sigma/windows/persistence/wmi_filter_create.yml](sigma/windows/persistence/wmi_filter_create.yml) | yes | yes | yes |
| [sigma/windows/persistence/wmi_subscription_triple.yml](sigma/windows/persistence/wmi_subscription_triple.yml) | yes | **no** | **no** |
| [sigma/windows/process/dns_query_burst_host.yml](sigma/windows/process/dns_query_burst_host.yml) | yes | **no** | **no** |
| [sigma/windows/process/dns_random_label_query.yml](sigma/windows/process/dns_random_label_query.yml) | yes | yes | yes |
| [sigma/windows/process/dropper_unsigned_temp_exec.yml](sigma/windows/process/dropper_unsigned_temp_exec.yml) | yes | yes | yes |
| [sigma/windows/process/mutex_single_instance.yml](sigma/windows/process/mutex_single_instance.yml) | yes | yes | yes |
| [sigma/windows/process/python_parent_child_shape.yml](sigma/windows/process/python_parent_child_shape.yml) | yes | yes | yes |
| [sigma/windows/process/removable_media_spreader_write.yml](sigma/windows/process/removable_media_spreader_write.yml) | yes | yes | yes |
| [sigma/windows/process/wmi_recon_command.yml](sigma/windows/process/wmi_recon_command.yml) | yes | yes | yes |
| [sigma/windows/registry/cpu_info_read.yml](sigma/windows/registry/cpu_info_read.yml) | yes | yes | yes |
| [sigma/wmi_event_subscription_persistence.yml](sigma/wmi_event_subscription_persistence.yml) | yes | yes | yes |

Totals: splunk 38/38, elastic 32/38, kusto 32/38
