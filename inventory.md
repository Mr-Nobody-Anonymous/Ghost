# Behavior inventory

Versioned inventory of behaviors and the detection that addresses each. Marked
`no native telemetry` where no practical host log source exists.

| Layer | Behavior | ATT&CK | Detection | Status |
|---|---|---|---|---|
| Stage 0 | unsigned PE in temp/Downloads, IP-literal HTTPS, HMAC+zip exec, sys.path mutation | T1105/T1027.002 | `dropper_unsigned_temp_exec.yml`, YARA `Stage_Dropper_Fetcher` | rule drafted, not proven |
| Stage 1 | pythonw/pyi parent spawning shell/task tools, `_MEI` extraction | T1059/T1027.002 | `python_parent_child_shape.yml`, `pyinstaller_onefile_execution.yml` | rule drafted |
| Stage 1 | single-instance mutex create/handle check | T1547-adjacent | — | no native telemetry; EDR handle sensor needed |
| Triage | debugger check, tick skew, CPU key read, memory/drive checks, USERNAME compare | T1497 | `cpu_info_read.yml`, `fixtures/malicious/T1497.json` | partial; sequence rule needed |
| Evasion | LoadLibrary amsi, VirtualProtect+memmove, AmsiScanBuffer/EtwEventWrite patch | T1562.001 | `amsi_etw_patch.yml`, `patch_sequence.yml` | rule drafted, no host telemetry proof |
| Persistence | Run key | T1547.001 | `run_key_write.yml` | drafted |
| Persistence | schtasks /Create ONLOGON | T1053.005 | `schtask_onlogon.yml` | drafted |
| Persistence | WMI triple create | T1546.003 | `wmi_subscription_triple.yml` | drafted |
| Persistence | Startup folder .cmd | T1547.001 | `startup_folder_cmd.yml` | drafted |
| C2 | UA/content-type/X-Id/X-Seq/poll/register/result, 204, self-signed cert, CERT_NONE | T1071.001 | `beacon_custom_headers.yml`, `beaconing_frequency.yml`, Suricata rules, `network/ja3-x509.md` | drafted; jitter-aware analytics needed |
| Runtime | shell/sleep/update/kill self-delete | T1059/T1070 | — | no native telemetry |
| Collection | keylog polling + `kl.enc` | T1056.001 | `keylog_encrypted_file.yml`, gap fixture | drafted, no telemetry proof |
| Collection | clipboard delta hash | T1115 | gap fixture | no rule |
| Collection | GDI BitBlt -> `%TEMP%\shot.bmp` | T1113 | `screenshot_bmp_artifact.yml` | drafted |
| Collection | DPAPI + Local State + SQLite copy + BCryptDecrypt | T1555.003 | `credential_file_access.yml`, `sqlite_temp_copy.yml` | drafted |
| Collection | wallet/docs zip | T1533 | `credential_file_access.yml`, `files.py` zip gap | partial |
| Spread | drive enum, svc_update.exe, autorun.inf, net view | T1091/T1135 | `autorun_inf_writes.yml`, `net_view_recon.yml` | drafted |
| Recon | ipify egress, SecurityCenter2 WMI query | T1592.002 | `ipify_egress.yml`, `wmi_recon_command.yml` | drafted |
| DGA | daily domain set, NXDOMAIN fallback | T1568.002 | `dga_high_entropy_dns.yml` | drafted |

## Single-sourced techniques

Network-only detections with no host twin: C2 headers, beacon periodicity, JA3,
x509, ipify egress, DGA DNS. If the proxy or DNS feed is removed, these die
silently. Mark them `single-sourced` in the matrix and add a host-side twin where
possible (e.g. process creating the connection).
