# Behavior inventory

Versioned inventory of behaviors and the detection that addresses each. A rule,
the telemetry it needs, and whether either has been proven are three different
claims; the Status column states which one holds.

| Layer | Behavior | ATT&CK | Detection | Status |
|---|---|---|---|---|
| Stage 0 | unsigned PE from temp/Downloads, IP-literal HTTPS, `sys.path` mutation | T1105 / T1027.002 | `dropper_unsigned_temp_exec.yml`, YARA `Stage_Dropper_Fetcher` | rule converts on all backends; no capture |
| Stage 1 | pythonw/pyi parent spawning shell/task tools | T1059 / T1053.005 | `python_parent_child_shape.yml` | rule converts on all backends; no capture |
| Stage 1 | PyInstaller `_MEI` extraction directory | T1027.002 | `mei_extraction_dir.yml`, `pyinstaller_onefile_execution.yml` | rules convert; no capture |
| Stage 1 | single-instance mutex create | T1547-adjacent | `mutex_single_instance.yml` | **telemetry gap**: no native Windows log; needs an EDR handle sensor |
| Triage | CPU key read, debugger/tick/RAM checks | T1497 | `cpu_info_read.yml` + `patch_sequence.yml` | rule converts; needs a SACL on the CPU key. Tick skew and debugger checks have **no telemetry** |
| Evasion | AMSI `AmsiScanBuffer` patch | T1685 | `amsi_etw_patch.yml`, `patch_sequence.yml` | **telemetry gap**: Sysmon 10 targets processes, not loaded modules. Needs EDR memory telemetry |
| Evasion | ETW `EtwEventWrite` patch | T1685 | `amsi_etw_patch.yml` | same gap; ETW patching also blinds the collector |
| Evasion | security component stopped / AMSI provider removed | T1685 | `security_component_tamper.yml` | rule converts on all backends; first member of the tamper sequence |
| Persistence | Run key | T1547.001 | `run_key_write.yml` | rule converts; no capture |
| Persistence | `schtasks /Create /SC ONLOGON` | T1053.005 | `schtask_onlogon.yml` | rule converts; no capture |
| Persistence | WMI filter + consumer + binding | T1546.003 | `wmi_subscription_triple.yml` + 3 member rules | sequence converts on Splunk only; no capture |
| Persistence | Startup folder script | T1547.001 | `startup_folder_cmd.yml` | rule converts; no capture |
| C2 | `X-Id`/`X-Seq` headers, `/poll?id=&seq=`, browser UA | T1071.001 | `beacon_custom_headers.yml`, Suricata 9001001-9001003 | **header retention unproven**; the proxy export must keep custom headers |
| C2 | jittered long-poll periodicity | T1071.001 | `beaconing_frequency.yml`, `beacon_interval_shift.yml` | count correlation converts on Splunk only; **jitter/variance analytics not implemented** |
| C2 | self-signed TLS, `CERT_NONE`, JA3 | T1071.001 | `host_selfsigned_tls.yml`, `network/ja3-x509.md` | **telemetry gap** for the host half; the JA3 script is unexercised |
| C2 | DGA fallback, NXDOMAIN burst | T1568.002 | `dga_high_entropy_dns.yml`, `nxdomain_long_label.yml`, `dns_query_burst_host.yml` | converts (Splunk for the correlation); requires DNS telemetry |
| Collection | keylog polling -> `kl.enc` | T1056.001 | `keylog_encrypted_file.yml` | file-write artifact only; **the polling itself has no telemetry** |
| Collection | clipboard delta hash | T1115 | - | **no rule, no telemetry**: Sysmon 24 is not enabled in the lab config |
| Collection | GDI `BitBlt` -> `%TEMP%\shot.bmp` | T1113 | `screenshot_bmp_artifact.yml` | file artifact only; no API telemetry |
| Collection | DPAPI + `Local State` + SQLite copy | T1555.003 | `credential_file_access.yml`, `sqlite_temp_copy.yml` | **Sysmon does not log file reads**; detects create/modify, not a stealthy read |
| Collection | wallet / document archive | T1005 | `credential_file_access.yml` | partial; archive creation itself is not detected |
| Spread | drive enumeration, `svc_update.exe`, `autorun.inf` | T1091 | `autorun_inf_writes.yml` | **USB insertion telemetry absent**, so a write cannot be tied to a plug event |
| Recon | public-IP echo service | T1592.002 | `ipify_egress.yml` | network-only; single-sourced |
| Recon | `SecurityCenter2` AV enumeration | T1592.002 | `wmi_recon_command.yml` | rule converts; no capture |
| Recon | `net view` share enumeration | T1135 | `net_view_recon.yml` | rule converts; no capture |
| Self-delete | process deletes its own image | T1070.004 | `self_delete.yml` | converts on Splunk only (`fieldref`); FileDelete is Sysmon 26, not 23 |

## Coverage arithmetic

37 rules, 18 distinct ATT&CK techniques. Every rule converts
on at least one backend; `attack/matrix.md` carries the per-backend result.
**No rule has a captured fixture**, so no technique is *covered* under the
definition in `docs/maturity.md` - that definition is ten gates, not one.

## Single-sourced techniques

Network-only detections with no host twin: C2 headers, beacon periodicity, JA3,
x509, ipify egress, DGA DNS. If the proxy or DNS feed is removed, these die
silently. Each is marked `single-sourced` in the matrix.

## Behaviors with no practical telemetry

Recorded as gaps rather than papered over with rules that cannot fire:

- keylogging and clipboard polling (no native Windows log)
- screenshot capture (no API sensor; only the file artifact)
- AMSI/ETW patching as seen by Sysmon (it cannot target loaded modules)
- single-instance mutex creation (EDR handle telemetry only)
- USB insertion, to pair with the `autorun.inf` write
