# Data sources

A rule without a data source is a hypothesis, not a detection. This table maps
each technique to the telemetry required and the field the rule reads.

## Field contract

Every field a rule reads must appear in this table, with the event that carries
it. `pipeline/field_contract.py` enforces this: a rule that reads a field not
listed here fails the gate, because no amount of rule tuning makes an
uncollected field appear.

| Field | Event / source | Notes |
|---|---|---|
| `EventID` | Sysmon 1, 8, 10, 11, 12-14, 19-21, 22, 26; Security 4663 | always present |
| `Computer` | every event | the only join key shared by Sysmon and Security |
| `Image` | Sysmon 1, 26 | full path of the acting process |
| `ParentImage` | Sysmon 1 | full path of the parent process |
| `ParentCommandLine` | Sysmon 1 | requires command-line capture (default) |
| `CommandLine` | Sysmon 1 | full command line |
| `TargetFilename` | Sysmon 11, 26 | full path created/deleted |
| `TargetObject` | Sysmon 12-14 | registry key or value path |
| `Details` | Sysmon 13 | registry value data, e.g. `DWORD (0x00000001)` |
| `TargetImage` | Sysmon 10 (process access), Sysmon 8 (remote thread) | a **process image**, never a loaded module |
| `SourceImage` | Sysmon 10 | process requesting access |
| `GrantedAccess` | Sysmon 10 | e.g. `0x1F0FFF` |
| `Signature` | Sysmon 1, 11 | resolved signer; empty when Sysmon cannot verify |
| `IntegrityLevel` | Sysmon 1 | `Medium`, `High`, `System` |
| `ProcessGuid` | Sysmon 22 and all Sysmon events | per-boot process identity, the correct join key |
| `QueryName` | Sysmon 22 | DNS name queried |
| `EventType` | Sysmon 19-21 | `WmiFilterEvent`, `WmiConsumerEvent`, `WmiConsumerToFilterEvent` |
| `Type` | Sysmon 20 | consumer class, e.g. `CommandLineEventConsumer` |
| `ObjectName` | Security 4663 | registry or file object opened under a SACL |
| `AccessMask` | Security 4663 | `0x1` = read |
| `SourceAddress` | proxy / netflow | client address |
| `DestinationHostname` | proxy | hostname from the request line or CONNECT |
| `DestinationPort` | EDR TLS callback | 443 in this repo |
| `destination_port` | netflow | field name as exported by the flow collector |
| `Process` | proxy (where the export joins socket owner) | not always available |
| `cs-user-agent` | proxy | full UA string; `|startswith` on `Mozilla/5.0` |
| `cs-uri-stem` | proxy | path only, e.g. `/poll` |
| `cs-uri-query` | proxy | query string, e.g. `id=...&seq=3` |
| `cs-header-X-Id` | proxy | **requires full custom-header retention** |
| `cs-header-X-Seq` | proxy | as above; the pair is the strongest signal |
| `cs-header-Accept-Language` | proxy | as above; absence is the assertion |
| `cs-header-Cookie` | proxy | as above; absence is the assertion |
| `rcode` | Zeek `dns.log` | `NXDOMAIN`, `NOERROR` |
| `query` | Zeek `dns.log` | queried name |
| `Source` | Zeek `dns.log` | client address |
| `CertificateSelfSigned` | EDR TLS callback | boolean; derived, not raw |

## Technique map

| Technique | Source | Event / provider | Field read | Status | Notes |
|---|---|---|---|---|---|
| AMSI patch T1685 | EDR memory telemetry | in-process memory write to `amsi.dll` | module name, writing process | partial | Sysmon has no loaded-module targeting; needs EDR |
| ETW patch T1685 | EDR memory telemetry | in-process memory write to `ntdll.dll` | module name, writing process | partial | ETW patching may blind the collector itself |
| Security component tamper T1685 | Sysmon + Security | 1, 12-14 | `Image`, `CommandLine`, `TargetObject`, `Details` | ready | sc/net stop, AMSI provider delete, Defender prefs |
| WMI persistence T1546.003 | Sysmon | 19 / 20 / 21 | `EventType`, `Computer`, `Type` | ready | enabled in sysmon-config.xml |
| Run key T1547.001 | Sysmon | 12 / 13 / 14 | `TargetObject` | ready | — |
| Scheduled task T1053.005 | Sysmon + Security | 1 / 4698 | `Image`, `CommandLine` | ready | — |
| Startup folder T1547.001 | Sysmon | 11 | `TargetFilename` | ready | — |
| PyInstaller staging T1027.002 | Sysmon | 1 / 11 | `Image`, `TargetFilename` containing `_MEI` | ready | — |
| DGA DNS T1568.002 | Zeek DNS / Windows DNS | `dns.log`, NXDOMAIN | `query`, `rcode`, `Source` | ready | requires DNS telemetry |
| Custom-header C2 T1071.001 | Proxy / SWG | request log | `cs-header-X-Id`, `cs-header-X-Seq`, `cs-uri-query` | partial | depends on header retention |
| Beacon periodicity T1071.001 | Proxy / netflow | correlation | `SourceAddress`, `DestinationHostname`, timestamps | partial | converts to Splunk only |
| Credential file access T1555.003 | Sysmon | 11 / 12 | `TargetFilename`, `TargetObject` | partial | Sysmon does not log reads; see caveat below |
| autorun.inf write T1091 | Sysmon | 11 | `TargetFilename` | ready | — |

| Self-delete T1070.004 | Sysmon | 26 | `TargetFilename`, `Image` (`fieldref`) | ready | Splunk only; see rule conversion notes |
| **Keylogger T1056.001** | ETW `Microsoft-Windows-Win32k` / API sensor | keyboard device open / `GetAsyncKeyState` pattern | device object path, process, timing | **gap** | no native Windows log |
| **Clipboard T1115** | Sysmon 24 `ClipboardChange` | event 24 | `Image`, `Session` | **gap** | not enabled in the lab config; high volume |
| **Screenshot T1113** | File artifact / API sensor | `%TEMP%\*.bmp` creation | 54-byte BMP header, resolution | **gap** | artifact rule only; no API telemetry |
| **Anti-analysis T1497** | Object Access audit + SACL | `ProcessorNameString` registry read | `ObjectName`, `AccessMask` | partial | SACL read audit; no sleep-skew signal |
| **USB insertion T1200/T1091** | ETW `DriverFrameworks-UserMode` | 400 / 410 | device instance ID, timestamp | **gap** | needed to tie a write to a plug event |
| Mutex T1547-adjacent | EDR handle telemetry | mutex create | mutex name, creating process | **gap** | no native log source |
| TLS fingerprint T1071.001 | Zeek SSL / Suricata JA3 | `ssl.log` JA3, `x509` | JA3 hash, cert subject, self-signed flag | **gap** | network rule only |

## Known telemetry assumptions that do not hold

These were assumed by earlier drafts of the rules and are recorded here so they
are not re-introduced:

1. **Sysmon 10 does not see loaded modules.** `TargetImage` is a process image.
   Any rule that selects `TargetImage|endswith: '\amsi.dll'` can never fire.
   AMSI/ETW patching is in-process memory modification and produces no
   ProcessAccess event.
2. **Sysmon 23 is archiving, not deletion.** FileDelete is event 26 in Sysmon 15+.
3. **Sysmon does not log file reads.** `credential_file_access.yml` detects
   creation/modification of credential files, not a stealthy read of an existing
   one. Closing that needs the file-system audit policy or EDR file telemetry.
4. **4663 has no ProcessId that joins to Sysmon.** `ProcessId` in Security is
   the auditing process, not the accessing one. Correlations across the two
   logs must join on `Computer` (or a SACL-derived handle), never on `ProcessId`.
5. **Proxy header retention is optional in most exports.** If `cs-header-X-*`
   is stripped, the C2 rule is dead and the gap is in the export config.
