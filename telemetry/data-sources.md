# Data sources

A rule without a data source is a hypothesis, not a detection. This table maps
each technique to the telemetry required and the field the rule reads.

| Technique | Source | Event / provider | Field read | Status | Notes |
|---|---|---|---|---|---|
| AMSI patch T1562.001 | EDR memory telemetry / Sysmon 10 | `ProcessAccess` to `amsi.dll` | `TargetImage`, `GrantedAccess` | partial | Needs RWX-grant visibility; ETW patching may blind the collector |
| ETW patch T1562.001 | EDR memory telemetry / Sysmon 10 | `ProcessAccess` to `ntdll.dll` | `TargetImage`, `GrantedAccess` | partial | Same caveat as AMSI |
| WMI persistence T1546.003 | Sysmon | 19 / 20 / 21 | `EventType`, `User`, `Name`, `CommandLine` | ready | Enable in sysmon-config.xml |
| Run key T1547.001 | Sysmon | 12 / 13 / 14 | `TargetObject` | ready | — |
| Scheduled task T1053.005 | Sysmon + Security | 1 / 4698 | `Image`, `CommandLine` | ready | — |
| Startup folder T1547.001 | Sysmon | 11 | `TargetFilename` | ready | — |
| PyInstaller staging T1027.002 | Sysmon | 1 / 11 | `Image`, `TargetFilename` containing `_MEI` | ready | — |
| DGA DNS T1568.002 | Zeek DNS / Windows DNS | `dns.log`, NXDOMAIN | `query`, `rcode`, `id.orig_h` | ready | Requires DNS telemetry |
| Custom-header C2 T1071.001 | Proxy / SWG | request log | `cs-header-X-Id`, `cs-header-X-Seq`, `cs-uri-query` | partial | Depends on header retention |
| Beacon periodicity T1071.001 | Proxy / netflow | correlation | `SourceAddress`, `DestinationHostname`, timestamps | partial | Sigma correlation backend support varies |
| Credential file access T1555.003 | Sysmon | 10 / 11 | `TargetFilename` | partial | Needs File/ProcessAccess config enabled |
| autorun.inf write T1091 | Sysmon | 11 | `TargetFilename` | ready | — |
| `net view` discovery T1135 | Sysmon | 1 | `CommandLine`, `Image` | ready | — |
| **Keylogger T1056.001** | ETW `Microsoft-Windows-Win32k` / API sensor | keyboard device open / `GetAsyncKeyState` pattern | device object path, process, timing | **gap** | No native Windows log. Needs ETW or API-hook sensor |
| **Clipboard T1115** | Sysmon 24 `ClipboardChange` | event 24 | `Image`, `Session`, `TargetImage` | **gap** | Off by default and noisy; enable in sysmon config |
| **Screenshot T1113** | File artifact / API sensor | `%TEMP%\*.bmp` creation | 54-byte BMP header, resolution, no EXIF | **gap** | No host log source; static artifact rule first |
| **Anti-analysis T1497** | Object Access audit + SACL | `ProcessorNameString` registry read | `ObjectName`, `ProcessId` | **gap** | Requires SACL on HKLM CPU key; API sensor for sleep-skew |
| **USB insertion T1200/T1091** | ETW `DriverFrameworks-UserMode` / DeviceSetupManager | 400 / 410 | device instance ID, timestamp | **gap** | Needed to tie a write to a plug event |
| Mutex T1547-adjacent | EDR handle telemetry | mutex create | mutex name, creating process | **gap** | No native log source |
| TLS fingerprint T1071.001 | Zeek SSL / Suricata JA3 | `ssl.log` JA3, `x509` | JA3 hash, cert subject, self-signed flag | **gap** | Add to network rules |
