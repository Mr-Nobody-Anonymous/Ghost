# OS and Sysmon support matrix

Sysmon event IDs, their semantics, and ETW providers differ by Sysmon and
Windows version. A rule validated on one build can silently fail on another.
This table was previously wrong in a way that mattered: it listed event 24 as
available on every build while the lab config did not enable it, and it never
noted that FileDelete changed meaning.

## Sysmon version floor

The repo pins `sysmon_min_version: 13` on most rules and **15** where the rule
depends on the current FileDelete/FileCreate semantics.

| Event | Meaning | Introduced / changed | Rules depending on it |
|---|---|---|---|
| 1 | ProcessCreate (`Image`, `ParentImage`, `CommandLine`, `Signature`, `IntegrityLevel`) | 1.0; `Signature` requires signature checking | most process rules |
| 8 | CreateRemoteThread | 1.0 | `amsi_etw_patch.yml` (remote-thread branch) |
| 10 | ProcessAccess (`SourceImage` -> `TargetImage`) | 1.0 | `amsi_etw_patch.yml` |
| 11 | FileCreate | 1.0; `Archived` in 7.4+ | file rules |
| 12-14 | RegistryEvent add/delete, value set, rename | 1.0 | persistence, tamper |
| 19-21 | WMI filter / consumer / binding | 4.0 | WMI rules |
| 22 | DnsQuery | 10.0 | DGA host rule |
| **23** | **Archived** file (FileDelete with archive) | 7.4 | **not used** - it is not a plain delete |
| **26** | FileDelete | **11.0** | `self_delete.yml` |
| 24 | ClipboardChange | 14.0, off by default | none - documented gap |

## OS builds

| OS build | Sysmon compiled | EIDs used here | Notes |
|---|---|---|---|
| Windows 10 21H2 | 15.x | 1, 8, 10-14, 19-22, 26 | primary lab target; **no baseline captured** |
| Windows 11 23H2 | 15.x | same | event 24 noise is different; do not enable it without a window |
| Server 2019 | 15.x | 1, 8, 10-14, 19-21, 26 | WMI provider manifests differ; validate 19-21 |
| Server 2022 | 15.x | same as 2019 | validate WMI before trusting the triple rule |

`Sysmon schemaversion` in `telemetry/sysmon-config.xml` is 4.90, which is
required for the `ArchiveDirectory` element. A Sysmon older than 15 refuses that
element and falls back to a default config - which silently drops every
selection in the file. Check `sysmon64.exe -c` output against the repo copy after
install; that is what `baseline/manifest.json` pins.

## Required checks before deployment

1. `sysmon64.exe -c` shows the same config hash as `baseline/manifest.json`.
2. Each rule's event ID and field appears in a clean baseline capture. **No
   capture exists yet**, so this check has never been performed for any rule.
3. ETW providers are enabled and the collector is not blinded by patching
   (`telemetry/etw-providers.md`).
4. Record the OS build and Sysmon build alongside the captured fixture.

Missing builds are gaps, not assumptions.
