# Advanced audit policy and SACLs

Commands require administrative rights on the lab host. Apply only in an
isolated VM and record the before/after state.

## Audit policy

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Registry Object" /success:enable /failure:enable
auditpol /set /subcategory:"File System Object" /success:enable /failure:enable
auditpol /set /subcategory:"Scheduled Task" /success:enable /failure:enable
auditpol /set /subcategory:"Object Access" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
```

Verify with:

```cmd
auditpol /get /category:*
```

## Registry SACL for anti-analysis detection (T1497)

Add a SACL so reads of the CPU processor string generate Object Access events:

```cmd
reg add "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" /v ProcessorNameString /d "" /f
icacls "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" /save acl_backup.txt
```

Run the generated script — do not hand-apply this one:

```powershell
.\deploy\telemetry\set-sacls.ps1
```

`deploy/telemetry/set-sacls.ps1` is generated from the rules by
`tools/build_sacl_script.py`. It backs up each ACL before changing it, applies
the Audit Read ACE for `Everyone`, reads the SACL back to prove it stuck, and
takes `-Rollback` to undo everything.

It has exactly one target, because exactly one rule in this repository reads a
4663 field (`cpu_info_read.yml`, AccessMask `0x1` on the processor key). An
earlier version of this document said "use Set-Acl / subinacl / your EDR's
tooling", which is three options and no command for a step that has to be exact
or the rule never fires and never says why.

A broad SACL is its own problem: audit `C:\Users` and you generate millions of
events a day to feed a rule that is not listening for them. `--check` in the gate
fails if a rule reads 4663 without a target, or if a target names a rule that
does not read it.

Correlate the resulting 4663 event with a process that also exhibits sleep-skew
behavior — a single registry read is not a finding.

## Event IDs to expect

| ID | Meaning |
|---|---|
| 4688 | Process creation (with command line if policy enabled) |
| 4663 | Object access (SACL-triggered registry/file read) |
| 4698 / 4699 / 4702 | Scheduled task create / modify / delete |
| 4656 / 4662 | Handle requested / directory service access |
| 4904 / 4905 | WMI event filter / consumer creation (where available) |

## Baseline first

Capture 24 hours of clean telemetry before enabling broad Object Access auditing.
Without a baseline, the FP rate on registry and file access will be unusable.
