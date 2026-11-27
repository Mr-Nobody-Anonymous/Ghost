# Sequence rule specifications

Single-event rules cannot see the implant's signature, which is ordering. Four
correlation cases, with expected events and fields.

## 1. triage -> AMSI/ETW patch

- **ATT&CK:** T1497 -> T1562.001
- **Group by:** `ProcessId`
- **Ordered:** true
- **Window:** 5s
- **Events:** `Security 4663` on `HARDWARE\DESCRIPTION\System\CentralProcessor\0` -> `Sysmon 10` with `TargetImage` ending `amsi.dll` or `ntdll.dll` and RWX-like `GrantedAccess`
- **Fields asserted:** `ProcessId`, `ObjectName`, `TargetImage`, `GrantedAccess`
- **Rule:** `sigma/windows/defense-evasion/patch_sequence.yml`

## 2. persistence triple

- **ATT&CK:** T1546.003
- **Group by:** `ProcessId` (or command-line token)
- **Window:** 30s
- **Events:** `__EventFilter` create -> `CommandLineEventConsumer` create -> `__FilterToConsumerBinding` create
- **Fields asserted:** `EventType`, `Name`, `CommandLine`, `User`
- **Rule:** `sigma/windows/persistence/wmi_subscription_triple.yml` (single-event selection; upgrade to sequence when EID 19/20/21 correlation is available)

## 3. stage0 -> stage1

- **ATT&CK:** T1105 -> T1027.002
- **Group by:** process tree / parent GUID
- **Window:** 60s
- **Events:** file create of unsigned PE in `%TEMP%`/Downloads -> process start from `_MEIxxxx` path -> first outbound HTTPS
- **Fields asserted:** `TargetFilename`, `Image`, `ParentImage`, proxy `DestinationHostname`
- **Rule:** `sigma/windows/process/dropper_unsigned_temp_exec.yml` + `python_parent_child_shape.yml`

## 4. patch -> beacon

- **ATT&CK:** T1562.001 -> T1071.001
- **Group by:** host + user
- **Window:** 120s
- **Events:** AMSI/ETW patch -> first `/poll?id=&seq=` request with `X-Id`/`X-Seq`
- **Fields asserted:** `TargetImage`, `cs-header-X-Id`, `cs-uri-query`
- **Rule:** correlation of `amsi_etw_patch.yml` + `beacon_custom_headers.yml`

## Beaconing note

Jitter 0.35 on a 45s base gives ~29-61s intervals. A fixed `count >= N in T`
threshold will miss. Use inter-arrival distribution (variance around a central
period) per host/destination, not a hard cutoff.
