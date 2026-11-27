# IOC checklist

Indicators to extract from a sample or an incident. Each needs provenance
(source artifact, UTC timestamp, sha256) before it is shared.

## File / binary

- sha256 of the sample and of every unpacked `_MEI*` child.
- PyInstaller overlay markers; `_MEIxxxxxx` temp paths.
- Dropped names: `svc_update.exe`, `autorun.inf`, `kl.enc`, `shot.bmp`,
  `wallets.zip`, `docs.zip`, `armed`.
- Staging directory pattern under `%TEMP%` with random suffix.

## Registry / persistence

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<name>`
- Scheduled task names with `/SC ONLOGON`.
- `root\subscription` `__EventFilter`, `CommandLineEventConsumer`,
  `__FilterToConsumerBinding` entries.
- Startup folder `.cmd` / `.bat` / `.lnk` files.

## Network

- Outbound HTTPS with `X-Id` and `X-Seq` headers, `Mozilla/5.0` UA,
  `Content-Type: application/octet-stream`.
- URI pattern `/register`, `/poll?id=&seq=`, `/result`.
- DNS queries matching `[a-z]{14,}\.(com|net|org|info|biz|ru|top|xyz)` with
  NXDOMAIN bursts (DGA fallback).
- TLS to hosts with self-signed / non-validating certificates (client uses
  `CERT_NONE`).

## Process / memory

- Process access (`Sysmon 10`) to `amsi.dll` / `ntdll.dll` with RWX-like masks.
- `VirtualProtect` calls on those modules; patch byte sequences
  `B8 57 00 07 80 C3` and `33 C0 C3`.
- `schtasks.exe /Create`, `powershell.exe` with WMI subscription cmdlets,
  `net view` from an unexpected user context.

## Handling

Redact third-party PII, secrets, and real credentials before sharing. Never put
plaintext recovered passwords into a report — record account, hash type, and
access level only.
