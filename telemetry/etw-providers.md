# ETW providers

Providers required to close the telemetry gaps. Enable through your EDR or a
log collector; this lab defines the requirements, not an enabler.

| Provider / GUID | Purpose | Techniques | Event of interest |
|---|---|---|---|
| `Microsoft-Windows-Kernel-Process` | Process create/exit, image load | T1027.002, T1059 | process start with `_MEI` path |
| `Microsoft-Windows-Win32k` | Keyboard/mouse device access | T1056.001 | non-interactive process opening keyboard device object |
| `Microsoft-Windows-Kernel-General` (Kbdclass stack) | Input device handles | T1056.001 | handle to `\Device\KeyboardClass0` from unexpected process |
| `Microsoft-Windows-DriverFrameworks-UserMode` | USB device arrival | T1200 / T1091 | device arrival followed by `autorun.inf` write |
| `Microsoft-Windows-DeviceSetupManager` | Device setup | T1200 / T1091 | events 400 / 410 |
| `Microsoft-Windows-DotNETRuntime` | CLR load | T1055-adjacent | unexpected CLR hosting |
| `Microsoft-Windows-Security-Auditing` | Registry/key access | T1497 | SACL-triggered 4663 on CPU key |
| `Microsoft-Windows-Sysmon` (if using Sysmon ETW channel) | Configurable events | multiple | 10, 11, 19, 20, 21, 24 |

## Caveats

- ETW patching (`EtwEventWrite` → `ret`) removes these signals. Do not treat a
  quiet ETW feed as a clean result; corroborate with EDR memory telemetry.
- `Microsoft-Windows-Win32k` is high-volume. Filter at the collector, not at the
  SIEM.
- Provider availability differs by Windows version. Record the exact provider
  manifest version in `samples/PINS.md`-style provenance for your lab host.
