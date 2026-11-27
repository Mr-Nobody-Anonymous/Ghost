# Benign false-positive corpus

The biggest hole in a rule collection is the inability to measure precision.
Each entry below is a software class you must run in the lab and record the
events it produces. Every rule trip gets a documented tuning decision in
`docs/tuning-log.md`.

| Software class | Expected trips | Tuning decision |
|---|---|---|
| Signed MSI installer (e.g. 7-Zip) | Run-key write, file writes to `%TEMP%` | allowlist `msiexec.exe` parent |
| Browser auto-updater (Chrome/Edge) | Credential file access, high request frequency to update CDN | allowlist updater image and CDN hostnames |
| OneDrive / Dropbox sync | `%TEMP%` zip creation, frequent HTTPS, credential-file reads | allowlist sync processes and hosts |
| Backup agent | Broad file reads, scheduled task creation | allowlist agent path and task names |
| VS Code | `_MEI`-like temp paths (Electron unpack), frequent requests | allowlist code.exe and update hosts |
| Gaming launcher | High request frequency, self-signed TLS, updater tasks | allowlist launcher path/hosts |
| NTP / Windows Update | Regular periodic traffic | allowlist known update endpoints; beaconing rule needs frequency threshold |
| Slack / Teams client | Beacon-like periodicity, clipboard reads, screenshot on share | allowlist client processes and domains |

## Minimum bar

Run each class for at least one business day. A rule that trips on more than one
untuned benign class is not ready for production. Record: rule ID, software
class, event sample, decision (allowlist / threshold / retire), and date.
