# Hunting queries for the coverage gaps

These target behaviors the Sigma rules cannot see well. Run them manually in a
lab first, then tune against your baseline.

## Splunk

```spl
# Processes created from a PyInstaller staging directory
index=sysmon EventCode=1
| where match(Image, "\\\\_MEI[0-9A-Za-z]{6,}")
| stats count by Computer, Image, ParentImage, CommandLine

# Scheduled task creation followed by a network connection from the same user
index=sysmon (EventCode=1 OR EventCode=3)
| where (match(CommandLine, "schtasks.*/Create") OR Image="net.exe")
| stats values(CommandLine) by Computer, User, _time

# File creation in staging directories with archive extensions
index=sysmon EventCode=11
| where match(TargetFilename, "AppData\\\\Local\\\\Temp")
    AND match(TargetFilename, "\\.(zip|db|bmp|enc)$")
| stats count by Computer, TargetFilename
```

## Zeek

```zeek
# Long random labels with NXDOMAIN - DGA fallback
event dns_log(rec: DNS::Info)
  {
  if ( rec$rcode == "NXDOMAIN" && |rec$query| > 20 )
    print rec$id$orig_h, rec$query;
  }

# Periodicity: inter-arrival times of requests to one host with low variance
# Compute deltas per (orig_h, resp_h) and alert when stddev/mean < 0.15
# and count > 20 in 10 minutes.
```

## Elastic / KQL

```kql
event.category:process and process.name:("net.exe" or "powershell.exe")
  and process.command_line:(*SecurityCenter2* or *"net view"*)

file.name:"autorun.inf" and not file.path:(*Program\ Files* or *Windows*)
```

## EDR memory telemetry

Query for `VirtualProtect`/`NtProtectVirtualMemory` calls whose target is inside
`ntdll.dll` or `amsi.dll`, followed by a write of `B8 57 00 07 80 C3` or
`33 C0 C3`. Pair with a process tree: the calling process should be unrelated to
any security product.

## Validation

For every query, record: hypothesis, expected telemetry, observed telemetry,
verdict (pass / gap / tune), and residual gap. Use
`analysis/report-template.md`.
