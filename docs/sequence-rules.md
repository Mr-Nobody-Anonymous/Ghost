# Sequence and frequency rule specifications

Single-event rules cannot see the implant's signature, which is ordering. Five
correlations exist; all use Sigma 2.1 correlation syntax (`event_count` and
`temporal`), not the deprecated pipe syntax, and not `frequency` - which is not a
Sigma correlation type and made these rules unloadable in pySigma.

**Platform note:** pySigma's Splunk backend converts correlations. Elastic and
Kusto do not, and `ci/convert_check.py` records that per rule. On those platforms
the member rules deploy as single-event detections and the join has to be built
in the SIEM.

## 1. CPU enumeration -> security component tamper

- **ATT&CK:** T1497 -> T1685
- **Type:** `temporal`
- **Group by:** `Computer` (the only key Security 4663 and Sysmon share -
  4663's `ProcessId` is the auditing process, not the accessing one)
- **Window:** 5m
- **Members:** `4663b1a0-...` (SACL read of the CPU key) -> `5e1c0f27-...`
  (service stop, AMSI provider removal, or Defender preference change)
- **Rule:** `sigma/windows/defense-evasion/patch_sequence.yml`
- **Converts:** splunk only

## 2. WMI persistence triple

- **ATT&CK:** T1546.003
- **Type:** `temporal`
- **Group by:** `Computer`
- **Window:** 30s
- **Members:** `wmi_filter_create.yml` (19) -> `wmi_consumer_create.yml` (20,
  `CommandLineEventConsumer`) -> `wmi_binding_create.yml` (21)
- **Rule:** `sigma/windows/persistence/wmi_subscription_triple.yml`
- **Converts:** splunk only. Members convert everywhere.

## 3. Stage 0 -> stage 1

- **ATT&CK:** T1105 -> T1027.002
- **Type:** not implemented as a Sigma correlation. A process-tree join is not
  expressible in Sigma; the two rules deploy separately and the join belongs in
  the SIEM (see `hunt-queries.md`).
- **Rules:** `dropper_unsigned_temp_exec.yml`, `python_parent_child_shape.yml`

## 4. Beacon frequency

- **ATT&CK:** T1071.001
- **Type:** `event_count`, >= 20 in 10m
- **Group by:** `SourceAddress`, `DestinationHostname`
- **Rule:** `sigma/beaconing_frequency.yml` over `beacon_custom_headers.yml`
- **Converts:** splunk only

## 5. DGA NXDOMAIN burst

- **ATT&CK:** T1568.002
- **Type:** `event_count`, >= 20 in 5m
- **Group by:** `Source` (Zeek DNS) or `ProcessGuid` (Sysmon 22)
- **Rules:** `sigma/dga_high_entropy_dns.yml`, `sigma/windows/process/dns_query_burst_host.yml`
- **Converts:** splunk only

## Beacon jitter

Jitter 0.35 on a 45s base gives ~29-61s intervals. A fixed `count >= N in T`
threshold will miss a slow beacon and fire on a fast poller:
`analytics/beacon_jitter.py --selftest` builds one of each with the same event
count and shows a count cannot separate them.

`beacon_interval_shift.yml` remains a **candidate filter**, not an alert. The
job it feeds is now implemented:

```bash
python3 analytics/beacon_jitter.py flows.jsonl          # table
python3 analytics/beacon_jitter.py flows.jsonl --json   # for a pipeline
python3 analytics/beacon_jitter.py --selftest           # gate stage 6
```

Per (source, destination) pair it takes sorted timestamps, diffs them to
inter-arrival times, and reports median and coefficient of variation (CV =
stdev/mean). A pair is `beacon_like` when CV <= 0.30 and the median interval is
between 5 s and 1 h. A 45 s beacon with 0.35 uniform jitter lands at CV ~= 0.23;
a log-normal poller with the same mean lands near 0.76.

**The limitation is stated, not hidden.** Backups, NTP and metrics scrapers are
periodic on purpose: a 300 s backup to `vault.corp` has CV 0.012 and is
statistically a beacon. No statistic fixes that, so the tool applies the rule's
own local-domain filter (`.local`, `.internal`, `.corp`) before measuring, and
prints what it filtered. `--no-rule-filter` shows the raw result if you want to
see why the filter exists. What remains after both is a candidate for a human,
not an alert.
