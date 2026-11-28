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
- **Type:** a **shared-parent** join, not a temporal sequence. Expressing it as
  `temporal` would group by a field present in both events, and Sysmon puts the
  parent's identity in the child event under `ParentProcessGuid`, never under
  `ProcessGuid`. Sigma cannot state that, so the join is
  `analytics/stage_join.py`.
- **Key:** `stage1.ParentProcessGuid == stage0.ProcessGuid`
- **Window:** 600 s between the drop and the first child process
- **Rules:** `dropper_unsigned_temp_exec.yml`, `python_parent_child_shape.yml`
- **Rejects:** a signed updater in `%TEMP%` spawning a shell; an installed
  Python outside a user-writable path; a `_MEI` interpreter whose child ran
  20 minutes later; a sensor clock skew putting the child first. All four are in
  `fixtures/stage_join_sample.jsonl` and each is asserted separately.

```bash
python3 analytics/stage_join.py --selftest
python3 analytics/stage_join.py events.jsonl
```

## 3b. Cross-source campaign

- **Rule:** `sigma/campaign_implant_sequence.yml`
- **Type:** "at least 3 of 4 chains fired for the same host inside 1 h". Sigma
  2.1 has no operator over correlation members, so writing this as `temporal`
  would mean "all four, in order" - a different and much weaker detector.
- **Chains:** recon->tamper, WMI subscription triple, beacon frequency, DGA burst
- **Implementation:** `analytics/campaign.py`
- **Fixture contrast:** `LAB-WS01` fires 3 of 4 (campaign); `LAB-WS02` fires 2
  and must not; `LAB-WS03` fires 1.

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
