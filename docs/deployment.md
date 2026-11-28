# Deployment: from a Windows host to a working alert

The repository can produce validated rules and a deployable bundle. It could not
tell anyone how to get telemetry from a host into an index, or how to load the
38 queries as scheduled searches. That gap is the difference between a rule set
and a working detection, so this page closes it.

Everything below is generic Splunk-on-Windows unless stated. Nothing here has
been executed against a real deployment — see the status box at the bottom.

---

## 1. Choose your backend

`attack/matrix.md` has a per-rule, per-backend table generated from the
conversion run. As of the current pin:

| Backend | Rules that convert | What you get |
|---|---|---|
| Splunk | 38/38 | everything, including the 5 correlations and the one `fieldref` rule |
| Elastic | 32/38 | single-event rules only; correlations must be rebuilt (see §6) |
| Kusto / Sentinel | 32/38 | same, plus `fieldref` does not translate |

**If you pick Elastic or Kusto, the five correlations do not deploy.** They are
`temporal` and `event_count` Sigma correlations, which pySigma converts only for
Splunk. The member rules deploy fine; the join is yours to build.

## 2. Get the telemetry in

The rules read fields this repository documents in `telemetry/data-sources.md`.
A rule cannot read a field that was never collected, and 37 of the 38 rules are
Windows-only. Minimum viable ingestion:

| Source | Channel / input | Why |
|---|---|---|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | 32 of the rules; the pinned config in `telemetry/sysmon-config.xml` is what they were written against |
| Security | `Security` | 4663 (SACL reads) for `cpu_info_read.yml` and the tamper sequence |
| Zeek or equivalent | `dns.log`, `ssl.log`, `conn.log` | the two DGA rules and the TLS rule |
| Proxy / SWG | access log **with request headers** | `beacon_custom_headers.yml` reads `cs-header-X-Id` |

Two things that break silently:

1. **Sysmon falls back to a default config if it rejects yours.** The schema
   version in `telemetry/sysmon-config.xml` is 4.90; older Sysmon refuses it and
   starts with something that matches none of these rules. After install, run
   `sysmon64.exe -c` and compare with the repo file. `baseline/manifest.json`
   pins the hash.
2. **Proxies drop custom headers.** `cs-header-X-Id` and `cs-header-X-Seq` are
   the whole point of the C2 rules. If the proxy does not export them, four
   rules become dead — and they will not error, they will just never fire. Test
   with one real request before trusting them.

## 3. Normalise field names

Sigma says `EventID`; Splunk's Windows add-on produces `EventCode`. Do not edit
38 rules to match one vendor. Map at ingest:

`deploy/fieldmap/props-sigma.conf` is generated, one stanza per sourcetype.
Install it:

```bash
cp deploy/fieldmap/props-sigma.conf \
   $SPLUNK_HOME/etc/system/local/props.conf   # then restart splunkd
```

Elastic and Sentinel get the same map in their own shape:
`deploy/fieldmap/ingest-pipeline.json` (PUT to `_ingest/pipeline/sigma-canonical`
and attach it to the Windows data stream) and `deploy/fieldmap/sigma-views.kql`
(one `let Sigma_<table>` projection per log table).

All three are rendered from `telemetry/field-map.json` and checked by
`pipeline/build_field_map.py --check` in the gate, so a field that a rule reads
cannot be missing a name on a platform.

If you skip this, `EventID` will not exist and every rule will evaluate against
a null field — which matches nothing, silently. `pipeline/field_contract.py`
keeps the repo's side honest (every field a rule reads is documented); the field
map keeps the platform side honest (every documented field has a name there).

Two mappings are not renames, and the map says so:

- `CertificateSelfSigned` is `subject == issuer`. It is computed, not aliased.
  A rename would put a certificate string where a rule tests a boolean.
- On Splunk the proxy fields go the *other* way: `cs_user_agent AS cs-user-agent`.
  Splunk has already rewritten the hyphen; the rules use the proxy's spelling.

## 4. Load the queries

```bash
python3 ci/convert_check.py --backends splunk          # measure first
python3 deploy/build_bundle.py --backend splunk \
  --out dist/splunk-queries.spl --manifest dist/splunk-manifest.json
```

`dist/splunk-queries.spl` holds one `comment`-delimited query per rule. The
manifest carries, per rule: `id`, `title`, `level`, `dedup_key`,
`dedup_window`, `min_eval_interval`, and a ready-made suppression string:

```text
alert.suppress = 1; alert.suppress.fields = host, user; alert.suppress.period = 5m
```

Apply that to the saved search. Without it, a rule that matches a common process
create fires once per occurrence — the manifest values exist so you do not have
to invent them.

Scheduling floor: never schedule faster than `min_eval_interval`. It is shorter
than `dedup_window` for every rule; the validator rejects the inverse.

## 5. Stage, then tune

1. Create every search **disabled**, level `informational`.
2. Enable in batches by level: `low` first, then `medium`, then `high`. High-level
   rules fire on rare things, so they cost little and can run early.
3. Watch `metrics/ceilings.json` against reality. Every ceiling is currently
   `measured: false` — the numbers are budgets, not observations.
4. Every trip gets a row in `docs/tuning-log.md` with an `allowlist` / `threshold`
   / `retire` / `keep` decision. `response/rules/<id>.md` has the first triage step.

A rule stays at `informational` until it has survived a week of a real environment
or the benign corpus. Nothing in this repository has yet.

## 6. Rebuilding correlations on Elastic

For each file with a `correlation:` block, the manifest lists its members. Build
the same join in your platform:

| Sigma | Elastic |
|---|---|
| `event_count`, `group-by`, `timespan`, `gte: N` | `stats count by <group-by>` over the window, filter `count >= N`, `bucket_span` = timespan |
| `temporal`, `group-by`, `timespan` | EQL `sequence by <group-by> with maxspan=<timespan> [...]` |

Keep the member `sid`/rule id in the alert, or the correlation and its members
cannot be told apart during triage.

## 7. Verify a deployment actually works

```bash
python3 tools/verify_baseline.py --input baseline.xml --json baseline/report.json
```

Run it on a capture from a host that has already installed the pinned config.
It reports per rule which `EventID`s are missing and which fields the capture does
not carry. This is the only check in the repository that can tell you the
telemetry pipeline is wrong rather than the rule — use it immediately after
deployment, before you trust a quiet dashboard.

---

## Status

This document is a correct procedure for a deployment that has never been
performed. No click, query, configuration line or hash above has been verified
against a running SIEM, and no rule in this repository has produced an alert on
real telemetry. Treat it as a plan with named risks, not a report of results.

Gaps this page does *not* solve, tracked in `docs/gap-register.md`:
G-01 blind capture, G-02 clean baseline, G-03 benign corpus, G-04 volume,
G-11 header retention, and G-14 the five Splunk-only correlations.
