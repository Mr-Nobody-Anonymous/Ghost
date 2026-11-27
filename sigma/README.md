# Sigma rules

Rules are written against common Sysmon / Windows Event Log / Zeek / proxy field
names. Before deployment:

- Run `sigma check *.yml` to validate syntax.
- Convert to your backend with `sigma convert -t <splunk|es-qs|sentinel> ...`.
- Map field names in the `logsource`/`detection` blocks to your ingestion schema.
- Tune with `falsepositives` and internal baselines. A rule that fires on every
  PyInstaller-packaged admin tool is worse than no rule.

Each rule carries an ATT&CK tag and a `level` reflecting the confidence of the
signal, not just the impact of the technique.
