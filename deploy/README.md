# Deployment

A Sigma rule that validates but does not convert to your backend is shelfware.

## Per-backend conversion gate

```bash
sigma convert -t splunk sigma/...      # Splunk
sigma convert -t es-qs sigma/...       # Elasticsearch
sigma convert -t kql sigma/...         # Sentinel / KQL
sigma convert -t zeek sigma/network/...
```

CI must run conversion for every declared backend and fail on unsupported or
empty output. Record which backends each rule compiles to in the matrix.

## Rollout

1. Stage as `informational` only; do not page anyone.
2. Measure events/day per rule (`metrics/`).
3. Run the benign corpus; tune allowlists.
4. Promote severity only after FP rate is acceptable.
5. Keep the previous rule set available for rollback.

## Rollback

On a false-positive surge, disable by rule ID, not by deleting the file. Record
the disable and reason in `docs/tuning-log.md`.
