# Metrics

Track events/day per rule after staging. A rule firing thousands of times a day
has a different cost than one firing twice a week.

| Metric | Why |
|---|---|
| events/day per rule | blast radius and analyst load |
| distinct hosts/day | scope of noise |
| precision (TP / all alerts) | whether tuning worked |
| FP trips by software class | where to tune next |
| rules with no events | candidate for retirement or missing telemetry |

Record results in `reports/`. A rule with zero events and no fixture is not
"quiet" — it may simply never fire.
