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

## Current state

`ceilings.json` has an entry for all 37 rules and **`measured: false` on every
one of them**. Ceilings were assigned by rule class (correlation outputs 20/day,
high-volume filter rules 5,000/day, single-object rules 50-100/day) as a budget
to test against, not as an observation. A ceiling with no measurement is a
guess, and the file says so rather than printing a number that looks measured.
