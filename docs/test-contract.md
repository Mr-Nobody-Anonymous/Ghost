# Test harness contract

A TP test must fail when a rule fires *for the wrong reason*.

## Per-test requirements

1. **Field assertions, not match counts.** Assert the exact `Image`, `TargetObject`,
   `CommandLine`, `TargetImage`, or header value the rule is supposed to read.
   A generic match count is not a pass.
2. **State reset.** Each fixture runs in a fresh VM snapshot. No persistence,
   listeners, marker files, or test accounts survive between fixtures.
3. **Independent capture.** Fixtures are written from observed events, not from
   the rule definition. The author of the fixture should not read the rule until
   after capture. This is the only way to break rule/fixture circularity.
4. **Failure semantics.**
   - TP fails on missing event, wrong field value, or wrong process.
   - FP fails on any alert from the benign corpus after tuning.
   - Compile fails on invalid YAML/YARA or unsupported backend conversion.
   - Ratchet fails on a rising PENDING count.
5. **NTP discipline.** Time sync before capture; the 28s poll window and jitter
   analysis are meaningless with clock drift.
6. **Timeout.** A fixture that produces no event within its declared window is a
   failure, not a skip.

## Commands

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 ci/pending_ratchet.py main
bash ci/gate.sh
```

## Current limitation

With no pinned artifact and no captured fixtures, TP tests only prove internal
consistency. `docs/maturity.md` records this honestly; do not report coverage
from these tests alone.
