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

## What the harness actually enforces

| Requirement above | Where it is enforced | State |
|---|---|---|
| 1. Field assertions | fixture `assert_fields`, asserted against the event that matched | **enforced**; assertions must appear on a matching event, not any OR-branch |
| 2. State reset | lab procedure only | **not enforced** - nothing verifies the VM was restored |
| 3. Independent capture | `tools/capture_kit.py` + `lifecycle` state machine | **not achieved** - every fixture is derived from its rule |
| 4. Failure semantics | `ci/gate.sh` (10 stages) | **enforced**, including a negative test that the gate fails on a broken rule |
| 5. NTP discipline | lab procedure only | **not enforced** |
| 6. Timeout | evaluator rejects out-of-window sequences | **enforced** for sequences only |

Requirement 3 is the important one and it is not met. Deriving a fixture from the
rule makes it a consistency check, which is what the `designed` status means; it
is not evidence of detection.
