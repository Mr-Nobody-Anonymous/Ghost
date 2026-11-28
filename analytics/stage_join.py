#!/usr/bin/env python3
"""Stage 0 -> stage 1: the process-tree join Sigma cannot express.

`docs/sequence-rules.md` entry 3 said this join "is not implemented as a Sigma
correlation ... the join belongs in the SIEM". Two rules deploy separately -
`dropper_unsigned_temp_exec.yml` (an executable launched from a user-writable
path with no signer) and `python_parent_child_shape.yml` (a Python interpreter
spawning a shell or task tool) - and nothing connected them.

They are a *shared-parent* join, not a temporal sequence. The relationship is
`stage1.ParentProcessGuid == stage0.ProcessGuid`: the dropped binary is the
parent of the shell it spawns. A Sigma `temporal` correlation groups by a field
shared between the events, and Sysmon never puts the parent's ProcessGuid into
the child event under the same name, so the correlation cannot state it. That is
why this is a tool and not a rule.

Method
------
  1. filter both streams independently with the members' own predicates, read
     from the Sigma files (not restated here, so the rules stay the only copy)
  2. match child.ParentProcessGuid to a filtered stage-0 ProcessGuid
  3. require the child to be later than its parent (a clock skew check, not an
     ordering assumption) and within MAX_ANCESTRY_AGE
  4. report whole chains, including the command lines, because the value of this
     alert is the story it tells

The single-event rules do not fire on this pair on purpose: a PyInstaller
one-file dropper unpacks into `_MEI...` and *becomes* Python, so its own
`Image` is a temp path and its child is the shell. Neither event alone is
unusual enough to page on.

What is not proven: this has never run on a real Sysmon capture. The sample in
`fixtures/stage_join_sample.jsonl` is synthetic, built to contain one true chain
and three near-misses. `--selftest` asserts exactly those outcomes.

Usage:
    python3 analytics/stage_join.py --selftest
    python3 analytics/stage_join.py fixtures/stage_join_sample.jsonl
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = {
    "stage0": ROOT / "sigma" / "windows" / "process" / "dropper_unsigned_temp_exec.yml",
    "stage1": ROOT / "sigma" / "windows" / "process" / "python_parent_child_shape.yml",
}
MAX_ANCESTRY_AGE = 600.0     # seconds between the drop and the first child proc


def _load_yaml(path):
    import yaml
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _values(entry):
    return [str(v) for v in (entry if isinstance(entry, list) else [entry])]


def _match_modifier(value, modifier, candidate):
    text = str(candidate or "")
    if modifier == "endswith":
        return any(text.lower().endswith(v.lstrip("\\").lower()) for v in _values(value))
    if modifier == "contains":
        return any(v.lower() in text.lower() for v in _values(value))
    if modifier == "startswith":
        return any(text.lower().startswith(v.lower()) for v in _values(value))
    raise ValueError(f"unsupported modifier {modifier!r} in a member rule")


def match_selection(selection, event):
    """One Sigma selection against one event dict. Missing fields never match."""
    for key, value in selection.items():
        if "|" in key:
            field, modifier = key.split("|", 1)
            if not _match_modifier(value, modifier, event.get(field)):
                return False
        else:
            if str(event.get(key, "")).lower() not in [v.lower() for v in _values(value)]:
                return False
    return True


def member_predicate(member):
    """Return a callable(event) -> bool for the rule's full condition.

    Only `A and not B`, `A or B`, `A and (B or C)` shapes appear in these two
    rules; the evaluator is the small one `detection-as-code/evaluate.py` uses,
    narrowed to the boolean forms present and refusing anything else rather than
    guessing.
    """
    detection = dict(member["detection"])
    condition = detection.pop("condition")
    selections = dict(detection)

    # Any token that would make this ambiguous is a hard failure.
    if re.search(r"\b1 of\b|\ball of\b|\bthem\b", str(condition)):
        raise ValueError(f"condition {condition!r} uses a quantifier this "
                         f"evaluator does not implement")

    def evaluate(event):
        # Substitution is safe here only because the condition is a pure
        # and/or/not expression with no arithmetic or comparison operators.
        expr = str(condition)
        for name, sel in selections.items():
            expr = re.sub(rf"\b{name}\b",
                          "True" if match_selection(sel, event) else "False", expr)
        if re.search(r"[^()\s]*(and|or|not|True|False)", expr) is None and expr:
            raise ValueError(f"condition {condition!r} did not reduce to booleans: {expr}")
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307
        except Exception as exc:  # noqa: BLE001 - a bad rule is a config error
            raise ValueError(f"condition {condition!r} did not evaluate: {exc}") from exc

    return evaluate


def load_members():
    members = {}
    for stage, path in RULES.items():
        data = _load_yaml(path)
        members[stage] = {
            "id": data["id"],
            "path": path.relative_to(ROOT).as_posix(),
            "title": data.get("title", ""),
            "predicate": member_predicate(data),
        }
    return members


def join(events, members):
    """Return the chains that satisfy stage0 -> child-of-stage0 -> stage1."""
    stage0 = [e for e in events if members["stage0"]["predicate"](e)]
    stage1 = [e for e in events if members["stage1"]["predicate"](e)]

    by_guid = {e.get("ProcessGuid"): e for e in stage0 if e.get("ProcessGuid")}
    chains, reasons = [], []
    for child in stage1:
        parent_guid = child.get("ParentProcessGuid")
        parent = by_guid.get(parent_guid)
        if parent is None:
            reasons.append(f"{child.get('Image')} (pid {child.get('ProcessId')}): "
                           f"parent {parent_guid} is not a stage-0 event")
            continue
        age = float(child.get("_ts", 0)) - float(parent.get("_ts", 0))
        if age < 0:
            reasons.append(f"{child.get('Image')}: child precedes its parent by "
                           f"{-age:.0f}s (clock skew, not a chain)")
            continue
        if age > MAX_ANCESTRY_AGE:
            reasons.append(f"{child.get('Image')}: parent is {age:.0f}s older "
                           f"than the {MAX_ANCESTRY_AGE:.0f}s ancestry window")
            continue
        chains.append({"parent": parent, "child": child, "age_seconds": age})
    return chains, reasons, len(stage0), len(stage1)


def load_events(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"FAIL: {path}:{n} is not JSON: {exc}") from exc
    return events


def selftest():
    sample = ROOT / "fixtures" / "stage_join_sample.jsonl"
    members = load_members()
    chains, reasons, n0, n1 = join(load_events(sample), members)
    ok = True
    if len(chains) != 1:
        print(f"FAIL: expected exactly one chain, got {len(chains)}", file=sys.stderr)
        ok = False
    else:
        c = chains[0]
        print(f"chain: {c['parent'].get('Image')} -> {c['child'].get('Image')} "
              f"({c['age_seconds']:.1f}s)")
    if not any("not a stage-0 event" in r for r in reasons):
        print("FAIL: the signed-binary drop should be excluded", file=sys.stderr)
        ok = False
    if not any("precedes its parent" in r for r in reasons):
        print("FAIL: the clock-skew case should be excluded", file=sys.stderr)
        ok = False
    if not any("ancestry window" in r for r in reasons):
        print("FAIL: a parent older than the window should be excluded",
              file=sys.stderr)
        ok = False
    print(f"stages: {n0} stage-0 candidate(s), {n1} stage-1 candidate(s), "
          f"{len(reasons)} near-miss(es) rejected")
    print("selftest:", "OK - one chain, three near-misses rejected" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.events:
        ap.error("give a JSONL file or --selftest")

    members = load_members()
    chains, reasons, n0, n1 = join(load_events(args.events), members)
    if args.json:
        print(json.dumps({"chains": chains, "rejected": reasons}, indent=2,
                         default=str))
        return 0
    for c in chains:
        print(f"CHAIN {c['parent'].get('ProcessGuid')} -> "
              f"{c['child'].get('ProcessGuid')} ({c['age_seconds']:.1f}s)")
        print(f"  stage0 {c['parent'].get('Image')} :: {c['parent'].get('CommandLine')}")
        print(f"  stage1 {c['child'].get('Image')} :: {c['child'].get('CommandLine')}")
    for r in reasons:
        print(f"  rejected: {r}")
    print(f"stage_join: {len(chains)} chain(s) from {n0} stage-0 and {n1} "
          f"stage-1 candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
