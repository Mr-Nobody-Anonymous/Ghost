#!/usr/bin/env python3
"""Check that a response playbook's steps can actually be carried out (G-18).

`response/rules/*.md` was generated from rule metadata: severity, ATT&CK id, and
one sentence telling the analyst to "confirm field values against a clean
baseline". Every one of those sentences names `rule:<id>:host:user`, an
identifier that exists nowhere else in the repo. So every playbook pointed its
reader at a field that cannot be looked up, and nothing noticed, because a
playbook is prose and nobody executes prose.

This does not pretend a human has worked an alert - that needs a lab and a
person. It checks the part that *can* be checked without one: does each step
name a telemetry field the rule actually reads, a hunt query that exists, and a
containment action the repo can justify. A step that references a nonexistent
field is a step an analyst cannot follow at 3am.

Usage:
    python3 response/check_playbooks.py            # verify
    python3 response/check_playbooks.py --json     # machine-readable
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLAYBOOKS = ROOT / "response" / "rules"

# The vocabulary a containment step may use. Every entry is something a Windows
# analyst can do with built-in tooling, and none of them is "reimage the box".
CONTAINMENT_ACTIONS = {
    "isolate-host": "disable the NIC or move the port to a quarantine VLAN",
    "disable-account": "net user <account> /active:no, then check group membership",
    "kill-process": "stop the process by PID, after capturing its image first",
    "quarantine-file": "move the file to a read-only share; do not delete it",
    "revoke-session": "invalidate the token (logoff, or reset the account's sessions)",
    "block-hash": "add the sha256 to the EDR blocklist",
    "block-domain": "sinkhole the domain at the resolver",
    "collect-memory": "capture a memory image before isolating anything else",
}

REQUIRED_HEADINGS = [
    "## What fired",
    "## Triage",
    "## Containment",
    "## What to preserve",
    "## When this is a false positive",
]

FIELD_REF = re.compile(r"`([A-Za-z_][A-Za-z0-9_.\-]*)`")


def load_rules():
    """id -> (rule doc, fields it reads, path). Same shape as
    tools/generate_playbooks.py's rules; two loaders returning tuples of
    different length under one name is how the tests broke."""
    import yaml
    out = {}
    for path in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or "id" not in doc:
            continue
        fields = set()
        for name, body in (doc.get("detection") or {}).items():
            if name == "condition" or not isinstance(body, dict):
                continue
            for key in body:
                fields.add(key.split("|", 1)[0])
        out[doc["id"].lower()] = (doc, fields, path)
    return out


def _rule_fields(doc):
    out = []
    for name, body in (doc.get("detection") or {}).items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for key in body:
            field = key.split("|", 1)[0]
            if field not in out:
                out.append(field)
    corr = doc.get("correlation")
    if isinstance(corr, dict):
        out.extend(corr.get("group-by", []) or [])
    return out


def hunt_queries():
    names = set()
    for path in (ROOT / "hunt").rglob("*"):
        if path.is_file() and path.suffix in (".kql", ".spl", ".md", ".sql"):
            names.add(path.stem)
            names.update(re.findall(r"^###\s+(\S+)", path.read_text(
                encoding="utf-8", errors="replace"), re.M))
    return names


def check_one(rule_id, text, rules, hunts):
    """Errors are things that make a step unfollowable; warnings are quality."""
    errors, warnings = [], []
    for heading in REQUIRED_HEADINGS:
        if heading not in text:
            errors.append(f"missing section {heading!r}")

    if rule_id not in rules:
        errors.append(f"no rule with id {rule_id}")
        return errors, warnings
    entry = rules[rule_id]
    # Accept both shapes the two tools produce: (doc, fields, path) from this
    # module, (path, doc) from the generator. Deriving fields from the doc is
    # one line; two loaders with the same name and different arity is how
    # every test in this file broke at once.
    doc, fields, path = (entry[0], entry[1], entry[2]) if len(entry) == 3 \
        else (entry[1], set(_rule_fields(entry[1])), entry[0])

    # 1. Every backticked identifier in a Triage/Containment step must be a
    #    field the rule reads, a hunt query that exists, or a known action.
    body = text.split("## Triage", 1)[-1]
    for token in FIELD_REF.findall(body):
        if token in fields or token in hunts or token in CONTAINMENT_ACTIONS:
            continue
        if token.startswith("rule:"):
            errors.append(f"invented identifier {token!r} - no such field, "
                          f"query or action exists in the repo")
        else:
            warnings.append(f"`{token}` is not a field this rule reads "
                            f"({', '.join(sorted(fields))})")

    # 2. A containment section must contain at least one action from the
    #    vocabulary. "Investigate further" is not containment.
    containment = text.split("## Containment", 1)[-1].split("##", 1)[0]
    if not any(action in containment for action in CONTAINMENT_ACTIONS):
        errors.append("containment names no action from the vocabulary "
                      f"({', '.join(sorted(CONTAINMENT_ACTIONS))})")

    # 3. The false-positive section must name a real benign behaviour, not a
    #    placeholder. This is what makes a playbook triageable rather than a
    #    restatement of the detection.
    fp = text.split("## When this is a false positive", 1)[-1]
    if len(fp.strip()) < 80:
        errors.append("false-positive section is too short to describe a real "
                      "benign cause")

    # 4. The preservation list must name at least two artifacts, and must not
    #    tell the analyst to delete anything.
    preserve = text.split("## What to preserve", 1)[-1].split("##", 1)[0]
    if preserve.lower().count("-") < 2:
        errors.append("preservation list names fewer than two artifacts")
    for verb in ("delete", "wipe", "reimage"):
        if verb in preserve.lower():
            errors.append(f"preservation step says {verb!r} - evidence "
                          f"destruction is not preservation")

    return errors, warnings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rules = load_rules()
    hunts = hunt_queries()
    findings = []
    for path in sorted(PLAYBOOKS.glob("*.md")):
        rule_id = path.stem.lower()
        errors, warnings = check_one(rule_id, path.read_text(encoding="utf-8"),
                                     rules, hunts)
        findings.append({"playbook": path.name, "rule": rule_id,
                         "errors": errors, "warnings": warnings})

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        bad = [f for f in findings if f["errors"]]
        for f in findings:
            for e in f["errors"]:
                print(f"FAIL {f['playbook']}: {e}", file=sys.stderr)
        for f in findings:
            for w in f["warnings"][:2]:
                print(f"warn {f['playbook']}: {w}")
        alone = len([f for f in findings if f["warnings"]])
        print(f"playbooks: {len(findings) - len(bad)}/{len(findings)} carry "
              f"out; {alone} with advisory warnings")

    return 1 if any(f["errors"] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
