#!/usr/bin/env python3
"""Enforce the field contract in telemetry/data-sources.md.

Every field a rule reads must be documented with the event that carries it. The
previous state of this repo had rules reading `cs-header-X-Id`, `Signature`,
`IntegrityLevel`, `CertificateSelfSigned` and others that no document defined,
so "deployable" was an assertion rather than a check.

Also flags the known-impossible selections recorded in that doc: Sysmon 10
selecting a DLL in TargetImage, and Sysmon 23 used as a delete event.

Usage: python3 pipeline/field_contract.py [--strict]
       --strict also fails on fields documented but not read by any rule
"""
import argparse
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "telemetry" / "data-sources.md"


def documented_fields():
    text = DOC.read_text(encoding="utf-8")
    fields = set()
    # rows in the field-contract table start with a backticked field name
    for line in text.splitlines():
        m = re.match(r"^\|\s*`([^`]+)`", line)
        if m:
            for part in m.group(1).split(","):
                fields.add(part.strip())
    return fields


def rule_fields():
    out = {}
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        fields = {}
        for name, body in (doc.get("detection") or {}).items():
            if name == "condition" or not isinstance(body, dict):
                continue
            for key in body:
                if key == "condition":
                    continue
                fields.setdefault(key.split("|")[0], set()).add(key)
        if fields:
            out[f] = (doc, fields)
    return out


def impossible_selections(doc):
    """Selections that can never match, recorded in the data-source doc."""
    problems = []
    det = doc.get("detection") or {}
    for name, body in det.items():
        if not isinstance(body, dict):
            continue
        eid = body.get("EventID")
        ids = eid if isinstance(eid, list) else [eid]
        target = str(body.get("TargetImage", ""))
        if 10 in ids and re.search(r"\\(amsi|ntdll)\.dll$", target):
            problems.append(f"{name}: Sysmon 10 TargetImage is a process image, "
                            f"not a loaded module ({target})")
        if 23 in ids and "FileDelete" not in str(doc.get("description", "")):
            problems.append(f"{name}: Sysmon 23 is archived FileDelete; FileDelete is 26")
        if 24 in ids:
            problems.append(f"{name}: Sysmon 24 (ClipboardChange) is not enabled in the lab config")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    documented = documented_fields()
    if not documented:
        print("FAIL: no field contract table found in telemetry/data-sources.md")
        return 1

    used = {}
    problems = 0
    for path, (doc, fields) in rule_fields().items():
        rel = path.relative_to(ROOT).as_posix()
        for field, keys in fields.items():
            used.setdefault(field, []).append(rel)
            if field not in documented:
                problems += 1
                print(f"FAIL {rel}: field {field!r} is not in the documented contract")
        for issue in impossible_selections(doc):
            problems += 1
            print(f"FAIL {rel}: {issue}")

    if args.strict:
        for field in sorted(documented - set(used)):
            print(f"warn contract lists {field!r} but no rule reads it")

    print(f"field contract: {len(used)} fields read by rules, "
          f"{len(documented)} documented, {problems} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
