#!/usr/bin/env python3
"""Sigma validator with duplicate-key detection and a strict schema.

Offline. Hard-fails on repeated YAML keys, missing required fields, tactic tags
mixed into `tags`, unpinned/invalid ATT&CK technique IDs, malformed IDs/dates,
and missing dedup keys.
"""
import argparse
import datetime
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = {
    "title", "id", "status", "description", "author", "date",
    "logsource", "falsepositives", "level", "references", "dedup_key",
}
TACTIC_RE = re.compile(r"^attack\.(?!t\d)[a-z][a-z0-9-]+$")
TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class DuplicateKeyError(Exception):
    pass


def no_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise DuplicateKeyError(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


if yaml is not None:
    class StrictLoader(yaml.SafeLoader):
        pass
    StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicates
    )


def load_pin():
    p = ROOT / "attack" / "attack-bundle-pin.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return set(t.upper() for t in data.get("techniques", [])), data.get("attack_version")
    except Exception:
        return set(), None


def check(path, pinned, version):
    errors = []
    text = path.read_text(encoding="utf-8")
    if yaml is None:
        return ["PyYAML not installed - strict validation unavailable"]
    try:
        doc = yaml.load(text, Loader=StrictLoader)
    except DuplicateKeyError as exc:
        return [str(exc)]
    except Exception as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(doc, dict):
        return ["top-level YAML is not a mapping"]

    missing = REQUIRED - set(doc)
    if "detection" not in doc and "correlation" not in doc:
        missing.add("detection or correlation")
    if missing:
        errors.append(f"missing keys: {', '.join(sorted(missing))}")

    rid = str(doc.get("id", ""))
    if not UUID_RE.match(rid):
        errors.append("id must be a lowercase UUIDv4")
    if not isinstance(doc.get("date"), datetime.date):
        errors.append("date must be an ISO date (YYYY-MM-DD)")

    tags = doc.get("tags", []) or []
    tactics = doc.get("tactics", []) or []
    if not isinstance(tags, list) or not isinstance(tactics, list):
        errors.append("tags and tactics must be lists")
    else:
        for t in tags:
            if not isinstance(t, str):
                errors.append("non-string tag")
                continue
            if TACTIC_RE.match(t):
                errors.append(f"tactic {t} belongs in tactics:, not tags:")
            elif TECHNIQUE_RE.match(t):
                if pinned and t.split(".", 1)[1].upper() not in pinned:
                    errors.append(f"ATT&CK ID {t} not in pinned bundle {version}")
            else:
                errors.append(f"malformed tag {t}")
        for t in tactics:
            if not isinstance(t, str) or not TACTIC_RE.match(t):
                errors.append(f"malformed tactic {t}")
        if not any(isinstance(t, str) and TECHNIQUE_RE.match(t) for t in tags):
            errors.append("no ATT&CK technique tag")

    det = doc.get("detection", {})
    if "detection" not in doc and "correlation" not in doc:
        errors.append("neither detection nor correlation block present")
    elif isinstance(det, dict) and "condition" not in det and "correlation" not in doc:
        errors.append("detection.condition missing")
    if "correlation" in doc and "rules" not in doc.get("correlation", {}):
        errors.append("correlation block has no rules")

    if not isinstance(doc.get("references"), list) or not doc["references"]:
        errors.append("references must be a non-empty list")
    if not isinstance(doc.get("falsepositives"), list):
        errors.append("falsepositives must be a list")
    if not isinstance(doc.get("dedup_key"), str) or not doc["dedup_key"]:
        errors.append("dedup_key must be a non-empty string")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=str(ROOT / "sigma"))
    args = ap.parse_args()
    root = pathlib.Path(args.path)
    files = sorted(root.rglob("*.yml"))
    if not files:
        print(f"no .yml files in {root}", file=sys.stderr)
        return 1
    pinned, version = load_pin()
    if not pinned:
        print("WARN: no ATT&CK pin loaded; technique existence not checked", file=sys.stderr)

    seen_ids = {}
    failed = 0
    for f in files:
        errs = check(f, pinned, version)
        text = f.read_text(encoding="utf-8")
        m = re.search(r"^id:\s*([0-9a-f-]{36})\s*$", text, re.M)
        if m:
            rid = m.group(1).lower()
            if rid in seen_ids:
                errs.append(f"duplicate id with {seen_ids[rid].name}")
            seen_ids[rid] = f
        if errs:
            failed += 1
            print(f"FAIL {f.relative_to(root)}")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"OK   {f.relative_to(root)}")
    print(f"\n{len(files) - failed}/{len(files)} rules passed (ATT&CK pin {version})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
