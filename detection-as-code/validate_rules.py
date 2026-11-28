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
    "title", "id", "status", "lifecycle", "description", "author", "date",
    "logsource", "falsepositives", "level", "references", "dedup_key",
    "sigma_spec_version", "dedup_window", "min_eval_interval", "min_os",
    "sample_ref", "conversion",
}

# `status` is the Sigma spec field and is parsed by pySigma. Anything outside the
# spec's own enum is rejected by pySigma before our conversion gate can run, so
# the repo lifecycle (designed -> captured -> ...) lives in `lifecycle` instead.
SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
LIFECYCLE = {"designed", "captured", "validated", "deployed", "stale", "deprecated"}
BACKENDS = ("splunk", "elastic", "kusto")
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
    """Load the pinned ATT&CK technique list and verify the bundle it claims.

    A pin whose hash is a placeholder string is not a pin: nothing stops the
    technique list drifting from the bundle it says it came from. The bundle is
    kept outside the repo (it is 50+ MB); the hash is the identity, so
    `tools/pin_attack_bundle.py` can verify or refresh it.
    """
    import hashlib
    p = ROOT / "attack" / "attack-bundle-pin.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return set(), None, None
    version = data.get("attack_version")
    if data.get("bundle_sha256"):
        bundle = (ROOT / data.get("bundle_path", "")).resolve()
        if not bundle.is_file():
            print(f"WARN: ATT&CK bundle for pin {version} not present at "
                  f"{data.get('bundle_path')!r}; technique IDs are checked against "
                  f"the pinned list only", file=sys.stderr)
        else:
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            if digest != data["bundle_sha256"]:
                print(f"FAIL: ATT&CK bundle hash {digest} != pin {data['bundle_sha256']}",
                      file=sys.stderr)
                return set(), None, version
    globals()["TECHNIQUE_TACTICS"] = data.get("technique_tactics", {})
    return (
        {t.upper() for t in data.get("techniques", [])},
        set(data.get("tactics", [])),
        version,
    )


def _duration_seconds(value):
    """Parse '10s' / '5m' / '1h' / '2d'. None when unparseable."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", value)
    if not m:
        return None
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def check(path, pinned, allowed_tactics, version):
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
    # A campaign rule has neither: it is an "at least N of these correlations
    # fired" layer that Sigma 2.1 cannot express. Exempting it here is only safe
    # because the campaign block is checked for real members in main().
    if not any(k in doc for k in ("detection", "correlation", "campaign")):
        missing.add("detection or correlation")
    if missing:
        errors.append(f"missing keys: {', '.join(sorted(missing))}")

    if doc.get("status") not in SIGMA_STATUS:
        errors.append(f"status must be a Sigma status: {', '.join(sorted(SIGMA_STATUS))} "
                      "- the repo lifecycle belongs in `lifecycle`")
    if doc.get("lifecycle") not in LIFECYCLE:
        errors.append(f"lifecycle must be one of: {', '.join(sorted(LIFECYCLE))}")

    conv = doc.get("conversion")
    if not isinstance(conv, dict):
        errors.append("conversion must be a mapping of backend -> supported|unsupported")
    else:
        for backend in BACKENDS:
            value = conv.get(backend)
            if value not in ("supported", "unsupported"):
                errors.append(f"conversion.{backend} must be supported or unsupported")
        unknown = set(conv) - set(BACKENDS) - {"note"}
        if unknown:
            errors.append(f"conversion has unknown backends: {', '.join(sorted(unknown))}")
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
            elif allowed_tactics and t not in allowed_tactics:
                errors.append(f"tactic {t} not in pinned allowlist")
        if not any(isinstance(t, str) and TECHNIQUE_RE.match(t) for t in tags):
            errors.append("no ATT&CK technique tag")
        # A tactics: list that has nothing to do with the technique is the kind of
        # error no other check catches - the tag is valid, the tactic is valid, and
        # the pair is wrong. ATT&CK v20 renamed Defense Evasion into Stealth and
        # Defense Impairment, so every one of these was stale.
        mapping = globals().get("TECHNIQUE_TACTICS") or {}
        if mapping:
            techs = [x.split(".", 1)[1].upper() for x in tags
                     if isinstance(x, str) and TECHNIQUE_RE.match(x)]
            expected = {f"attack.{ph}" for x in techs for ph in mapping.get(x, [])}
            declared = {x for x in tactics if isinstance(x, str)}
            if expected:
                stray = sorted(declared - expected)
                if stray:
                    errors.append(f"tactic(s) {stray} not reached by the rule's "
                                  f"technique(s) {techs}; pinned bundle says "
                                  f"{sorted(expected)}")
                if not declared:
                    errors.append(f"tactics: missing; pinned bundle says {sorted(expected)}")

    det = doc.get("detection", {})
    # A campaign rule is neither a selection nor a Sigma correlation: it is an
    # "at least N of these chains fired" layer that Sigma 2.1 cannot express and
    # analytics/campaign.py implements. Accepting it here without a check would
    # let any rule skip detection; the check is that the campaign block names
    # real correlation members.
    if "campaign" in doc:
        camp = doc.get("campaign") or {}
        members = camp.get("of") or {}
        if not isinstance(members, dict) or not members:
            errors.append("campaign block has no `of` members")
        if not isinstance(camp.get("require_at_least"), int):
            errors.append("campaign.require_at_least must be an integer")
        elif not 1 <= camp["require_at_least"] <= len(members):
            errors.append("campaign.require_at_least is outside 1..len(of)")
    elif "detection" not in doc and "correlation" not in doc:
        errors.append("neither detection nor correlation block present")
    elif (isinstance(det, dict) and "condition" not in det
          and "correlation" not in doc and "campaign" not in doc):
        errors.append("detection.condition missing")
    if "correlation" in doc and "rules" not in doc.get("correlation", {}):
        errors.append("correlation block has no rules")

    # Suppression arithmetic. Every rule declares dedup_window and
    # min_eval_interval, and nothing checked that they are sane: an eval interval
    # longer than the dedup window means a rule can fire inside its own
    # suppression gap, and a declared-but-unparsed duration is worse than none.
    durations = {}
    for key in ("dedup_window", "min_eval_interval"):
        value = doc.get(key)
        secs = _duration_seconds(value)
        if value is not None and secs is None:
            errors.append(f"{key} {value!r} is not a duration like 10s / 5m / 1h")
        durations[key] = secs
    if durations.get("dedup_window") and durations.get("min_eval_interval"):
        if durations["min_eval_interval"] >= durations["dedup_window"]:
            errors.append(
                f"min_eval_interval {doc['min_eval_interval']} >= dedup_window "
                f"{doc['dedup_window']}: the rule re-fires inside its own suppression window")

    # Sysmon event 26 is FileDelete, added in Sysmon 11; a rule selecting it
    # under sysmon_min_version < 15 is claiming a build that cannot emit it.
    det_text = str(doc.get("detection", "")) + str(doc.get("correlation", ""))
    floor = doc.get("sysmon_min_version")
    if isinstance(floor, int):
        if re.search(r"EventID:\s*(?:\[^\]]*\b)?26\b", det_text) and floor < 11:
            errors.append(f"selects Sysmon 26 (FileDelete, added in 11) but "
                          f"sysmon_min_version is {floor}")

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
    pinned, tactics, version = load_pin()
    if not pinned:
        print("WARN: no ATT&CK pin loaded; technique existence not checked", file=sys.stderr)

    seen_ids = {}
    failed = 0
    docs = {}
    for f in files:
        try:
            docs[f] = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            docs[f] = {}
    by_id = {d.get("id"): d for d in docs.values() if isinstance(d, dict) and d.get("id")}
    for f in files:
        errs = check(f, pinned, tactics, version)
        doc = docs[f]
        # Campaign members must be correlations. Checked here, not in check(),
        # because it needs the whole collection: a campaign of single-event
        # rules is just an event_count and would misrepresent its own shape.
        camp = doc.get("campaign") if isinstance(doc, dict) else None
        for label, rid in (camp or {}).get("of", {}).items():
            member = by_id.get(rid)
            if member is None:
                errs.append(f"campaign member {label!r} ({rid}) is not a rule")
            elif not member.get("correlation"):
                errs.append(f"campaign member {label!r} ({rid}) is not a "
                            f"correlation")
        text = f.read_text(encoding="utf-8")
        m = re.search(r"^id:\s*([0-9a-f-]{36})\s*$", text, re.MULTILINE)
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
