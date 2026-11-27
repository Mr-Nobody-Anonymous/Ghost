#!/usr/bin/env python3
"""Generate per-rule fixtures with CONCRETE event values.

Still `status: designed` - these are not blind captures - but every field has a
real value so the evaluator can actually match instead of comparing placeholders.
Negative fixtures carry a concrete `must_not_match` event derived from the
rule's filter sections.
"""
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("FAIL: PyYAML required\n")
    raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
POS = ROOT / "fixtures" / "per_rule"
NEG = ROOT / "fixtures" / "negative"


def real_value(field, value, modifier):
    vals = value if isinstance(value, list) else [value]
    v = str(vals[0])
    if field == "EventID":
        return int(v) if v.isdigit() else 1
    if field == "ProcessId":
        return 4242
    if field == "ProcessGuid":
        return "{aaaaaaaa-0000-0000-0000-000000000001}"
    if field == "GrantedAccess":
        return "0x001F0FFF"
    if field == "AccessMask":
        return "0x1"
    if modifier == "re":
        if "[a-z]{14,}" in v:
            return "abcdefghijklmnop.top"
        return v.strip("^$")
    if modifier == "endswith":
        if v.startswith("\\"):
            return "C:\\Windows\\System32" + v
        if v == "lsass.exe":
            return "C:\\Windows\\System32\\lsass.exe"
        return "C:\\Users\\lab\\AppData\\Local\\Temp\\" + v.lstrip("\\")
    if modifier == "startswith":
        return v + "suffix"
    if modifier == "contains":
        if "\\" in v:
            return "C:\\Users\\lab\\" + v
        if "CurrentVersion\\Run" in v or "RunOnce" in v:
            return "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\marker"
        if v in ("SecurityCenter2", "AntiVirusProduct"):
            return 'powershell.exe -NoP -NonI -C "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct"'
        if v == "id=" or v == "seq=":
            return "id=abc&seq=3"
        return "prefix-" + v + "-suffix"
    if field.startswith("cs-header-"):
        return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    if field == "cs-user-agent" or field == "UserAgent":
        return "Mozilla/5.0"
    if field == "destination_port" or field == "DestinationPort":
        return 443
    if field == "CertificateSelfSigned":
        return True
    return v


def merge_constraints(field, constraints):
    contains = [str(c[1][0]) for c in constraints if c[0] == "contains"]
    ends = [str(c[1][0]) for c in constraints if c[0] == "endswith"]
    starts = [str(c[1][0]) for c in constraints if c[0] == "startswith"]
    base = "C:\\Users\\lab"
    for c in contains:
        base += c if c.startswith("\\") else "\\" + c
    if ends:
        base = base.rstrip("\\") + "\\" + ends[0].lstrip("\\")
    if starts:
        base = starts[0] + base
    return base


def event_from_selection(selection):
    constraints = {}
    order = []
    for key, value in selection.items():
        if key == "condition":
            continue
        parts = key.split("|")
        field, mod = parts[0], (parts[1] if len(parts) > 1 else "")
        if mod == "exists" and value is False:
            continue
        if field not in constraints:
            constraints[field] = []
            order.append(field)
        constraints[field].append((mod, value if isinstance(value, list) else [value]))
    event = {"_ts": 0}
    for field in order:
        items = constraints[field]
        if len(items) > 1:
            event[field] = merge_constraints(field, items)
        else:
            mod, value = items[0]
            event[field] = real_value(field, value, mod)
    return event


def positive_event(doc):
    det = doc.get("detection", {}) or {}
    merged = {"_ts": 0}
    for name, body in det.items():
        if name == "condition" or name.startswith("filter") or not isinstance(body, dict):
            continue
        event = event_from_selection(body)
        for k, v in event.items():
            if k != "_ts" and k not in merged:
                merged[k] = v
    return merged


def benign_value(field, modifier, value):
    """A concrete value that intentionally does not satisfy the constraint."""
    if modifier == "endswith":
        return "C:\\Windows\\explorer.exe"
    if modifier == "contains":
        return "benign-no-match"
    if modifier == "re":
        return "zzz"
    if modifier == "exists":
        return None
    if field == "EventID":
        return 999999
    if field in ("ProcessId", "destination_port", "DestinationPort"):
        return 0
    if field == "CertificateSelfSigned":
        return False
    if field in ("cs-user-agent", "UserAgent"):
        return "curl/8.0"
    return "benign-no-match"


def negative_event(doc, positive):
    det = doc.get("detection", {}) or {}
    neg = {"_ts": 0}
    # Invert every field read by a positive selection so the rule cannot fire.
    for name, body in det.items():
        if name == "condition" or name.startswith("filter") or not isinstance(body, dict):
            continue
        for key, value in body.items():
            if key == "condition":
                continue
            parts = key.split("|")
            field, mod = parts[0], (parts[1] if len(parts) > 1 else "")
            v = benign_value(field, mod, value)
            if v is not None:
                neg[field] = v
    # Filter fields get plausible benign values so `not filter` stays true.
    for name, body in det.items():
        if not name.startswith("filter") or not isinstance(body, dict):
            continue
        for key, value in body.items():
            if key == "condition":
                continue
            parts = key.split("|")
            field = parts[0]
            neg[field] = real_value(field, value, parts[1] if len(parts) > 1 else "")
    if not neg:
        neg = {"_ts": 0, "Image": "C:\\Windows\\explorer.exe", "EventID": 1}
    return neg


def sequence_events(doc, rules):
    corr = doc.get("correlation", {}) or {}
    events = []
    for i, rid in enumerate(corr.get("rules", [])):
        member = rules.get(rid)
        if not member:
            continue
        ev = positive_event(member)
        ev["_ts"] = i * 3
        events.append(ev)
    if corr.get("type") == "frequency" and events:
        gte = int((corr.get("condition", {}) or {}).get("gte", 1)) + 1
        events = [dict(events[0], _ts=i) for i in range(gte)]
    return events


def main():
    rules = {}
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("id"):
            rules[doc["id"]] = doc
    POS.mkdir(parents=True, exist_ok=True)
    NEG.mkdir(parents=True, exist_ok=True)
    count = 0
    for rid, doc in rules.items():
        tech = next((t.split(".", 1)[1].upper() for t in (doc.get("tags") or [])
                     if isinstance(t, str) and re.match(r"attack\.t\d", t)), "UNKNOWN")
        if "correlation" in doc:
            events = sequence_events(doc, rules)
        else:
            events = [positive_event(doc)]
            cond = (doc.get("detection", {}) or {}).get("condition", "")
            m = re.search(r"count\(\)\s*(?:by\s*[\w\-]+)?\s*(>=|>)\s*(\d+)", cond)
            if m:
                threshold = int(m.group(2))
                needed = threshold + 1
                events = [dict(events[0], _ts=i) for i in range(needed)]
        pos = {
            "fixture_id": "FX-" + rid[:8],
            "rule_id": rid,
            "attack_id": tech,
            "status": "designed",
            "sample_ref": "PIN-0000",
            "events": events,
            "assert_fields": {
                k: events[0][k] for k in events[0] if k != "_ts"
            } if events else {},
            "note": "Concrete but authored from the rule. Replace with an independent blind capture.",
        }
        neg = {
            "fixture_id": "NF-" + rid[:8],
            "rule_id": rid,
            "status": "designed",
            "sample_ref": "benign",
            "benign_lookalikes": doc.get("falsepositives", []),
            "tuning_decision": "pending",
            "must_not_match": {"events": [negative_event(doc, events[0] if events else {})]},
        }
        (POS / (rid + ".json")).write_text(json.dumps(pos, indent=2) + "\n", encoding="utf-8")
        (NEG / (rid + ".json")).write_text(json.dumps(neg, indent=2) + "\n", encoding="utf-8")
        count += 1
    print(f"generated {count} concrete positive and negative fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
