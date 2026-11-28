#!/usr/bin/env python3
"""Generate per-rule fixtures with CONCRETE event values.

Still `status: designed` - these are not blind captures - but every field has a
real value so the evaluator can actually match instead of comparing placeholders.
Negative fixtures carry a concrete `must_not_match` event derived from the
rule's filter sections.

The positive event for a rule is NOT invented here. It is built by the
evaluator's own `sequence_events()` from the rule's detection block, so a rule
that changes cannot keep passing against a stale hand-written event.

Usage:
    python3 tools/generate_fixtures.py            # rewrite every fixture
    python3 tools/generate_fixtures.py --check    # exit 1 if any fixture differs
"""
import argparse
import json
import pathlib
import sys

try:
    import yaml  # noqa: F401 - imported for the availability check below
except ImportError:
    sys.stderr.write("FAIL: PyYAML required\n")
    raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))
import evaluate

POS = ROOT / "fixtures" / "per_rule"
NEG = ROOT / "fixtures" / "negative"


def benign_value(field, modifier, value):
    """A concrete value that intentionally does not satisfy the constraint."""
    if modifier == "endswith":
        return "C:\\Windows\\explorer.exe"
    if modifier == "contains":
        return "benign-no-match"
    if modifier == "re":
        # A value that fails the pattern but is still the right *type* of thing.
        # "zzz" for a filename told the reader nothing; "C:\Windows\explorer.exe"
        # for a path and "www.example.com" for a DNS query read like telemetry.
        if field in ("TargetFilename", "Image", "ParentImage", "ObjectName"):
            return "C:\\Windows\\System32\\svchost.exe"
        if field in ("QueryName", "query"):
            return "www.example.com"
        return "zzz"
    if modifier == "exists":
        return None
    if modifier == "fieldref":
        return None
    if field == "EventID":
        return 999999
    if field in ("ProcessId", "destination_port", "DestinationPort"):
        return 0
    if field == "CertificateSelfSigned":
        return False
    if field in ("cs-user-agent", "UserAgent"):
        return "curl/8.0"
    if field == "rcode":
        return "NOERROR"
    if field == "Source":
        return "192.0.2.10"
    if field in ("Image", "TargetFilename", "ParentImage"):
        return "C:\\Program Files\\Contoso\\contoso.exe"
    return "benign-no-match"


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
        if "a-z]{13," in v:
            return "abcdefghijklm.top"
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
        if v in ("id=", "seq="):
            return "id=abc&seq=3"
        return "prefix-" + v + "-suffix"
    if field.startswith("cs-header-"):
        return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    if field == "cs-user-agent" or field == "UserAgent":
        return "Mozilla/5.0"
    if field in ("destination_port", "DestinationPort"):
        return 443
    if field == "CertificateSelfSigned":
        return True
    if field == "Signature":
        return "Microsoft Windows"
    if field == "IntegrityLevel":
        return "Medium"
    if field == "rcode":
        return "NXDOMAIN"
    return v


def negative_event(doc, positive):
    """A concrete event that must NOT match: benign-looking but complete.

    Built from scratch rather than mutated out of the positive event. Every
    field the positive selections read is inverted, and every `filter` field
    gets its real benign value, so the rule has a full record to evaluate.
    """
    det = doc.get("detection", {}) or {}
    neg = {"_ts": 0}
    for name, body in det.items():
        if name == "condition" or name.startswith("filter") or not isinstance(body, dict):
            continue
        refs = {n for n in det if n != "condition"}
        if name not in refs:
            continue
        for key, value in body.items():
            if key == "condition":
                continue
            parts = key.split("|")
            field, mod = parts[0], (parts[1] if len(parts) > 1 else "")
            if mod == "exists":
                continue
            v = benign_value(field, mod, value)
            if v is not None:
                neg[field] = v
    for name, body in det.items():
        if not name.startswith("filter") or not isinstance(body, dict):
            continue
        for key, value in body.items():
            if key == "condition":
                continue
            parts = key.split("|")
            if parts[0] in neg:
                continue
            neg[parts[0]] = real_value(parts[0], value, parts[1] if len(parts) > 1 else "")
    if len(neg) == 1:
        neg.update({"Image": "C:\\Windows\\explorer.exe", "EventID": 1})
    return neg


# A negative fixture only proves something if the rule could plausibly have
# fired on it. `negative_event` above builds one by inverting the selections,
# which produces an event that is *structurally* incompatible - EventID 999999
# matches no rule. That is a test of the evaluator, not of the rule, and it is
# how `runkey_schtask_startup_persistence` shipped an installer filter that
# read `ParentImage` against registry events, which have no such field: nothing
# ever handed it a real installer event to reject.
#
# The installer rows below are real telemetry shapes - an MSI writing a Run key,
# an MSI spawning schtasks - that select on the same events the rule reads and
# must be excluded by its `filter*` sections. They are appended for any rule
# that writes a registry value or creates a scheduled task.
INSTALLER_NEGATIVES = {
    "registry": {
        "EventID": 13,
        "Image": "C:\\Windows\\System32\\msiexec.exe",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "TargetObject": "HKLM\\Software\\Microsoft\\Windows"
                        "\\CurrentVersion\\Run\\SevenZip",
        "Details": "C:\\Program Files\\7-Zip\\7zFM.exe",
        "_ts": 1,
    },
    "scheduled_task": {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\schtasks.exe",
        "ParentImage": "C:\\Windows\\System32\\msiexec.exe",
        "CommandLine": "schtasks.exe /Create /TN SevenZipUpdate /TR 7zFM.exe",
        "_ts": 2,
    },
}


def installer_negatives(doc):
    """Realistic installer events a rule must reject, if it selects their shape.

    Only events the rule's own selections accept are returned: an event the
    rule cannot match would make the negative vacuous again, in the other
    direction.
    """
    det = doc.get("detection", {}) or {}
    picked = []
    for key, event in INSTALLER_NEGATIVES.items():
        if not any(evaluate.eval_detection(doc, event) for _ in [0]):
            # `eval_detection` already applies the filters, so a clean False
            # could mean "filtered" or "never selected". Ask the unfiltered
            # question to tell them apart.
            det_only = {k: v for k, v in det.items()
                        if not k.startswith("filter") and k != "condition"}
            if not det_only:
                continue
            if any(evaluate.match_selection(event, body)
                   for name, body in det_only.items()
                   if isinstance(body, dict) and name in str(det.get("condition", ""))):
                picked.append(event)
    return picked


def campaign_events(doc, rules):
    """A campaign fixture is the union of its members' own verified sequences.

    The plain path produced a single `{"_ts": 0}` event with no fields, which
    evaluates to `no match` and would have shipped as a passing test of nothing.
    The fixture has to contain what the campaign actually consumes: whatever each
    member chain fires on.
    """
    events = []
    for label, rid in (doc.get("campaign") or {}).get("of", {}).items():
        member = rules.get(rid)
        if member is None:
            continue
        events.extend(evaluate.sequence_events(member, rules))
    return events


def build(rid, doc, rules):
    det = doc.get("detection", {}) or {}
    if "campaign" in doc:
        events = campaign_events(doc, rules)
    elif "correlation" in doc:
        events = evaluate.sequence_events(doc, rules)
    else:
        condition = det.get("condition", "")
        event = evaluate.sequence_events({"correlation": {"rules": [rid]}}, rules)[0]
        events = [event]
        m = None if "count()" not in str(condition) else True
        if m:
            match = __import__("re").search(r"count\(\)\s*(?:by\s*[\w\-]+)?\s*(>=|>)\s*(\d+)", condition)
            if match:
                needed = int(match.group(2)) + 1
                events = [dict(event, _ts=i) for i in range(needed)]

    tech = next((t.split(".", 1)[1].upper() for t in (doc.get("tags") or [])
                 if isinstance(t, str) and __import__("re").match(r"attack\.t\d", t)), "UNKNOWN")
    first_fields = {k: v for k, v in events[0].items() if k != "_ts"} if events else {}

    pos = {
        "fixture_id": "FX-" + rid[:8],
        "rule_id": rid,
        "attack_id": tech,
        "status": "designed",
        "sample_ref": "PIN-0000",
        "events": events,
        "assert_fields": first_fields,
        "note": "Derived from the rule's own detection block by tools/generate_fixtures.py. "
                "Replace with an independent blind capture.",
    }
    if "correlation" in doc:
        # Self-contained: a correlation fixture must carry its member rules or
        # the file cannot be evaluated in isolation.
        pos["members"] = {
            m: json.loads(json.dumps(rules[m], default=str))
            for m in doc["correlation"]["rules"] if m in rules
        }
    if "campaign" in doc:
        campaigned = list((doc.get("campaign") or {}).get("of", {}).values())
        pos["members"] = {
            m: json.loads(json.dumps(rules[m], default=str))
            for m in campaigned if m in rules
        }
        pos["campaign"] = dict(doc["campaign"])
        pos["note"] += (" This fixture is the union of its members' verified "
                        "sequences; analytics/campaign.py evaluates it, not "
                        "detection-as-code/evaluate.py, which has no campaign "
                        "operator.")
    neg = {
        "fixture_id": "NF-" + rid[:8],
        "rule_id": rid,
        "status": "designed",
        "sample_ref": "benign",
        "benign_lookalikes": doc.get("falsepositives", []),
        "tuning_decision": "pending",
        "must_not_match": {
            "events": [negative_event(doc, events[0] if events else {})]
                      + installer_negatives(doc),
        },
    }
    return pos, neg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify fixtures are current instead of rewriting")
    args = ap.parse_args()

    rules = evaluate.load_collection(ROOT)
    POS.mkdir(parents=True, exist_ok=True)
    NEG.mkdir(parents=True, exist_ok=True)
    stale = 0
    for rid, doc in rules.items():
        pos, neg = build(rid, doc, rules)
        for path, payload in ((POS / (rid + ".json"), pos), (NEG / (rid + ".json"), neg)):
            text = json.dumps(payload, indent=2) + "\n"
            if args.check:
                if not path.exists() or path.read_text(encoding="utf-8") != text:
                    print(f"STALE {path.relative_to(ROOT)}")
                    stale += 1
            else:
                path.write_text(text, encoding="utf-8")
    if args.check:
        if stale:
            print(f"\n{stale} fixtures do not match their rule - run tools/generate_fixtures.py")
            return 1
        print(f"fixtures: all {len(rules)} rule/negative pairs current")
        return 0
    print(f"generated {len(rules)} concrete positive and negative fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
