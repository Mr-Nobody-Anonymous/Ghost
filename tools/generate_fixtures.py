#!/usr/bin/env python3
"""Generate per-rule fixture stubs (positive field assertions + negative case).

These are DESIGNED stubs, not captures. They make the test harness able to
assert field values, but they do not prove a rule fires on real telemetry.
Replace with blind captures when a pinned artifact exists.
"""
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
POS = ROOT / "fixtures" / "per_rule"
NEG = ROOT / "fixtures" / "negative"


def selections(doc):
    if "correlation" in doc:
        corr = doc["correlation"] or {}
        fields = list(corr.get("group-by", []) or [])
        return fields or ["ProcessId"]
    det = doc.get("detection", {}) or {}
    fields = []
    for name, body in det.items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for k in body:
            if k not in fields:
                fields.append(k)
    return fields


def main():
    POS.mkdir(parents=True, exist_ok=True)
    NEG.mkdir(parents=True, exist_ok=True)
    count = 0
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        text = f.read_text(encoding="utf-8")
        doc = yaml.safe_load(text) if yaml is not None else None
        if not isinstance(doc, dict):
            continue
        rid = doc.get("id", "")
        if not rid:
            continue
        fields = selections(doc)
        tech = next((t.split(".", 1)[1].upper() for t in (doc.get("tags") or [])
                     if isinstance(t, str) and re.match(r"attack\.t\d", t)), "UNKNOWN")
        pos = {
            "fixture_id": "FX-" + rid[:8],
            "rule_id": rid,
            "attack_id": tech,
            "telemetry_source": doc.get("logsource", {}),
            "expected_events": [
                {"fields": {k: "<captured value>" for k in fields}, "occurs_within_seconds": 0}
            ],
            "fields_rule_reads": fields,
            "status": "designed",
            "captured_utc": "",
            "sample_ref": "PIN-0000",
            "note": "DESIGNED stub - replace with an independent blind capture.",
        }
        neg = {
            "fixture_id": "NF-" + rid[:8],
            "rule_id": rid,
            "software_class": "benign lookalike from rule falsepositives",
            "benign_lookalikes": doc.get("falsepositives", []),
            "why_it_should_not_alert": "tuning decision pending",
            "tuning_decision": "pending",
            "expected_events": [],
            "sample_ref": "benign",
        }
        (POS / (rid + ".json")).write_text(json.dumps(pos, indent=2) + "\n", encoding="utf-8")
        (NEG / (rid + ".json")).write_text(json.dumps(neg, indent=2) + "\n", encoding="utf-8")
        count += 1
    print(f"generated {count} positive stubs and {count} negative stubs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
