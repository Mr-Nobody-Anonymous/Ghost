#!/usr/bin/env python3
"""Export ATT&CK Navigator layer JSON from the rule set.

`attack/matrix.md` is readable by a human, but a reader who wants to see gaps
has to diff table rows by hand. Navigator renders coverage as a heat map over
the matrix, which makes "12 of 15 tactics, nothing in exfiltration" obvious at a
glance instead of requiring a count.

Scores are deliberately coarse and named in the legend:

    0  no rule
    1  rule exists, fixture is designed (nothing captured)  <- every rule today
    2  rule has a captured fixture, not validated
    3  rule has a validated fixture from a pinned sample

With every fixture at `designed`, the whole layer will render at score 1. That
is the honest picture, and it is the point: the layer cannot look better than
the evidence, because the score comes from the fixtures rather than from the
rule count.

Usage:
    python3 tools/export_navigator.py                 # attack/navigator-layer.json
    python3 tools/export_navigator.py --out x.json
"""
import argparse
import datetime
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

import yaml

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "stealth",
    "defense-impairment", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]

STATUS_SCORE = {"deprecated": 0, "desired": 0, "designed": 1,
                "captured": 2, "validated": 3, "deployed": 3, "stale": 1}


def deferred_paths():
    """Rules this repository has decided upstream covers better.

    `attack/sigmahq-overlap.json` is where that decision is recorded, with a
    measured overlap and a rationale. A deferred rule must not contribute to the
    layer: painting a technique this repository does not uniquely detect is the
    same false claim as painting an unverified one, one level up.
    """
    path = ROOT / "attack" / "sigmahq-overlap.json"
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {r["ours"] for r in (data.get("reviewed") or [])
            if r.get("decision") == "defer"}


def load_rules():
    out = []
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("id"):
            doc["_path"] = f.relative_to(ROOT).as_posix()
            out.append(doc)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "attack" / "navigator-layer.json"))
    ap.add_argument("--version", default=None,
                    help="ATT&CK version label; defaults to the pin")
    args = ap.parse_args()

    pin_path = ROOT / "attack" / "attack-bundle-pin.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8")) if pin_path.is_file() else {}
    version = args.version or pin.get("attack_version", "")

    rules = load_rules()
    by_technique = {}
    deferred = deferred_paths()
    for doc in rules:
        if doc.get("_path") in deferred:
            continue
        techs = [t.split(".", 1)[1].upper() for t in doc.get("tags", [])
                 if str(t).lower().startswith("attack.t")]
        score = STATUS_SCORE.get(doc.get("lifecycle"), 1)
        for tech in techs:
            entry = by_technique.setdefault(tech, {"score": 0, "rules": []})
            entry["score"] = max(entry["score"], score)
            entry["rules"].append({
                "path": doc["_path"],
                "title": doc.get("title"),
                "level": doc.get("level"),
                "lifecycle": doc.get("lifecycle"),
            })

    techniques = []
    for tech, entry in sorted(by_technique.items()):
        techniques.append({
            "techniqueID": tech,
            "score": entry["score"],
            "color": "",
            "comment": "; ".join(f"{r['title']} ({r['level']}, {r['lifecycle']})"
                                 for r in entry["rules"]),
            "enabled": True,
            "metadata": [{"name": "rules", "value": ", ".join(r["path"] for r in entry["rules"])}],
            "links": [{"label": r["title"], "url": r["path"]} for r in entry["rules"]],
            "showSubtechniques": any("." in x for x in by_technique),
        })

    used_tactics = {t for doc in rules for t in doc.get("tactics", [])}
    layer = {
        "name": "Ghost detection lab",
        "versions": {"attack": version, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Generated {datetime.datetime.now(datetime.UTC).date().isoformat()} "
            f"from {len(rules)} Sigma rules. Score is evidence, not rule count: "
            f"1 = designed, 2 = captured, 3 = validated. "
            f"No rule has a captured fixture, so every score here is 1."),
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max",
                   "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ffd6a5", "#fdae61", "#e34a33"],
            "minValue": 0,
            "maxValue": 3,
        },
        "legendItems": [
            {"label": "no rule", "color": "#ffffff"},
            {"label": "rule, no capture", "color": "#ffd6a5"},
            {"label": "captured fixture", "color": "#fdae61"},
            {"label": "validated from a pinned sample", "color": "#e34a33"},
        ],
        "metadata": [
            {"name": "coverage", "value": f"{len(by_technique)} techniques, "
                                          f"{len(used_tactics)} tactics"},
            {"name": "evidence level", "value": "designed only - nothing captured"},
            {"name": "missing tactics",
             "value": ", ".join(sorted(t.replace("attack.", "") for t in
                                       set(pin.get("tactics", [])) - used_tactics)) or "none"},
        ],
        "links": [{"label": "gap register", "url": "docs/gap-register.md"}],
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    scores = {}
    for t in techniques:
        scores[t["score"]] = scores.get(t["score"], 0) + 1
    print(f"wrote {out.relative_to(ROOT)}: {len(techniques)} techniques "
          f"across {len(used_tactics)} tactics; scores {dict(sorted(scores.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
