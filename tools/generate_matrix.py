#!/usr/bin/env python3
"""Generate attack/matrix.md from rule metadata.

Techniques come only from `tags: [attack.tXXXX]`; tactics live in their own
field and are never counted as techniques. Network-only rules are marked
single-sourced. Correlation rules are flagged for backend-conversion risk.
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
TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def load(path):
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        doc = yaml.safe_load(text)
        if isinstance(doc, dict):
            return {
                "title": doc.get("title", path.stem),
                "id": doc.get("id", ""),
                "status": doc.get("status", "unknown"),
                "level": doc.get("level", ""),
                "tags": doc.get("tags", []) or [],
                "tactics": doc.get("tactics", []) or [],
                "sample_ref": doc.get("sample_ref", ""),
                "fixture_ref": doc.get("fixture_ref", ""),
                "lifecycle": doc.get("lifecycle", "unknown"),
                "correlation": "correlation" in doc,
                "logsource": doc.get("logsource", {}),
            }
    m = re.search(r"^tags:\s*\[([^\]]*)\]", text, re.MULTILINE)
    tags = [x.strip() for x in m.group(1).split(",")] if m else []
    lt = re.search(r"^tactics:\s*\[([^\]]*)\]", text, re.MULTILINE)
    return {
        "title": re.search(r"^title:\s*(.+)$", text, re.MULTILINE).group(1) if "title:" in text else path.stem,
        "id": "", "status": "unknown", "level": "", "tags": tags,
        "tactics": [x.strip() for x in lt.group(1).split(",")] if lt else [],
        "sample_ref": "", "fixture_ref": "", "lifecycle": "",
        "correlation": "correlation:" in text,
        "logsource": {},
    }


def source_of(rule):
    ls = rule.get("logsource", {}) or {}
    if ls.get("product") == "windows":
        return "host"
    if ls.get("category") in ("proxy", "firewall") or ls.get("service") in ("dns", "ssl", "suricata"):
        return "network"
    return "host"


def deferred_paths():
    """Rules recorded as covered better by upstream SigmaHQ.

    Counting a deferred rule as this repository's coverage would inflate the
    matrix in exactly the way the overlap check just stopped being unknown about.
    The rule still exists and still ships; it stops being *unique* coverage.
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


def main():
    rules, deferred = [], deferred_paths()
    deferred_rules = []
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        r = load(f)
        r["path"] = f.relative_to(ROOT).as_posix()
        if r["path"] in deferred:
            deferred_rules.append(r)
            continue
        rules.append(r)

    by_tech = {}
    tactic_tags = set()
    for r in rules:
        tactic_tags.update(r["tactics"])
        for t in r["tags"]:
            if isinstance(t, str) and TECH_RE.match(t):
                by_tech.setdefault(t.split(".", 1)[1].upper(), []).append(r)

    fixtures = {p.stem for p in (ROOT / "fixtures" / "per_rule").glob("*.json")}
    out = []
    out.append("# Attack matrix (generated)\n")
    # No wall clock: the header must be a function of the inputs, or every gate
    # run rewrites this file and `git status` can never be clean.
    out.append("Generated from rule metadata and attack/conversion.json. "
               "Do not edit by hand - run tools/generate_matrix.py.\n")
    out.append(f"Rules: {len(rules)} | distinct techniques: {len(by_tech)} | "
               f"tactics used: {len(tactic_tags)} of the pinned set "
               f"(not counted as techniques)\n")
    if deferred_rules:
        # Said out loud, because a reader counting rows would otherwise assume
        # every rule in sigma/ is being claimed here.
        out.append(
            f"**Excluded: {len(deferred_rules)} rule(s) deferred to upstream SigmaHQ** - "
            f"{', '.join('`' + r['path'] + '`' for r in deferred_rules)}. "
            f"`tools/sigmahq_overlap.py` measured the overlap and "
            f"`attack/sigmahq-overlap.json` records the decision. These still "
            f"ship, but their coverage belongs to upstream, not here.\n")
    out.append("| Technique | Rule | Source | Lifecycle | Level | Fixture | Pin | Flags |")
    out.append("|---|---|---|---|---|---|---|---|")
    for tech in sorted(by_tech):
        for r in by_tech[tech]:
            src = source_of(r)
            flags = []
            if src == "network":
                flags.append("single-sourced")
            if r["correlation"]:
                flags.append("conversion-risk")
            fx = r["fixture_ref"] or ("automatic" if tech in fixtures else "MISSING")
            out.append(
                f"| {tech} | [{r['title']}]({r['path']}) | {src} | {r['status']} | "
                f"{r['level']} | {fx} | {r['sample_ref'] or 'none'} | {', '.join(flags) or '-'} |"
            )
    out.append("")
    out.append("A technique is covered only when telemetry, rule, compilation, TP fixture, and FP corpus all pass. See `docs/maturity.md`.\n")

    pin_path = ROOT / "attack" / "attack-bundle-pin.json"
    if pin_path.is_file():
        import json as _json
        pin = _json.loads(pin_path.read_text(encoding="utf-8"))
        pinned_tactics = set(pin.get("tactics", []))
        used = set(tactic_tags)
        out.append(f"## Tactic coverage against ATT&CK {pin.get('attack_version')}\n")
        out.append(f"{len(used)} of {len(pinned_tactics)} pinned tactics have at least one rule. "
                   "A tactic with no rule is a blind spot, not a gap in the rule set's quality.\n")
        out.append("| Tactic | Rules |")
        out.append("|---|---|")
        for tac in sorted(pinned_tactics):
            n = sum(1 for r in rules if tac in r["tactics"])
            out.append(f"| {tac.replace('attack.', '')} | {'**0**' if n == 0 else n} |")
        out.append("")

    conv_path = ROOT / "attack" / "conversion.json"
    if conv_path.is_file():
        import json as _json
        conv = _json.loads(conv_path.read_text(encoding="utf-8"))
        results = conv.get("results", {})
        out.append("## Deployability (generated from ci/convert_check.py)\n")
        out.append(f"Conversion stamp: {conv.get('generated_utc')}. "
                   f"A rule is only deployable where the backend is `supported`.\n")
        out.append("| Rule | splunk | elastic | kusto |")
        out.append("|---|---|---|---|")
        for path, entry in sorted(results.items()):
            cells = []
            for backend in ("splunk", "elastic", "kusto"):
                state = (entry.get(backend) or {}).get("actual", "?")
                cells.append("yes" if state == "supported" else "**no**")
            out.append(f"| [{path}]({path}) | " + " | ".join(cells) + " |")
        counts = {b: sum(1 for e in results.values()
                         if (e.get(b) or {}).get("actual") == "supported")
                  for b in ("splunk", "elastic", "kusto")}
        out.append("")
        out.append("Totals: " + ", ".join(f"{k} {v}/{len(results)}" for k, v in counts.items()) + "\n")

    target = ROOT / "attack"
    target.mkdir(exist_ok=True)
    (target / "matrix.md").write_text("\n".join(out), encoding="utf-8")
    print(f"wrote attack/matrix.md: {len(rules)} rules, {len(by_tech)} techniques, {len(tactic_tags)} tactics")
    return 0


if __name__ == "__main__":
    sys.exit(main())
