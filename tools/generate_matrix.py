#!/usr/bin/env python3
"""Generate attack/matrix.md from rule metadata.

Techniques come only from `tags: [attack.tXXXX]`; tactics live in their own
field and are never counted as techniques. Network-only rules are marked
single-sourced. Correlation rules are flagged for backend-conversion risk.
"""
import datetime
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
                "correlation": "correlation" in doc,
                "logsource": doc.get("logsource", {}),
            }
    m = re.search(r"^tags:\s*\[([^\]]*)\]", text, re.M)
    tags = [x.strip() for x in m.group(1).split(",")] if m else []
    lt = re.search(r"^tactics:\s*\[([^\]]*)\]", text, re.M)
    return {
        "title": re.search(r"^title:\s*(.+)$", text, re.M).group(1) if "title:" in text else path.stem,
        "id": "", "status": "unknown", "level": "", "tags": tags,
        "tactics": [x.strip() for x in lt.group(1).split(",")] if lt else [],
        "sample_ref": "", "fixture_ref": "", "correlation": "correlation:" in text,
        "logsource": {},
    }


def source_of(rule):
    ls = rule.get("logsource", {}) or {}
    if ls.get("product") == "windows":
        return "host"
    if ls.get("category") in ("proxy", "firewall") or ls.get("service") in ("dns", "ssl", "suricata"):
        return "network"
    return "host"


def main():
    rules = []
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        r = load(f)
        r["path"] = f.relative_to(ROOT).as_posix()
        rules.append(r)

    by_tech = {}
    tactic_count = 0
    for r in rules:
        tactic_count += len(r["tactics"])
        for t in r["tags"]:
            if isinstance(t, str) and TECH_RE.match(t):
                by_tech.setdefault(t.split(".", 1)[1].upper(), []).append(r)

    fixtures = {p.stem for p in (ROOT / "fixtures" / "malicious").glob("*.json")}
    out = []
    out.append("# Attack matrix (generated)\n")
    out.append(f"Generated {datetime.datetime.now(datetime.timezone.utc).isoformat()} from rule metadata. Do not edit by hand.\n")
    out.append(f"Rules: {len(rules)} | distinct techniques: {len(by_tech)} | tactic tags: {tactic_count} (not counted as techniques)\n")
    out.append("| Technique | Rule | Source | Status | Level | Fixture | Pin | Flags |")
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

    target = ROOT / "attack"
    target.mkdir(exist_ok=True)
    (target / "matrix.md").write_text("\n".join(out), encoding="utf-8")
    print(f"wrote attack/matrix.md: {len(rules)} rules, {len(by_tech)} techniques, {tactic_count} tactics")
    return 0


if __name__ == "__main__":
    sys.exit(main())
