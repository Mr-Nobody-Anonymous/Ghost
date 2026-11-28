#!/usr/bin/env python3
"""Generate the `rules_referencing` and `fixture_refs` sections of samples/PINS.md."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = ROOT / "samples" / "PINS.md"

START = "<!-- GENERATED:START -->"
END = "<!-- GENERATED:END -->"


def main():
    refs = {}
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        text = f.read_text(encoding="utf-8")
        m = re.search(r"^sample_ref:\s*(\S+)", text, re.MULTILINE)
        rid = re.search(r"^id:\s*(\S+)", text, re.MULTILINE)
        if m and rid:
            refs.setdefault(m.group(1), []).append(rid.group(1))
    fx = {}
    for f in sorted((ROOT / "fixtures" / "per_rule").glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        fx.setdefault(d.get("sample_ref", ""), []).append(f.stem[:8])

    lines = [START, "## Generated references", "", "| Sample ref | Rules | Fixtures |", "|---|---|---|"]
    for ref in sorted(refs):
        lines.append(f"| {ref} | {len(refs[ref])} | {len(fx.get(ref, []))} |")
    lines.append("")
    lines.append("Staleness rule: when a pin's hash changes, every rule and fixture")
    lines.append("listed above must be revalidated and their status set to `stale`.")
    lines.append(END)

    text = PINS.read_text(encoding="utf-8")
    if START in text and END in text:
        text = text[:text.index(START)] + "\n".join(lines) + text[text.index(END) + len(END):]
    else:
        text = text.rstrip() + "\n\n" + "\n".join(lines) + "\n"
    PINS.write_text(text, encoding="utf-8")
    print(f"generated references for {len(refs)} sample pins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
