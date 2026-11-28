#!/usr/bin/env python3
"""One-off schema migration: split tactics from techniques and add required fields.

Text-based so rule bodies stay readable. Safe to re-run: it adds only missing
fields and never removes a technique tag.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TACTIC_RE = re.compile(r"^attack\.[a-z][a-z0-9-]+$")
TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def migrate(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    i = 0
    tactics = []
    while i < len(lines):
        line = lines[i]
        if line.startswith("tags:"):
            if "[" in line and "]" in line:
                inner = line[line.index("[") + 1:line.index("]")]
                tags = [x.strip() for x in inner.split(",") if x.strip()]
                out.append("tags: [" + ", ".join(t for t in tags if TECH_RE.match(t)) + "]")
                tactics = [t for t in tags if TACTIC_RE.match(t)]
                i += 1
                continue
            out.append(line)
            i += 1
            block = []
            while i < len(lines) and lines[i].startswith("  - "):
                t = lines[i][4:].strip()
                block.append(t)
                i += 1
            tactics = [t for t in block if TACTIC_RE.match(t)]
            techniques = [t for t in block if TECH_RE.match(t)]
            if techniques:
                out.append("tags: [" + ", ".join(techniques) + "]")
            else:
                out.extend("  - " + t for t in block)
            continue
        out.append(line)
        i += 1

    text = "\n".join(out)
    if tactics and "tactics:" not in text:
        insert_at = text.index("\n", text.index("tags:")) + 1 if "tags:" in text else 0
        text = text[:insert_at] + "tactics: [" + ", ".join(dict.fromkeys(tactics)) + "]\n" + text[insert_at:]
    if "dedup_key:" not in text:
        m = re.search(r"^id:\s*(\S+)\s*$", text, re.MULTILINE)
        rid = m.group(1) if m else "unknown"
        text = text.replace(
            f"id: {rid}\n",
            f"id: {rid}\ndedup_key: \"rule:{rid}:host:user\"\n",
            1,
        )
    if "references:" not in text:
        tech = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", text)
        ref = f"https://attack.mitre.org/techniques/{tech.group(1).upper()[1:]}/" if tech else "https://attack.mitre.org/"
        block = "references:\n  - " + ref + "\n  - inventory.md\n"
        if "\nlogsource:" in text:
            text = text.replace("\nlogsource:", "\n" + block + "logsource:", 1)
        else:
            text += "\n" + block
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def main():
    files = sorted((ROOT / "sigma").rglob("*.yml"))
    for f in files:
        migrate(f)
    print(f"migrated {len(files)} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
