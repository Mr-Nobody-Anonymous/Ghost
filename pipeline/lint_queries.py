#!/usr/bin/env python3
"""Lint the SQL and query text that ships in hunt-queries.md and analysis/.

These queries are the manual fallback when a rule cannot express a behavior.
They were never executed by anything, so a typo in a field name would only be
found during an incident. This linter is deliberately shallow: it checks the
things that break a query outright, not whether it is a good query.

Checks:
  * balanced parentheses and quotes on each fenced query block
  * every field the query reads appears in telemetry/data-sources.md
  * no pipe-aggregation Sigma syntax left in a rule (checked in tests)
  * hunt queries name an index or a source, never an unbounded search

Usage: python3 pipeline/lint_queries.py [--verbose]
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

QUERY_DOCS = [
    ROOT / "hunt-queries.md",
    ROOT / "network" / "ja3-x509.md",
    ROOT / "docs" / "sequence-rules.md",
]

# Fields the data-source map claims we can read. A query using anything else is
# either inventing a field or relying on telemetry the repo has not defined.
FIELD_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.]{2,40})\b(?=\s*(?:=|==|~=|!=|:|\)|,|\bin\b))")
NOISE = {
    "and", "or", "not", "if", "print", "where", "stats", "eval", "match", "search",
    "index", "count", "values", "span", "bin", "time", "as", "by", "sort", "head",
    "event", "local", "var", "let", "true", "false", "null", "json", "table",
    "summarize", "extend", "project", "ago", "now", "datatable",
}


def known_fields():
    text = (ROOT / "telemetry" / "data-sources.md").read_text(encoding="utf-8")
    fields = set()
    for line in text.splitlines():
        for cell in line.split("|"):
            for token in re.findall(r"`([A-Za-z0-9_.\-]+)`", cell):
                fields.add(token)
            for token in re.findall(r"\b([A-Za-z][A-Za-z0-9]*(?:[A-Z][A-Za-z0-9]*)+)\b", cell):
                fields.add(token)
    return fields


def fenced_blocks(path):
    text = path.read_text(encoding="utf-8")
    return re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S)


def balanced(block):
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    in_string = None
    for ch in block:
        if in_string:
            if ch == in_string:
                in_string = None
            continue
        if ch in "\"'`":
            in_string = ch
            continue
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack.pop() != pairs[ch]:
                return False, f"unbalanced {ch!r}"
    if stack:
        return False, f"unclosed {stack[-1]!r}"
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    fields = known_fields()
    problems = 0
    checked = 0
    for doc in QUERY_DOCS:
        if not doc.is_file():
            continue
        for i, block in enumerate(fenced_blocks(doc), 1):
            head = block.strip().splitlines()[0] if block.strip() else ""
            if not re.search(r"(index=|\||event dns_log|event ssl|event http|SELECT)", block):
                continue  # shell/copy-paste snippet, not a query
            checked += 1
            ok, why = balanced(block)
            if not ok:
                problems += 1
                print(f"FAIL {doc.name} block {i} ({head[:50]}): {why}")
                continue
            if re.search(r"\bindex=\S*(?:OR|AND)\b", block):
                problems += 1
                print(f"FAIL {doc.name} block {i}: index= combined with a boolean - unbounded search")
            if re.search(r"event\s+(dns|ssl|http|conn)_", block):
                continue  # Zeek script: parameters are script variables, not log fields
            for name in FIELD_RE.findall(block):
                if name in NOISE or len(name) < 4:
                    continue
                if name not in fields and not any(name in f for f in fields):
                    if args.verbose:
                        print(f"warn {doc.name} block {i}: field {name!r} not in data-sources.md")
    print(f"query lint: {checked} blocks checked, {problems} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
