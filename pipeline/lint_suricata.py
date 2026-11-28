#!/usr/bin/env python3
"""Lint the Suricata rules — the one detection format with no check at all.

`sigma/network/suricata_xid_xseq.rules` shipped with three signatures, and
nothing in the repo parsed them: not the schema validator (YAML only), not the
query lint (markdown only), not conversion (Sigma only). A typo in a content
match, a duplicate `sid`, or a rule with no `classtype` would have reached a
sensor or, more likely, never reached one because nobody noticed it was broken.

Checks, each of which breaks the rule outright on a real sensor:

  * rule parses: `action proto src sport -> dst dport (options)` and a
    parenthesised option list that closes
  * `sid` present, unique in the file and not in the reserved 1-1000000 range
    (those belong to the Emerging Threats / Suricata distribution)
  * `rev`, `msg`, `classtype` present
  * every `metadata: attack Txxxx` names a technique in the pinned ATT&CK bundle
  * sticky buffers (`http.uri`, `http.header`, ...) precede the `content` they
    apply to - a `content` before any buffer matches the whole payload, which is
    almost never what the author meant
  * content strings are hex/ASCII valid and end with a `;`

This is not a Suricata parser and does not claim to be; it is the subset whose
absence makes a rule silently inert. `suricata -T` is the real check and is
noted in the deploy README as the step to run on the sensor.

Usage: python3 pipeline/lint_suricata.py [path ...]
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE_RE = re.compile(
    r"^(?P<action>alert|drop|pass|reject)\s+(?P<proto>\w+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<opts>.*)\)\s*$"
)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
REV_RE = re.compile(r"\brev\s*:\s*(\d+)\s*;")
MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]*)"\s*;')
CLASSTYPE_RE = re.compile(r"\bclasstype\s*:\s*([\w-]+)\s*;")
ATTACK_RE = re.compile(r"\bmetadata\s*:[^;]*?\battack\s+(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
STICKY = {
    "http.uri", "http.header", "http.user_agent", "http.method", "http.host",
    "http.cookie", "http.request_body", "http.response_body", "dns.query",
    "tls.sni", "tls.cert_subject", "file.data", "file.name",
}
CONTENT_RE = re.compile(r'(?<![\w.])(content|pcre)\s*:', re.IGNORECASE)


def split_options(text):
    """Split on `;` outside double quotes and outside a pcre /regex/."""
    out, buf, quote, in_re = [], [], False, False
    for ch in text:
        if ch == '"' and not in_re:
            quote = not quote
        elif ch == "/" and not quote:
            in_re = not in_re
        if ch == ";" and not quote and not in_re:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return [o for o in out if o]


def check_file(path, pinned):
    problems = []
    raw = path.read_text(encoding="utf-8")
    seen_sids = {}
    n = 0
    for lineno, line in enumerate(raw.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = RULE_RE.match(s)
        if not m:
            problems.append(f"{path.name}:{lineno}: does not parse as a Suricata rule")
            continue
        n += 1
        opts_text = m.group("opts")
        if opts_text.count("(") != opts_text.count(")"):
            problems.append(f"{path.name}:{lineno}: unbalanced parentheses in options")
        opts = split_options(opts_text)

        sid, rev = SID_RE.search(s), REV_RE.search(s)
        if not sid:
            problems.append(f"{path.name}:{lineno}: no sid")
        else:
            sid_v = int(sid.group(1))
            if sid_v in seen_sids:
                problems.append(f"{path.name}:{lineno}: duplicate sid {sid_v} "
                                f"(also line {seen_sids[sid_v]})")
            seen_sids[sid_v] = lineno
            if sid_v < 1_000_000:
                problems.append(f"{path.name}:{lineno}: sid {sid_v} is in the range "
                                f"reserved for the ET/Suricata distribution; use >= 1000000")
        if not rev:
            problems.append(f"{path.name}:{lineno}: no rev")
        if not MSG_RE.search(s):
            problems.append(f"{path.name}:{lineno}: no msg")
        if not CLASSTYPE_RE.search(s):
            problems.append(f"{path.name}:{lineno}: no classtype")

        for tech in ATTACK_RE.findall(s):
            if pinned and tech.upper() not in pinned:
                problems.append(f"{path.name}:{lineno}: {tech} is not in the pinned "
                                f"ATT&CK bundle (revoked or invented)")

        # sticky-buffer ordering: content before a buffer matches raw payload
        buffered = False
        for opt in opts:
            name = opt.split(":", 1)[0].strip().lower()
            if name in STICKY:
                buffered = True
            elif CONTENT_RE.match(opt) and not buffered:
                problems.append(f"{path.name}:{lineno}: `{opt.split(':')[0]}` appears "
                                f"before any sticky buffer - it matches the whole payload, "
                                f"not the header/URI it was written for")
                buffered = True
    return n, problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="default: sigma/network/*.rules")
    args = ap.parse_args()

    paths = [pathlib.Path(p) for p in args.paths] or \
        sorted((ROOT / "sigma" / "network").glob("*.rules"))
    if not paths:
        print("suricata lint: no .rules files found")
        return 1

    pinned = set()
    pin_path = ROOT / "attack" / "attack-bundle-pin.json"
    if pin_path.is_file():
        pinned = set(json.loads(pin_path.read_text(encoding="utf-8")).get("techniques", []))

    total, problems = 0, []
    for p in paths:
        n, probs = check_file(p, pinned)
        total += n
        problems.extend(probs)
    for msg in problems:
        print("FAIL", msg)
    print(f"suricata lint: {total} rules checked in {len(paths)} file(s), "
          f"{len(problems)} problems")
    if problems:
        print("note: this checks structure, not efficacy. Run `suricata -T -S <file>` "
              "on the sensor before deployment.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
