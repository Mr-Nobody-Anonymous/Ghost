#!/usr/bin/env python3
"""Backend conversion gate.

Every rule declares which backends it converts to in a `conversion:` block:

    conversion:
      splunk: supported
      elastic: unsupported
      kusto: unsupported
      note: why

A rule with no block claims support on all three backends. This script converts
each rule (and each correlation rule together with its member rules) with the
real pySigma backend and compares the outcome to the claim. A mismatch in
either direction fails the gate: an over-claim is a rule that will not deploy,
an under-claim is a rule we are silently giving up on.

Results are written to attack/conversion.json so the coverage matrix can report
per-rule deployability instead of asserting it.

Missing pySigma is a hard failure, not a skip.
"""
import argparse
import datetime
import json
import pathlib
import sys

try:
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule
except ImportError:
    SigmaCollection = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
BACKENDS = {
    "splunk": ("sigma.backends.splunk", "SplunkBackend"),
    "elastic": ("sigma.backends.elasticsearch", "LuceneBackend"),
    "kusto": ("sigma.backends.kusto", "KustoBackend"),
}
DEFAULT_CLAIM = "supported"


def load_backends(names):
    loaded = {}
    for name in names:
        module, cls = BACKENDS[name]
        try:
            mod = __import__(module, fromlist=[cls])
        except ImportError:
            return None, f"backend {name} not installed ({module}) - partial availability is not a pass"
        backend_cls = getattr(mod, cls, None)
        if backend_cls is None:
            return None, f"backend {name} has no class {cls}"
        loaded[name] = backend_cls
    return loaded, None


def read_rules():
    """Return (files_with_text) so each rule can be converted in isolation."""
    files = []
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        text = f.read_text(encoding="utf-8")
        files.append((f, text, is_correlation(text)))
    return files


def is_correlation(text):
    return any(line.startswith("correlation:") for line in text.splitlines())


def convert_one(text, backend_cls):
    """Return (ok, detail). Converts without consulting the claim."""
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:  # load failure is distinct from conversion failure
        return False, f"load error: {type(exc).__name__}: {exc}"
    try:
        out = backend_cls().convert(collection)
    except NotImplementedError as exc:
        return False, f"unsupported: {str(exc).splitlines()[0][:160]}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
    if not out or not any(str(q).strip() for q in out):
        return False, "empty conversion"
    return True, ""


def member_context(correlation_text, all_texts):
    """A correlation rule needs its members present in the same collection."""
    ids = []
    in_rules = False
    for line in correlation_text.splitlines():
        if line.startswith("  rules:"):
            in_rules = True
            continue
        if in_rules:
            if line.strip().startswith("- "):
                ids.append(line.strip()[2:].strip())
            else:
                break
    wanted = set(ids)
    chunks = []
    for text in all_texts:
        for rid in wanted:
            if f"id: {rid}" in text:
                chunks.append(text)
    return "\n---\n".join(chunks + [correlation_text])


def claim_of(text):
    """Parse the conversion block without importing YAML for the claim itself."""
    claim = {}
    note = ""
    inside = False
    for line in text.splitlines():
        if line.startswith("conversion:"):
            inside = True
            continue
        if inside:
            if line and not line.startswith(" "):
                break
            stripped = line.strip()
            for backend in BACKENDS:
                if stripped.startswith(backend + ":"):
                    claim[backend] = stripped.split(":", 1)[1].strip()
            if stripped.startswith("note:"):
                note = stripped.split(":", 1)[1].strip()
    return claim, note


def _content_stamp(results):
    """A stable identity for this conversion result, not a clock reading.

    Hashes the rule files *and* their measured outcomes. Hashing only the stored
    result would make the stamp agree with itself no matter how the rules
    changed - a check that cannot fail, which is the exact defect this repo keeps
    finding. Hashing only the rules would make it change on a comment edit
    without invalidating anything, so both go in.
    """
    import hashlib
    digest = hashlib.sha256()
    for path in sorted(results):
        f = ROOT / path
        digest.update(path.encode())
        digest.update(hashlib.sha256(f.read_bytes()).hexdigest().encode()
                      if f.is_file() else b"<missing>")
        digest.update(json.dumps(results[path], sort_keys=True).encode())
    return "sha256:" + digest.hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backends", nargs="+", default=list(BACKENDS),
                    help="subset of: " + ", ".join(BACKENDS))
    ap.add_argument("--write", default=str(ROOT / "attack" / "conversion.json"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if SigmaCollection is None:
        print("FAIL: pySigma is not installed - conversion cannot be proven")
        return 1

    backends, err = load_backends(args.backends)
    if err:
        print(f"FAIL: {err}")
        return 1

    files = read_rules()
    if not files:
        print("FAIL: no rules found")
        return 1

    all_texts = [text for _, text, _ in files]
    results = {}
    failures = []
    checked = 0

    for path, text, correlation in files:
        rel = path.relative_to(ROOT).as_posix()
        claim, note = claim_of(text)
        target = member_context(text, all_texts) if correlation else text
        missing = [b for b in backends if b not in claim]
        if missing and len(claim) > 0:
            # partial block: undeclared backends are over-claims by default
            for b in missing:
                claim[b] = DEFAULT_CLAIM
        entry = {}
        for name, cls in backends.items():
            checked += 1
            ok, detail = convert_one(target, cls)
            declared = claim.get(name, DEFAULT_CLAIM)
            actual = "supported" if ok else "unsupported"
            entry[name] = {"actual": actual, "declared": declared}
            if actual != declared:
                failures.append(
                    f"MISMATCH {rel} [{name}]: declared {declared}, actually {actual}"
                    + (f" ({detail})" if detail else "")
                )
            elif not ok and not args.quiet:
                print(f"ok   {rel} [{name}]: declared unsupported - {detail}")
            if not ok:
                entry[name]["reason"] = detail
        if note:
            entry["note"] = note
        entry["correlation"] = correlation
        results[rel] = entry

    out = {
        "generated_utc": _content_stamp(results),
        "rules": len(files),
        "backends": list(backends),
        "results": results,
    }
    target = pathlib.Path(args.write)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    if failures:
        print()
        for line in failures:
            print("FAIL", line)
        print(f"\nconversion: {len(failures)} declaration/actual mismatches "
              f"across {checked} rule/backend pairs")
        return 1

    per_backend = {name: sum(1 for e in results.values() if e[name]["actual"] == "supported")
                   for name in backends}
    summary = ", ".join(f"{k} {v}/{len(files)}" for k, v in per_backend.items())
    print(f"conversion: {summary} rules convert; all declarations match actual output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
