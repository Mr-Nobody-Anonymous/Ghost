#!/usr/bin/env python3
"""Build a deployable bundle from attack/conversion.json.

A "deployable rule" is not a rule that validates; it is a rule that converts to
the backend you actually run. This script reads the conversion results the gate
produced and emits, per backend, only the rules that really convert - with a
manifest that records why each excluded rule was excluded.

Refuses to build when the conversion results are missing, empty, or older than
the rule they describe.

Usage:
    python3 deploy/build_bundle.py --backend splunk
    python3 deploy/build_bundle.py --backend splunk --out dist/splunk.txt
"""
import argparse
import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")

try:
    from sigma.collection import SigmaCollection
except ImportError:
    SigmaCollection = None

BACKEND_CLASSES = {
    "splunk": ("sigma.backends.splunk", "SplunkBackend"),
    "elastic": ("sigma.backends.elasticsearch", "LuceneBackend"),
    "kusto": ("sigma.backends.kusto", "KustoBackend"),
}

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONVERSION = ROOT / "attack" / "conversion.json"


def conversion_stamp(results):
    """Recompute ci/convert_check.py's content stamp, identically.

    It must hash the rule *files* as well as the stored results: a stamp derived
    from the results alone agrees with itself forever and cannot detect an edit.
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


# dedup_key tokens are conceptual ("host", "user", "dst"); a SIEM needs field
# names. `host::host` is CIM lookup syntax and is invalid in
# alert.suppress.fields, which takes plain field names.
DEDUP_FIELD = {
    "host": "host", "user": "user", "src": "src", "dst": "dest",
    "process": "process_name", "target": "target_filename",
    "directory": "file_path", "mutex": "process_name",
}


def _dedup_note(doc, backend):
    """How to apply the rule's declared suppression on the target platform.

    Emitted as guidance, not as SPL: pySigma produces the search, and suppression
    in Splunk is a saved-search setting (`alert.suppress`), not a query clause.
    Rewriting the SPL to dedupe would change what the rule proves.
    """
    raw = doc.get("dedup_key") or ""
    key = raw.replace("rule:" + str(doc.get("id")) + ":", "").strip(":")
    tokens = [x for x in key.split(":") if x]
    fields = [DEDUP_FIELD.get(x, x) for x in tokens]
    window = doc.get("dedup_window") or "5m"
    interval = doc.get("min_eval_interval") or "1m"
    note = {
        "dedup_tokens": tokens,
        "suppress_fields": fields,
        "suppress_period": window,
        "min_schedule": interval,
        "unknown_tokens": [x for x in tokens if x not in DEDUP_FIELD],
    }
    if backend == "splunk":
        note["splunk_savedsearch"] = (
            "alert.suppress = 1; alert.suppress.fields = " + ", ".join(fields) +
            f"; alert.suppress.period = {window}; "
            f"alert.schedule — not faster than {interval}")
    return note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", required=True, choices=["splunk", "elastic", "kusto"])
    ap.add_argument("--out", help="write the query text here (default: stdout)")
    ap.add_argument("--manifest", help="write the manifest JSON here")
    args = ap.parse_args()

    if not CONVERSION.is_file():
        print("FAIL: attack/conversion.json missing - run ci/convert_check.py first")
        return 1
    data = json.loads(CONVERSION.read_text(encoding="utf-8"))
    if args.backend not in data.get("backends", []):
        print(f"FAIL: conversion results do not cover {args.backend}; re-run the gate")
        return 1
    results = data.get("results", {})
    if not results:
        print("FAIL: conversion results are empty")
        return 1

    # Stale results: the stamp is a digest of the rules and their measured
    # outcomes, so a mismatch means a rule changed after conversion - the bundle
    # would ship a query nobody proved.
    stamp = data.get("generated_utc", "")
    if stamp.startswith("sha256:"):
        if conversion_stamp(results) != stamp:
            print("FAIL: attack/conversion.json does not match the rules on disk; "
                  "re-run python3 ci/convert_check.py")
            return 1
    else:
        print(f"FAIL: conversion.json has an unrecognised stamp {stamp!r}; "
              "re-run ci/convert_check.py")
        return 1

    deployable, excluded = [], []
    for path, entry in sorted(results.items()):
        backend = entry.get(args.backend, {})
        if backend.get("actual") == "supported":
            doc = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
            deployable.append({
                "path": path,
                "id": doc.get("id"),
                "title": doc.get("title"),
                "level": doc.get("level"),
                "lifecycle": doc.get("lifecycle"),
                "correlation": bool(entry.get("correlation")),
                # Suppression travels with the query. A rule that ships without
                # these fires once per event: 37 rules x every matching process
                # create is an unusable alert queue, and the numbers exist in the
                # source but were never emitted anywhere.
                "dedup_key": doc.get("dedup_key"),
                "dedup_window": doc.get("dedup_window"),
                "min_eval_interval": doc.get("min_eval_interval"),
                "dedup_note": _dedup_note(doc, args.backend),
            })
        else:
            excluded.append({
                "path": path,
                "reason": backend.get("reason", "declared unsupported"),
            })

    # Emit the real query text: a bundle of titles is shelfware with extra steps.
    if SigmaCollection is None:
        print("FAIL: pySigma required to emit query text")
        return 1
    module, cls_name = BACKEND_CLASSES[args.backend]
    backend_cls = getattr(__import__(module, fromlist=[cls_name]), cls_name)

    texts = {p: (ROOT / p).read_text(encoding="utf-8") for p in results}
    member_cache = {}
    for path, text in texts.items():
        if "correlation:" not in text:
            continue
        ids = []
        inside = False
        for line in text.splitlines():
            if line.startswith("  rules:"):
                inside = True
                continue
            if inside:
                if line.strip().startswith("- "):
                    ids.append(line.strip()[2:].strip())
                else:
                    break
        member_cache[path] = ids

    lines = [
        f"-- {args.backend} bundle - conversion {data['generated_utc']}",
        f"-- deployable: {len(deployable)}  excluded: {len(excluded)}",
        "-- Every query below was produced by pySigma from the cited rule.",
        "",
    ]
    failures = 0
    for item in deployable:
        path = item["path"]
        text = texts[path]
        chunks = [text]
        for rid in member_cache.get(path, []):
            for other, other_text in texts.items():
                if f"id: {rid}" in other_text and other != path:
                    chunks.append(other_text)
        combined = "\n---\n".join(chunks)
        try:
            queries = backend_cls().convert(SigmaCollection.from_yaml(combined))
            if not queries or not any(str(q).strip() for q in queries):
                raise ValueError("empty conversion")
        except Exception as exc:
            failures += 1
            print(f"FAIL {path}: {type(exc).__name__}: {exc}")
            continue
        lines.append(f"-- [{item['level']}] {item['title']}  ({item['id']})")
        lines.append(f"-- source: {path}")
        if item["correlation"]:
            lines.append("-- CORRELATION: deploy the member rules as well")
        lines.append("")
        lines.append(str(queries[-1]).strip() if item["correlation"] else str(queries[0]).strip())
        lines.append("")
    if failures:
        print(f"FAIL: {failures} rules declared convertible but failed at build time")
        return 1

    text = "\n".join(lines)
    if args.out:
        out = ROOT / args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}: {len(deployable)} deployable, {len(excluded)} excluded")
    else:
        print(text)

    if args.manifest:
        path = ROOT / args.manifest
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "backend": args.backend,
            "generated_utc": data["generated_utc"],
            "deployable": deployable,
            "excluded": excluded,
        }, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
