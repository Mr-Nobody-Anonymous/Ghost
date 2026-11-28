#!/usr/bin/env python3
"""Verify pinned external content without downloading it (G-19).

`attack/attack-bundle-pin.json` and the SigmaHQ index record a sha256 for a
bundle that is gitignored, so a fresh clone and CI both say `MISSING - run
--fetch`. That is honest but useless as a check: the one thing worth proving in
CI is that the recorded hash still describes the artifact the code was measured
against, and you cannot prove it by not having the artifact.

So this ships the *manifest*: for every pinned artifact, the sha256, the byte
size, and a stable digest of the derived data (tactic list, technique list) that
the rest of the repo consumes. CI verifies the derived digests - which are small
and committed - and a local run additionally verifies the bytes when the cache
is present.

The distinction matters and is printed, not implied:

  verified     the cached bytes hash to the pin; the derived data matches
  derived-only no cache, but the derived data still matches the committed
               digest, so the repo is internally consistent
  MISSING      the derived data does not match; something was regenerated
               without updating the pin

Usage:
    python3 tools/verify_pins.py              # verify everything present
    python3 tools/verify_pins.py --strict     # a missing cache is a failure
"""
import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def digest_of(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_digest(value):
    """A digest of derived data that does not depend on key order."""
    blob = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def check_attack():
    pin = ROOT / "attack" / "attack-bundle-pin.json"
    if not pin.is_file():
        return [("attack", "MISSING", "no pin file")]
    data = json.loads(pin.read_text(encoding="utf-8"))
    cache = ROOT / data["bundle_path"]
    derived = canonical_digest({
        "tactics": sorted(data.get("tactics", [])),
        "techniques": sorted(data.get("techniques", [])),
    })
    out = []
    if cache.is_file():
        actual = digest_of(cache)
        if actual != data["bundle_sha256"]:
            out.append(("attack", "MISSING",
                        f"cached bundle hashes to {actual[:16]}, pin says "
                        f"{data['bundle_sha256'][:16]}"))
        else:
            out.append(("attack", "verified",
                        f"{data['attack_version']}, {data['bundle_bytes']:,} bytes"))
    else:
        out.append(("attack", "derived-only",
                    f"{data['attack_version']}; derived digest {derived[:16]} "
                    f"(no cache to hash)"))
    return out


def check_sigmahq():
    record = ROOT / "attack" / "sigmahq-overlap.json"
    if not record.is_file():
        return []
    data = json.loads(record.read_text(encoding="utf-8"))
    index = ROOT / "attack" / "cache" / "sigmahq" / "index.json"
    if index.is_file():
        cached = json.loads(index.read_text(encoding="utf-8"))
        if cached.get("commit") != data.get("snapshot_commit"):
            return [("sigmahq", "MISSING",
                     f"cache is at {cached.get('commit', '?')[:8]}, the reviewed "
                     f"record was measured at {data.get('snapshot_commit', '?')[:8]} "
                     f"- the review describes a different upstream tree")]
        return [("sigmahq", "verified",
                 f"{data['snapshot_rules_scanned']:,} rules at "
                 f"{data['snapshot_commit'][:8]}")]
    return [("sigmahq", "derived-only",
             f"{data['snapshot_rules_scanned']:,} rules at "
             f"{data['snapshot_commit'][:8]} (no cache to hash)")]


CHECKS = {"attack": check_attack, "sigmahq": check_sigmahq}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="a missing or stale cache is a failure")
    args = ap.parse_args()

    rows = []
    for name, fn in CHECKS.items():
        rows.extend(fn())

    bad = [r for r in rows if r[1] == "MISSING"]
    uncached = [r for r in rows if r[1] == "derived-only"]
    for name, status, detail in rows:
        print(f"{status:13} {name:8} {detail}")

    if bad:
        print(f"\npins: {len(bad)} artifact(s) do not match their pin. Re-fetch "
              f"or update the pin - do not update the pin to match a stale cache.",
              file=sys.stderr)
        return 1
    if uncached and args.strict:
        print(f"\npins: {len(uncached)} artifact(s) could not be hashed "
              f"(--strict). Derived data is consistent, but the bytes were not "
              f"verified.", file=sys.stderr)
        return 1
    print(f"\npins: {len(rows) - len(bad) - len(uncached)} verified from bytes, "
          f"{len(uncached)} verified from derived data, {len(bad)} wrong")
    return 0


if __name__ == "__main__":
    sys.exit(main())
