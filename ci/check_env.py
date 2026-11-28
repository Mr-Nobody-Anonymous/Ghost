#!/usr/bin/env python3
"""Verify the installed dependencies match requirements.txt.

The gate compares generated query text against `attack/conversion.json`, which
was produced by one specific pySigma and set of backends. With no pinning, a
`pip install` on a new machine could silently produce different query text and
the gate would report a conversion mismatch - a true failure, but blamed on the
rules instead of the environment.

This makes the environment an explicit, checkable input:

    python3 ci/check_env.py            # fail on any version drift
    python3 ci/check_env.py --report   # print and do not fail (local debugging)

A package that is missing entirely is also a failure: the gate must not skip a
stage because an import happened to be unavailable.
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements.txt"

# Import name differs from distribution name for pySigma.
IMPORT_NAME = {
    "pysigma": "sigma",
    "pysigma-backend-splunk": "sigma.backends.splunk",
    "pysigma-backend-elasticsearch": "sigma.backends.elasticsearch",
    "pysigma-backend-kusto": "sigma.backends.kusto",
    "pyyaml": "yaml",
    "yara-python": "yara",
}


MIN_PYTHON = (3, 9)   # tools/evtx_to_fixture.py uses Path.is_relative_to (3.9+)


def check_python():
    if sys.version_info < MIN_PYTHON:
        have = "%d.%d.%d" % sys.version_info[:3]
        want = "%d.%d" % MIN_PYTHON
        return [f"python {have} is older than the required {want}"]
    return []


def parse_requirements():
    out = {}
    for line in REQ.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;]+)", line)
        if m:
            out[m.group(1)] = m.group(2)
        elif line:
            out[line] = None  # unpinned requirement: reported, not rejected here
    return out


def installed_version(dist):
    try:
        from importlib.metadata import version
    except ImportError:  # pragma: no cover
        return None
    try:
        return version(dist)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true", help="never fail")
    args = ap.parse_args()

    if not REQ.is_file():
        print("FAIL: requirements.txt missing - the gate cannot be reproduced",
              file=sys.stderr)
        return 0 if args.report else 1

    required = parse_requirements()
    problems, notes = check_python(), []
    for dist, want in sorted(required.items()):
        have = installed_version(dist)
        if want is None:
            notes.append(f"unpinned: {dist} (installed {have})")
            continue
        if have is None:
            problems.append(f"{dist} is not installed (pinned {want})")
        elif have != want:
            problems.append(f"{dist} {have} != pinned {want}")

    for note in notes:
        print(f"note {note}")
    for problem in problems:
        print(f"FAIL {problem}")

    if problems:
        print("\nThe gate's conversion results were produced with the pinned "
              "versions. Re-install from requirements.txt, or - if the upgrade is "
              "intended - update requirements.txt AND re-run ci/convert_check.py so "
              "attack/conversion.json reflects the new backend.", file=sys.stderr)
        return 0 if args.report else 1

    print(f"environment: python {'%d.%d' % sys.version_info[:2]}, "
          f"{len(required)} pinned packages match requirements.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
