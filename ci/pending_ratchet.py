#!/usr/bin/env python3
"""PENDING ratchet.

PENDING fixture links are allowed ONLY on files changed on the current branch.
CI fails if the number of PENDING links rises relative to the base branch.
Offline: uses git locally, no network.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = sys.argv[1] if len(sys.argv) > 1 else "main"


def count_pending(text):
    return len(re.findall(r'PENDING', text))


def current_pending():
    total = 0
    files = []
    for f in (ROOT / "sigma").rglob("*.yml"):
        n = count_pending(f.read_text(encoding="utf-8"))
        if n:
            total += n
            files.append((f.relative_to(ROOT).as_posix(), n))
    return total, files


def changed_files():
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only", BASE + "...HEAD"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL,
        )
        return set(out.splitlines())
    except Exception:
        return set()


def main():
    total, files = current_pending()
    changed = changed_files()
    offenders = [f for f, _ in files if f not in changed]
    baseline = 0
    try:
        out = subprocess.check_output(
            ["git", "show", f"{BASE}:ci/pending-baseline.txt"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL,
        )
        baseline = int(out.strip())
    except Exception:
        pass

    print(f"PENDING links: {total} (baseline {baseline})")
    if total > baseline:
        print("FAIL: PENDING count rose. Every new PENDING must be on a changed file and committed with a baseline bump.")
        return 1
    if offenders:
        print("FAIL: PENDING on unchanged files:")
        for f in offenders:
            print("  -", f)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
