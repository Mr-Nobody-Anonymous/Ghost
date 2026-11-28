#!/usr/bin/env python3
"""Check the deployment procedure against the repository it describes (G-27).

`docs/deployment.md` was written and never executed. That is an honest status for
the parts that need a Splunk indexer, an Elastic cluster and a Windows host. It
is not honest for the parts that are commands in *this* repository: if the
procedure says `python3 deploy/build_bundle.py --backend splunk` produces a
bundle, that command can be run here, right now, and the doc should say what it
actually produces.

Three kinds of check, in increasing order of usefulness:

  1. Every path the doc mentions exists.
  2. Every count it states (rules, correlations) matches the repository.
  3. Every command that only depends on this repo runs and exits 0.

What cannot be checked, and is printed as such: the Splunk/Elastic/Sentinel
parts, which need a deployment, and the Sysmon install, which needs Windows.

Usage:
    python3 tools/check_deployment_doc.py
    python3 tools/check_deployment_doc.py --json
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "deployment.md"

# Commands in the doc that are fully determined by this repository. Run them.
RUNNABLE = [
    # All three backends, deliberately. `convert_check.py` writes
    # attack/conversion.json as a side effect, so running it with one backend
    # rewrites the file with the other two blank - and every downstream consumer
    # then reads "elastic converts nothing". This tool caused that for a while:
    # it ran the Splunk-only command the doc shows, and the matrix test failed
    # two stages later with no obvious connection.
    ["python3", "ci/convert_check.py", "--backends", "splunk", "elastic", "kusto"],
    ["python3", "deploy/build_bundle.py", "--backend", "splunk",
     "--out", "dist/_deploycheck.spl", "--manifest", "dist/_deploycheck.json"],
    ["python3", "pipeline/build_field_map.py", "--check"],
    ["python3", "tools/build_sacl_script.py", "--check"],
]

# Commands that need a real stack. Named so the skip is explicit rather than a
# silent pass - this is the whole reason the gap exists.
NEEDS_A_DEPLOYMENT = [
    "cp deploy/fieldmap/props-sigma.conf $SPLUNK_HOME/...  (needs Splunk)",
    "PUT _ingest/pipeline/sigma-canonical                      (needs Elastic)",
    "sysmon64.exe -c                                            (needs Windows)",
    ".\\deploy\\telemetry\\set-sacls.ps1                           (needs Windows + admin)",
    "python3 tools/verify_baseline.py --input baseline.xml      (needs a capture)",
    "splunk add saved-search ...                                (needs Splunk)",
    "Kusto .create-or-alter function Sigma_...                  (needs Sentinel)",
]


def deployability():
    """Per-backend supported count, from conversion.json rather than the matrix.

    The matrix is generated FROM conversion.json; reading the derivative to
    check a doc that describes the source means one stale generation makes the
    checker report the doc as wrong when the matrix is what is wrong. That
    happened: an earlier run wrote conversion.json with two backends blank, the
    matrix was regenerated from it, and this function then blamed the prose.
    """
    conv = json.loads((ROOT / "attack" / "conversion.json").read_text(
        encoding="utf-8"))
    results = conv.get("results", {})
    counts = {
        backend: sum(1 for entry in results.values()
                     if (entry.get(backend) or {}).get("actual") == "supported")
        for backend in ("splunk", "elastic", "kusto")
    }
    return len(results), counts


def stated_counts(text):
    """(phrase, claimed, actual) for every count the doc asserts."""
    rules = list((ROOT / "sigma").rglob("*.yml"))
    n_rules = len(rules)
    corr = 0
    import yaml
    for path in rules:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("correlation"), dict):
            corr += 1
    out = []
    total, per_backend = deployability()
    if total != n_rules:
        out.append(("attack/matrix.md deployability table", total, n_rules))
    for backend, count in per_backend.items():
        for match in re.finditer(rf"\b{backend}\b[^\n]*?\|\s*(\d+)/", text, re.I):
            claimed = int(match.group(1))
            if claimed != count:
                out.append((f"{backend} conversion count", claimed, count))
    # Only phrases that assert a TOTAL. "34 of the 39 rules are Windows-only" is
    # a true subset and flagging it trains the reader to ignore this check.
    for match in re.finditer(r"\b(\d+)/(\d+)\b", text):
        claimed = int(match.group(2))
        if claimed != n_rules:
            out.append((match.group(0), claimed, n_rules))
    for match in re.finditer(r"\b(\d+)\s+(?:rules|queries)\b(?!\s+to\b)", text):
        claimed = int(match.group(1))
        if claimed != n_rules:
            out.append((match.group(0), claimed, n_rules))
    for match in re.finditer(r"\b(one|two|three|four|five|six|seven|eight|nine|"
                             r"ten|eleven|twelve)\s+(?:Splunk-only\s+)?"
                             r"correlation", text, re.I):
        words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
                 "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
                 "twelve": 12}
        claimed = words[match.group(1).lower()]
        if claimed != corr:
            out.append((match.group(0), claimed, corr))
    return out


def referenced_paths(text):
    """Repo paths the doc tells the reader to use."""
    found = set()
    for match in re.finditer(r"`((?:deploy|tools|pipeline|telemetry|attack|ci|"
                             r"detection-as-code|response|analytics|hunt|"
                             r"fixtures|samples|baseline|docs|dist)/[^`\s]+)`", text):
        path = match.group(1).rstrip(".,;")
        if "*" in path or path.endswith("/"):
            continue
        found.add(path)
    return found


def run_commands():
    results = []
    for cmd in RUNNABLE:
        r = subprocess.run([str(part) if part != "python3" else sys.executable
                            for part in cmd],
                           cwd=ROOT, capture_output=True, text=True)
        results.append({"command": " ".join(cmd), "exit": r.returncode,
                        "tail": (r.stdout + r.stderr).strip().splitlines()[-1:]})
    # Restore conversion.json: the run above rewrites it, and a checker that
    # leaves the repository in a different state than it found it is not a
    # checker.
    guard = subprocess.run(["git", "status", "--porcelain", "attack/conversion.json"],
                           cwd=ROOT, capture_output=True, text=True)
    if guard.stdout.strip():
        subprocess.run(["git", "checkout", "--", "attack/conversion.json"],
                       cwd=ROOT, check=False)
    for name in ("dist/_deploycheck.spl", "dist/_deploycheck.json"):
        target = ROOT / name
        if target.is_file():
            target.unlink()
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    text = DOC.read_text(encoding="utf-8")
    problems = []

    # Read-only checks first. `run_commands` below rewrites conversion.json and
    # restores it via git; anything measured during that window is measured
    # against a half-written file, which is how this tool briefly reported that
    # the doc's elastic counts were wrong when the file was the thing that was
    # wrong.
    for path in sorted(referenced_paths(text)):
        if not (ROOT / path).exists():
            problems.append(f"docs/deployment.md tells the reader to use "
                            f"{path}, which does not exist")

    for phrase, claimed, actual in stated_counts(text):
        problems.append(f"docs/deployment.md says {phrase!r}; the repository "
                        f"has {actual}")

    runs = run_commands()
    for run in runs:
        if run["exit"] != 0:
            problems.append(f"the doc's own command exits {run['exit']}: "
                            f"{run['command']}")

    report = {"problems": problems, "ran": runs,
              "not_runnable_here": NEEDS_A_DEPLOYMENT}

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        passed = len(runs) - sum(1 for r in runs if r["exit"] != 0)
        print(f"deployment: {passed}/{len(runs)} procedure commands run here; "
              f"{len(NEEDS_A_DEPLOYMENT)} steps need a live stack and are not "
              f"verified")
        if not problems:
            print("            the unverified steps are the gap, not a detail: "
                  "no alert has been deployed from this page")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
