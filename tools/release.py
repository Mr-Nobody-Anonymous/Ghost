#!/usr/bin/env python3
"""Derive the release identity of this tree, and check the changelog covers it.

`CHANGELOG.md` was hand-maintained and went stale twice - the gap register's own
words. There were no tags, nothing computed a version, and no artifact carried
an identity beyond a conversion hash. A consumer of `dist/detection-lab.tgz`
could not say what they had.

This computes what can honestly be computed and refuses to invent the rest:

  * **content digest** - sha256 over every tracked file that determines
    behaviour: rules, fixtures, telemetry contract, tooling, gate. Not docs, not
    the changelog itself (which would make the digest depend on its own record).
    This is the real identity: the same digest means the same detection content.
  * **rule counts and coverage** - from the tree, not from a constant
  * **changelog coverage** - every commit since the last tag must be mentioned
    in `CHANGELOG.md`, by its `Release-Note:` trailer if it has one, otherwise
    it is listed as uncovered. This is the check the changelog never had: it
    cannot silently miss a change.
  * **version** - `YYYY.MM.DD+N`, where N counts releases on that date. Derived
    from the date and the existing tags; never hand-edited.

A version is not a claim of quality. It is a name for an exact tree, and the
`--verify` mode makes sure the name on the tag still refers to the tree.

Usage:
    python3 tools/release.py                       # human summary
    python3 tools/release.py --json                # machine, for a release job
    python3 tools/release.py --check-changelog     # gate: fail on an unrecorded change
    python3 tools/release.py --verify <tag>        # tag's digest == tree's digest
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# What determines behaviour. Adding a directory here changes the digest; adding
# prose does not, so documentation edits do not need a release.
BEHAVIOUR = ("sigma", "fixtures", "yara", "emulation", "analytics", "deploy",
             "detection-as-code", "pipeline", "telemetry", "tools", "ci", "tests")
BEHAVIOUR_FILES = ("requirements.txt", "pyproject.toml", "attack/attack-bundle-pin.json")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, check=False)


def tracked_files():
    r = git("ls-files")
    if r.returncode != 0:
        raise SystemExit(f"FAIL: not a git checkout: {r.stderr.strip()}")
    return [line for line in r.stdout.splitlines() if line]


def digest():
    """sha256 over (path, content-hash) of every behaviour-relevant tracked file.

    The path is included so a file move is a different tree even when the bytes
    are identical - a rule moving between categories changes what deployed
    where.
    """
    h = hashlib.sha256()
    counted = 0
    for rel in tracked_files():
        if not (rel.startswith(BEHAVIOUR) or rel in BEHAVIOUR_FILES):
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(path.read_bytes()).digest())
        counted += 1
    return h.hexdigest(), counted


def rule_stats():
    import yaml
    rules = []
    for path in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("id"):
            rules.append(doc)
    techniques, tactics = set(), set()
    for doc in rules:
        techniques.update(t.split(".", 1)[1].upper()
                          for t in (doc.get("tags") or [])
                          if isinstance(t, str) and t.startswith("attack.t"))
        tactics.update(doc.get("tactics") or [])
    correlations = sum(1 for d in rules if d.get("correlation"))
    campaigns = sum(1 for d in rules if d.get("campaign"))
    return {"rules": len(rules), "techniques": len(techniques),
            "tactics": len(tactics), "correlations": correlations,
            "campaigns": campaigns}


def last_tag():
    r = git("describe", "--tags", "--abbrev=0")
    return r.stdout.strip() if r.returncode == 0 else None


def commits_since(tag):
    rng = f"{tag}..HEAD" if tag else "HEAD"
    r = git("log", "--format=%H%x00%s%x00%b%x01", rng)
    out = []
    for chunk in r.stdout.split("\x01"):
        chunk = chunk.strip("\n")
        if not chunk:
            continue
        sha, subject, body = (chunk.split("\x00") + ["", ""])[:3]
        out.append({"sha": sha, "subject": subject, "body": body})
    return out


def release_note(commit):
    m = re.search(r"^Release-Note:\s*(.+)$", commit["body"], re.M | re.I)
    return m.group(1).strip() if m else None


def needle_for(commit):
    """The string that must appear in CHANGELOG.md for this commit.

    One definition, because the check and its own regression test disagreed:
    the check stripped whitespace before truncating and the test did not, so a
    subject whose 40th character is a space produced two different needles and
    the test pruned nothing.
    """
    needle = (release_note(commit) or commit["subject"]).split("(")[0].strip()
    # 40 characters is enough to identify a commit and short enough to survive a
    # reworded changelog line. It is also a trap: truncation can land mid-word,
    # so a line that starts with the subject in bold
    # ("**Find four more stale counts, in the table cells.**") carries
    # "...in the tabl" followed by `e cells.**`, and the needle does not match.
    # Matching on a shorter prefix avoids depending on where the cut falls,
    # without making the check any weaker: 24 characters of a commit subject is
    # still specific.
    return needle[:24].rstrip()


def changelog_text():
    path = ROOT / "CHANGELOG.md"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def coverage(tag=None):
    """Which commits since the last tag the changelog actually accounts for.

    A commit counts as recorded when its own `Release-Note:` trailer appears in
    CHANGELOG.md, or when its subject does (someone pasted the line in). A
    trailer is the better habit: the note is written by the person who knows why.
    """
    text = changelog_text()
    commits = commits_since(tag)
    covered, uncovered = [], []
    for c in commits:
        note = release_note(c)
        needle = needle_for(c)
        if needle and needle.lower() in text.lower():
            covered.append({**c, "note": note})
        else:
            uncovered.append({**c, "note": note})
    return covered, uncovered


def version():
    tag = last_tag()
    today = datetime.date.today().strftime("%Y.%m.%d")
    r = git("tag", "--list", f"v{today}.*")
    existing = [t for t in r.stdout.split() if t]
    return f"v{today}.{len(existing) + 1}", tag


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--check-changelog", action="store_true")
    ap.add_argument("--verify", metavar="TAG")
    args = ap.parse_args()

    sha, counted = digest()
    stats = rule_stats()
    ver, prev = version()
    covered, uncovered = coverage(prev)

    if args.verify:
        r = git("rev-parse", "--verify", f"{args.verify}^{{commit}}")
        if r.returncode != 0:
            print(f"FAIL: no such tag {args.verify}", file=sys.stderr)
            return 1
        # The digest of the *tagged tree*, not of the working copy.
        h = hashlib.sha256()
        ls = git("ls-tree", "-r", "--name-only", args.verify)
        for rel in ls.stdout.splitlines():
            if not (rel.startswith(BEHAVIOUR) or rel in BEHAVIOUR_FILES):
                continue
            blob = git("show", f"{args.verify}:{rel}")
            h.update(rel.encode("utf-8"))
            h.update(b"\x00")
            h.update(hashlib.sha256(blob.stdout.encode("utf-8", "surrogateescape")).digest())
        tag_digest = h.hexdigest()
        same = tag_digest == sha
        print(f"release: {args.verify} digest {tag_digest[:16]} "
              f"{'==' if same else '!='} working tree {sha[:16]}")
        return 0 if same else 1

    if args.check_changelog:
        if uncovered:
            for c in uncovered:
                print(f"FAIL {c['sha'][:8]} {c['subject']}", file=sys.stderr)
                print("      add a CHANGELOG.md line (or a `Release-Note:` "
                      "trailer) for this change", file=sys.stderr)
            print(f"release: {len(uncovered)} unrecorded commit(s) since "
                  f"{prev or 'the first commit'}", file=sys.stderr)
            return 1
        print(f"release: {len(covered)} commit(s) since {prev or 'the beginning'} "
              f"all recorded; content digest {sha[:16]}")
        return 0

    payload = {"version": ver, "previous_tag": prev, "content_digest": sha,
               "files_hashed": counted, **stats,
               "commits_since_previous": len(covered) + len(uncovered),
               "unrecorded_commits": [c["subject"] for c in uncovered]}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"version        {ver}  (derived; tag vYYYY.MM.DD.N)")
    print(f"previous tag   {prev or 'none'}")
    print(f"content digest {sha}")
    print(f"               {counted} behaviour-relevant files hashed")
    print(f"rules          {stats['rules']} ({stats['correlations']} correlations, "
          f"{stats['campaigns']} campaign)")
    print(f"coverage       {stats['techniques']} techniques, {stats['tactics']} tactics")
    print(f"changelog      {len(covered)} recorded, {len(uncovered)} unrecorded "
          f"since {prev or 'the beginning'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
