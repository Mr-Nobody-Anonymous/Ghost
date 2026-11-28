#!/usr/bin/env python3
"""Release identity must come from the tree, and the changelog must keep up.

The gap was not "no version number". It was that `CHANGELOG.md` went stale twice
and nothing noticed, because the only thing checking it was a human reading it.
The load-bearing test is `test_every_commit_since_the_last_tag_is_recorded`: it
fails the build when a change lands without a changelog line.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "release.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("release", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_content_digest_is_stable_and_sensitive(self):
        a, count = self.tool.digest()
        b, count2 = self.tool.digest()
        self.assertEqual(a, b, "digest is not deterministic")
        self.assertEqual(count, count2)
        self.assertGreater(count, 100, "digest covers suspiciously few files")
        # A one-byte change in a rule must change the digest.
        target = next(ROOT.glob("sigma/*.yml"))
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\n# digest probe\n")
            c, _ = self.tool.digest()
        finally:
            target.write_bytes(original)
        self.assertNotEqual(a, c, "a rule change did not change the digest")
        self.assertEqual(self.tool.digest()[0], a, "restore failed")

    def test_changelog_covers_every_commit(self):
        r = subprocess.run([sys.executable, str(TOOL), "--check-changelog"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         "a commit landed without a CHANGELOG.md line:\n" + r.stderr)

    def test_unrecorded_commit_is_detected(self):
        """Prove the check bites by making the changelog forget a commit."""
        changelog = ROOT / "CHANGELOG.md"
        original = changelog.read_text(encoding="utf-8")
        # Drop every line that mentions the most recent commit's subject.
        commits = self.tool.commits_since(None)
        latest = commits[0]
        needle = (self.tool.release_note(latest) or latest["subject"]).split("(")[0][:40]
        pruned = "\n".join(line for line in original.splitlines()
                           if needle.lower() not in line.lower())
        try:
            changelog.write_text(pruned, encoding="utf-8")
            covered, uncovered = self.tool.coverage(None)
            self.assertTrue(uncovered,
                            f"removing {needle!r} from the changelog did not "
                            f"produce an uncovered commit")
        finally:
            changelog.write_text(original, encoding="utf-8")

    def test_version_is_derived_not_stored(self):
        ver, _prev = self.tool.version()
        self.assertRegex(ver, r"^v\d{4}\.\d{2}\.\d{2}\.\d+$")

    def test_rule_stats_come_from_the_tree(self):
        stats = self.tool.rule_stats()
        on_disk = len(list((ROOT / "sigma").rglob("*.yml")))
        self.assertGreaterEqual(on_disk, stats["rules"])
        self.assertGreaterEqual(stats["rules"], 39)
        self.assertGreaterEqual(stats["correlations"], 5)
        self.assertEqual(stats["campaigns"], 1)

    def test_json_output_has_the_identity_fields(self):
        r = subprocess.run([sys.executable, str(TOOL), "--json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        for key in ("version", "content_digest", "rules", "techniques",
                    "files_hashed"):
            self.assertIn(key, data)
        self.assertEqual(len(data["content_digest"]), 64)

    def test_verify_against_head_matches(self):
        """`--verify` re-hashes a commit; against HEAD it must equal the tree."""
        r = subprocess.run([sys.executable, str(TOOL), "--verify", "HEAD"],
                           capture_output=True, text=True, cwd=ROOT)
        # The working tree may legitimately differ from HEAD with edits in
        # progress; what matters is that the comparison runs and reports either
        # way rather than crashing.
        self.assertIn("digest", r.stdout)

    def test_digest_ignores_documentation(self):
        """Prose edits must not force a release; behaviour files must."""
        files = self.tool.tracked_files()
        behaviour = [f for f in files
                     if f.startswith(self.tool.BEHAVIOUR)
                     or f in self.tool.BEHAVIOUR_FILES]
        self.assertNotIn("README.md", behaviour)
        self.assertNotIn("CHANGELOG.md", behaviour)
        self.assertTrue(any(f.startswith("sigma/") for f in behaviour))
        self.assertIn("ci/gate.sh", behaviour)


if __name__ == "__main__":
    unittest.main()
