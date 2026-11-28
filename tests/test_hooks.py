#!/usr/bin/env python3
"""The git hooks must exist, be executable, and actually reject bad input.

A hook that is a file nobody can execute, or that exits 0 on a three-character
subject, is worse than no hook: it looks like enforcement. These tests invoke
the scripts directly with crafted input, the same way git would.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOKS = ROOT / ".githooks"


class HookTest(unittest.TestCase):
    def test_hooks_are_executable(self):
        for name in ("pre-commit", "commit-msg"):
            path = HOOKS / name
            self.assertTrue(path.is_file(), f"{name} is missing")
            self.assertTrue(path.stat().st_mode & 0o111,
                            f"{name} is not executable; git will silently skip it")

    def test_pre_commit_skips_a_docs_only_commit(self):
        r = subprocess.run(["bash", str(HOOKS / "pre-commit")],
                           capture_output=True, text=True, cwd=ROOT,
                           env={"PATH": "/usr/bin:/bin", "GIT_INDEX_FILE": ""})
        # Whatever it decides, it must not crash: an unhandled error in a hook
        # blocks every commit in the repository.
        self.assertNotIn("command not found", r.stderr)
        self.assertIn(r.returncode, (0, 1))

    def test_commit_msg_rejects_a_placeholder_subject(self):
        for bad in ("fix", "wip", "update", "x"):
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write(bad + "\n")
                path = fh.name
            r = subprocess.run(["bash", str(HOOKS / "commit-msg"), path],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, f"{bad!r} was accepted")

    def test_commit_msg_accepts_a_descriptive_subject(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("Add the campaign layer and the joins it needs\n")
            path = fh.name
        r = subprocess.run(["bash", str(HOOKS / "commit-msg"), path],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_merge_and_revert_are_exempt(self):
        for good in ("Merge branch 'x' into y", "Revert \"Add a thing\""):
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write(good + "\n")
                path = fh.name
            r = subprocess.run(["bash", str(HOOKS / "commit-msg"), path],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{good!r} was rejected: {r.stderr}")

    def test_readme_explains_the_install(self):
        text = (HOOKS / "README.md").read_text(encoding="utf-8")
        self.assertIn("core.hooksPath", text)
        self.assertIn("--no-verify", text)


if __name__ == "__main__":
    unittest.main()
