#!/usr/bin/env python3
"""The stage0 -> stage1 join must find the chain and reject the lookalikes.

The near-misses are the point. Any of three ordinary situations produces two
events that a naive `count >= 2 in 5m` would alert on:

  * a signed updater in Temp spawning a shell (stage 0 filtered on Signature)
  * a real install of Python spawning a shell (stage 0 needs a *temp* path)
  * a genuine `_MEI` interpreter whose child ran 20 minutes later (window)
  * a sensor clock skew putting the child before the parent

Each is in the fixture and each is asserted separately, so a change that widens
the join to "any two events" fails here rather than in production.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "analytics" / "stage_join.py"
SAMPLE = ROOT / "fixtures" / "stage_join_sample.jsonl"


def load_tool():
    spec = importlib.util.spec_from_file_location("stage_join", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StageJoinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.members = cls.tool.load_members()
        cls.chains, cls.reasons, cls.n0, cls.n1 = cls.tool.join(
            cls.tool.load_events(SAMPLE), cls.members)

    def test_one_chain(self):
        self.assertEqual(len(self.chains), 1)

    def test_chain_is_the_python_interpreter_and_the_shell(self):
        chain = self.chains[0]
        self.assertIn("_MEI123456", chain["parent"]["Image"])
        self.assertTrue(chain["child"]["Image"].lower().endswith("powershell.exe"))
        self.assertEqual(chain["child"]["ParentProcessGuid"],
                         chain["parent"]["ProcessGuid"])
        self.assertLessEqual(chain["age_seconds"], self.tool.MAX_ANCESTRY_AGE)

    def test_signed_binary_in_temp_is_rejected(self):
        self.assertTrue(any("not a stage-0 event" in r for r in self.reasons),
                        self.reasons)

    def test_program_files_python_is_not_stage0(self):
        """The member rule requires a user-writable path; an installed Python is
        not stage 0 even though it does spawn cmd.exe."""
        stage0_images = [e["Image"] for e in
                         self.tool.load_events(SAMPLE)
                         if self.members["stage0"]["predicate"](e)]
        self.assertFalse(any("Program Files" in i for i in stage0_images),
                         stage0_images)

    def test_out_of_window_parent_is_rejected(self):
        self.assertTrue(any("ancestry window" in r for r in self.reasons),
                        self.reasons)

    def test_clock_skew_is_rejected(self):
        self.assertTrue(any("precedes its parent" in r for r in self.reasons),
                        self.reasons)

    def test_selftest_passes(self):
        r = subprocess.run([sys.executable, str(TOOL), "--selftest"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("one chain, three near-misses rejected", r.stdout)

    def test_json_output_is_parseable(self):
        r = subprocess.run([sys.executable, str(TOOL), str(SAMPLE), "--json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(len(data["chains"]), 1)
        self.assertTrue(data["rejected"])

    def test_the_join_key_is_not_a_shared_field(self):
        """Why this is a tool and not a Sigma correlation: the child event
        carries the parent's guid under a different name, so `group-by` on a
        shared field cannot express it."""
        events = self.tool.load_events(SAMPLE)
        child = next(e for e in events if e.get("ProcessGuid", "").endswith("-S1"))
        self.assertIn("ParentProcessGuid", child)
        self.assertNotIn("ProcessGuid", [k for k in child
                                         if k == "ParentProcessGuid"])
        self.assertNotEqual(child.get("ProcessGuid"), child.get("ParentProcessGuid"))

    def test_missing_field_does_not_match(self):
        """An event without the field must not satisfy an `|endswith` clause."""
        sel = self.members["stage1"]["predicate"]
        bare = {"EventID": 1, "Image": "", "ParentImage": ""}
        self.assertFalse(sel(bare))

    def test_malformed_line_fails_loudly(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write("not json\n")
            path = fh.name
        r = subprocess.run([sys.executable, str(TOOL), path],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("is not JSON", r.stderr)


if __name__ == "__main__":
    unittest.main()
