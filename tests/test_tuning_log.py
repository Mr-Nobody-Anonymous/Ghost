#!/usr/bin/env python3
"""The tuning loop must refuse claims without observations.

Two things are tested here:

  * the renderer and the CSV cannot disagree
  * a rule cannot be promoted to `lifecycle: tuned` without a `keep` row

The second is the one that matters. Every rule in this repository is `designed`
today, so the invariant holds vacuously; a test that only ran against the real
tree would prove nothing. These tests drive `tools/tuning_log.py` as a
subprocess against a temporary copy of the rule set, which is how the check will
behave the day somebody promotes a rule.
"""
import csv
import importlib.util
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "tuning_log.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("tuning_log", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TuningLogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.index = cls.tool.rule_index()

    def test_every_declared_rule_is_known(self):
        """The index must see every rule in the tree.

        Asserted against a fresh count rather than the literal 38: a hardcoded
        number turns "a rule was added" into a test failure for the wrong
        reason, which is how a suite starts lying about what it checks.
        """
        on_disk = sum(1 for p in (ROOT / "sigma").rglob("*.yml")
                      if re.search(r"^id:\s*\S+", p.read_text(encoding="utf-8"),
                                   re.M))
        self.assertEqual(len(self.index), on_disk)
        self.assertGreaterEqual(len(self.index), 38)

    def test_real_tree_is_consistent(self):
        r = subprocess.run([sys.executable, str(TOOL), "--check"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_rendered_table_matches_the_csv(self):
        rows = self.tool.load_rows()
        table = self.tool.render(self.index, rows)
        doc = (ROOT / "docs" / "tuning-log.md").read_text(encoding="utf-8")
        self.assertIn(table, doc,
                      "docs/tuning-log.md was hand-edited; run "
                      "`python3 tools/tuning_log.py --render`")

    def test_unknown_rule_is_rejected(self):
        rows = [{"date": "2026-01-01", "rule_id": "deadbeef-0000-0000-0000-000000000000",
                 "benign_class": "backup agent", "observed_trip": "write to temp",
                 "decision": "allowlist", "rationale": "known good installer",
                 "events_per_day": "", "reporter": ""}]
        problems = self.tool.validate(rows, self.index)
        self.assertTrue(any("is not a rule in this repository" in p for p in problems))

    def test_bad_decision_and_short_rationale_are_rejected(self):
        rid = next(iter(self.index))
        rows = [{"date": "2026-01-01", "rule_id": rid, "benign_class": "x",
                 "observed_trip": "y", "decision": "vibes", "rationale": "ok",
                 "events_per_day": "abc", "reporter": ""}]
        problems = self.tool.validate(rows, self.index)
        joined = " ".join(problems)
        self.assertIn("not one of", joined)
        self.assertIn("too short", joined)
        self.assertIn("is not a number", joined)

    def test_future_date_is_rejected(self):
        rid = next(iter(self.index))
        rows = [{"date": "2999-01-01", "rule_id": rid,
                 "benign_class": "backup agent", "observed_trip": "trip",
                 "decision": "keep", "rationale": "observed on host-1",
                 "events_per_day": "3", "reporter": ""}]
        problems = self.tool.validate(rows, self.index)
        self.assertTrue(any("in the future" in p for p in problems))

    def test_tuned_without_keep_observation_fails(self):
        """The invariant, exercised on a temporary tree where one rule is tuned."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "sigma").mkdir()
            rule = ("title: Rule that claims tuning\n"
                    "id: 11111111-2222-3333-4444-555555555555\n"
                    "lifecycle: tuned\n")
            (root / "sigma" / "tuned.yml").write_text(rule, encoding="utf-8")
            (root / "tuning").mkdir()
            (root / "tuning" / "observations.csv").write_text(
                ",".join(self.tool.COLUMNS) + "\n", encoding="utf-8")
            (root / "metrics").mkdir()
            shutil.copy(ROOT / "metrics" / "ceilings.json", root / "metrics")
            (root / "docs").mkdir()
            (root / "docs" / "tuning-log.md").write_text(
                f"x\n{self.tool.BEGIN}\n{self.tool.END}\n", encoding="utf-8")

            src = TOOL.read_text(encoding="utf-8")
            # re-point the module's ROOT at the temporary tree
            src = src.replace(
                'ROOT = pathlib.Path(__file__).resolve().parent.parent',
                f'ROOT = pathlib.Path({str(root)!r})')
            tool = root / "tuning_log.py"
            tool.write_text(src, encoding="utf-8")

            r = subprocess.run([sys.executable, str(tool), "--check"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, "a claimed-tuned rule with no "
                                              "observation was accepted")
            self.assertIn("lifecycle: tuned with no `keep` observation", r.stderr)

            with (root / "tuning" / "observations.csv").open("a", newline="",
                                                             encoding="utf-8") as fh:
                csv.writer(fh).writerow(["2026-01-01", "11111111-2222-3333-4444-555555555555",
                                         "backup agent", "wrote to temp", "keep",
                                         "confirmed benign on host-1", "2", "analyst"])

            r = subprocess.run([sys.executable, str(tool), "--check"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_ceilings_become_measured_only_from_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            ceilings = root / "ceilings.json"
            shutil.copy(ROOT / "metrics" / "ceilings.json", ceilings)
            rid = next(iter(self.tool.rule_index()))
            rows = [{"date": "2026-01-01", "rule_id": rid, "benign_class": "backup",
                     "observed_trip": "noise", "decision": "threshold",
                     "rationale": "twenty a day, all backup", "events_per_day": "21",
                     "reporter": "analyst"}]
            import json
            self.tool.CEILINGS = ceilings
            changed = self.tool.apply_ceilings(self.tool.rule_index(), rows)
            self.assertEqual(changed, [rid])
            data = json.loads(ceilings.read_text(encoding="utf-8"))
            self.assertTrue(data[rid]["measured"])
            self.assertEqual(data[rid]["observed_events_per_day"], 21.0)


if __name__ == "__main__":
    unittest.main()
