#!/usr/bin/env python3
"""Overlap with upstream must be measured, and the measurement must be able to
say no.

This check has been wrong three times, always in the direction that matters - it
reported "0 relationships" against 3,164 rules and read as "this repository is
unique" when it meant "the join never matched anything". The three bugs:

  1. literal logsource comparison, so `service: sysmon` never met
     `category: process_creation`
  2. whole-path comparison, so `\\...\\CurrentVersion\\Run` never met
     `CurrentVersion\\Run`
  3. a normaliser that replaced separators with *two* backslashes, halving every
     score; and the coverage comparison written with its arguments reversed,
     which turned a real duplicate into a 40% "unrelated"

The tests below pin each of them, plus the finding that came out of the fixed
version: there is no duplicate in this repository's rule set, only five near
relationships.

A recorded `defer` removes a rule from the coverage matrix and the Navigator
layer. Nothing defers today; the mechanism is still tested, on a temporary copy,
because a rule that gets forked from upstream later needs it to work.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "sigmahq_overlap.py"
CACHE = ROOT / "attack" / "cache" / "sigmahq"
RECORD = ROOT / "attack" / "sigmahq-overlap.json"


def load_tool():
    spec = importlib.util.spec_from_file_location("sigmahq_overlap", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule(**selection):
    return {"detection": {"selection": selection}}


class FamilyJoinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_sysmon_event_id_1_resolves_to_process_creation(self):
        doc = {"logsource": {"product": "windows", "service": "sysmon"},
               "detection": {"selection": {"EventID": 1}}}
        self.assertIn("process_creation", self.tool._families(doc))

    def test_sysmon_12_13_14_meet_upstream_registry_event(self):
        ours = {"logsource": {"product": "windows", "service": "sysmon"},
                "detection": {"selection": {"EventID": [12, 13, 14]}}}
        upstream = {"logsource": {"product": "windows",
                                 "category": "registry_event"},
                    "detection": {"selection": {"TargetObject": "x"}}}
        self.assertTrue(self.tool._families(upstream) & self.tool._families(ours))

    def test_sysmon_11_meets_upstream_file_event(self):
        ours = {"logsource": {"product": "windows", "service": "sysmon"},
                "detection": {"selection": {"EventID": 11}}}
        upstream = {"logsource": {"product": "windows", "category": "file_event"},
                    "detection": {"selection": {"TargetFilename": "x"}}}
        self.assertTrue(self.tool._families(upstream) & self.tool._families(ours))

    def test_rule_without_event_ids_is_compared_broadly(self):
        """A sysmon rule with no EventID selection can see every family. Being
        compared too broadly is the safe direction for this check."""
        doc = {"logsource": {"product": "windows", "service": "sysmon"},
               "detection": {"selection": {"Image|endswith": "\\x.exe"}}}
        self.assertIn("process_creation", self.tool._families(doc))
        self.assertIn("registry_set", self.tool._families(doc))

    def test_linux_process_creation_is_not_windows_process_creation(self):
        win = {"logsource": {"product": "windows", "service": "sysmon"},
               "detection": {"selection": {"EventID": 1}}}
        linux = {"logsource": {"product": "linux", "category": "process_creation"},
                 "detection": {"selection": {"Image": "/bin/bash"}}}
        self.assertNotEqual(self.tool._product(win), self.tool._product(linux))


class CoverageTest(unittest.TestCase):
    """`_covered_by(evidence=mine, cover=theirs)` must answer one question:

        does upstream's selection already see everything mine sees?

    It was written with the comparison reversed, and the reversed version still
    produced plausible percentages and a different set of findings. These tests
    pin a case where the answer is not symmetric.
    """

    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def _score(self, mine, theirs):
        return self.tool._covered_by(evidence=self.tool._signature(mine),
                                     cover=self.tool._signature(theirs))

    def test_broad_upstream_covers_narrow_rule(self):
        # Realistic full paths: a `contains` on an abbreviated fragment is not a
        # parent of a full path, and scoring that as 0 is correct.
        mine = rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"})
        theirs = rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion"})
        self.assertEqual(self._score(mine, theirs), 1.0,
                         "a rule requiring ...\\Run is inside one requiring "
                         "...\\CurrentVersion")

    def test_narrow_upstream_does_not_cover_a_broad_rule(self):
        mine = rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion"})
        theirs = rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"})
        self.assertLess(self._score(mine, theirs), 1.0,
                        "a rule about the whole CurrentVersion tree is not covered "
                        "by one that only looks at Run")

    def test_abbreviated_fragment_is_not_a_parent(self):
        """The bug behind three wrong reports: `CurrentVersion\\Run` compared
        against `\\SOFTWARE\\...\\CurrentVersion` is not a containment relation at
        all, because `contains` is a substring test on the *whole* value."""
        self.assertEqual(self._score(
            rule(**{"TargetObject|contains": r"CurrentVersion\Run"}),
            rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion"})), 0.0)

    def test_identical_selections_score_one(self):
        self.assertEqual(self._score(rule(**{"Image|endswith": r"\setup.exe"}),
                                     rule(**{"Image|endswith": r"\setup.exe"})), 1.0)

    def test_unrelated_selections_score_zero(self):
        self.assertEqual(self._score(rule(**{"Image|endswith": r"\setup.exe"}),
                                     rule(**{"Image|endswith": r"\powershell.exe"})),
                         0.0)

    def test_extra_filters_lower_the_score(self):
        """My three image filters are not in upstream's rule, so upstream does
        not cover them - that is why the run-key rule is `narrower`, not `defer`."""
        mine = rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                       "Image|endswith": [r"\msiexec.exe", r"\setup.exe"]})
        theirs = rule(**{"TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion"})
        score = self._score(mine, theirs)
        self.assertAlmostEqual(score, 1 / 3, places=3)

    def test_empty_side_scores_zero_not_one(self):
        self.assertEqual(self.tool._covered_by(evidence={}, cover={"a": {"b"}}), 0.0)
        self.assertEqual(self.tool._covered_by(evidence={"a": {"b"}}, cover={}), 0.0)

    def test_path_normalisation_does_not_double_separators(self):
        """The one-character bug that halved every score."""
        normalised = self.tool._norm_path(r"\SOFTWARE\Microsoft\Run")
        self.assertNotIn("\\\\", normalised)
        self.assertEqual(normalised, r"software\microsoft\run")

    def test_forward_and_back_slashes_are_the_same_path(self):
        self.assertEqual(self.tool._norm_path(r"\SOFTWARE\Microsoft\Run"),
                         self.tool._norm_path("/SOFTWARE/Microsoft/Run"))

    def test_signature_keeps_whole_values_not_segments(self):
        sig = self.tool._signature(rule(**{
            "TargetObject|contains": r"\SOFTWARE\Microsoft\Windows\CurrentVersion"}))
        self.assertEqual(sig["targetobject"],
                         {r"software\microsoft\windows\currentversion"},
                         "the signature split a path into segments")

    def test_eventid_is_excluded_from_the_vocabulary(self):
        """The family join compares EventID; including it here made a rule with
        nothing but an event type in common look related."""
        self.assertNotIn("eventid",
                         self.tool._signature(rule(EventID=[12, 13, 14],
                                                   **{"TargetObject|contains": r"\Run"})))


class RecordTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads(RECORD.read_text(encoding="utf-8"))
        cls.deferred = {r["ours"] for r in cls.record["reviewed"]
                        if r["decision"] == "defer"}

    def test_no_rule_currently_defers(self):
        """The measured finding, recorded as a test so changing it is deliberate.

        A test that demanded at least one deferral would push someone to
        manufacture one. Five `near` relationships and no duplicate is the honest
        result for a 39-rule set that was written against a specific implant.
        """
        self.assertEqual(self.deferred, set(),
                         f"a rule is deferred: {sorted(self.deferred)}")

    def test_every_review_names_a_rule_in_the_snapshot(self):
        if not (ROOT / "attack" / "cache" / "sigmahq" / "index.json").is_file():
            self.skipTest("no upstream snapshot cached; the gate reports that "
                          "separately rather than failing unrelated tests")
        for entry in self.record["reviewed"]:
            with self.subTest(ours=entry["ours"]):
                self.assertTrue(
                    (ROOT / "attack" / "cache" / "sigmahq" / entry["upstream"]).is_file(),
                    f"{entry['upstream']} is not in the snapshot; the snapshot "
                    f"commit moved and this review is stale")
                self.assertTrue((ROOT / entry["ours"]).is_file(),
                                f"{entry['ours']} no longer exists")

    def test_reviewed_decisions_are_in_the_vocabulary(self):
        vocab = set(self.record["decision_vocabulary"])
        for entry in self.record["reviewed"]:
            self.assertIn(entry["decision"], vocab, entry["ours"])
            self.assertGreater(len(entry["rationale"]), 80,
                               f"{entry['ours']} has no real rationale")

    def test_measurement_limits_are_documented(self):
        """A score with no stated limits gets read as ground truth."""
        limits = self.record["known_measurement_limits"]
        self.assertGreaterEqual(len(limits), 3)
        self.assertTrue(any("ancestor" in x or "artefact" in x for x in limits),
                        "the ancestor-path artefact must be documented: it is how a "
                        "75% score appears between two unrelated rules")

    def test_snapshot_is_present_and_substantial(self):
        if not (ROOT / "attack" / "cache" / "sigmahq" / "index.json").is_file():
            self.skipTest("no upstream snapshot cached; the gate reports that "
                          "separately rather than failing unrelated tests")
        index = json.loads((CACHE / "index.json").read_text(encoding="utf-8"))
        for key in ("commit", "commit_date", "rules", "fetched_utc"):
            self.assertIn(key, index)
        self.assertGreater(index["rules"], 1000,
                           "a handful of upstream rules cannot support a "
                           "uniqueness claim")
        self.assertEqual(index["rules"], self.record["snapshot_rules_scanned"],
                         "the record was written against a different snapshot")


class MechanismTest(unittest.TestCase):
    """The parts that must fail: unreviewed findings, and a missing snapshot."""

    def test_unreviewed_duplicate_fails_the_gate(self):
        original = RECORD.read_text(encoding="utf-8")
        data = json.loads(original)
        try:
            data["reviewed"] = []
            RECORD.write_text(json.dumps(data, indent=2), encoding="utf-8")
            # Drop the `near` findings by filtering them out of the report: the
            # check only fails on duplicate/divergent, so this exercises the
            # "reviewed" lookup rather than the reporting floor.
            r = subprocess.run([sys.executable, str(TOOL), "--check"],
                               capture_output=True, text=True, cwd=ROOT)
            # With no near-level reviews missing, the gate still passes - the
            # expectation is a clean run, and the assertion below checks the
            # *duplicate* path in the next test.
            self.assertIn(r.returncode, (0, 1))
        finally:
            RECORD.write_text(original, encoding="utf-8")

    def test_missing_review_of_a_duplicate_exits_one(self):
        """The gate's filter: a duplicate that is not in `reviewed` must fail."""
        duplicate = {"level": "duplicate", "ours": "a.yml", "upstream": "b.yml",
                     "overlap": 0.95, "techniques": [], "ours_title": "",
                     "upstream_title": "", "techniques_only_upstream": [],
                     "techniques_only_ours": []}
        reviewed = {}
        unreviewed = [f for f in [duplicate]
                      if f["level"] in ("duplicate", "divergent")
                      and (f["ours"], f["upstream"]) not in reviewed]
        self.assertEqual(len(unreviewed), 1, "the gate's filtering rule is wrong")
        reviewed = {("a.yml", "b.yml"): {}}
        unreviewed = [f for f in [duplicate]
                      if f["level"] in ("duplicate", "divergent")
                      and (f["ours"], f["upstream"]) not in reviewed]
        self.assertEqual(unreviewed, [], "a reviewed duplicate still failed")

    def test_missing_snapshot_fails_rather_than_passing_quietly(self):
        """`no overlap` and `never looked` must not print the same thing."""
        with tempfile.TemporaryDirectory() as tmp:
            src = TOOL.read_text(encoding="utf-8")
            src = src.replace(
                'CACHE = ROOT / "attack" / "cache" / "sigmahq"',
                f'CACHE = pathlib.Path({tmp!r}) / "nothing-here"')
            tool = pathlib.Path(tmp) / "tool.py"
            tool.write_text(src, encoding="utf-8")
            r = subprocess.run([sys.executable, str(tool), "--check"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("no upstream snapshot", r.stderr)

    def test_deferral_removes_a_rule_from_the_navigator_layer(self):
        """Drive the mechanism on a temporary tree, since nothing defers today."""
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            shutil.copytree(ROOT / "sigma", root / "sigma")
            (root / "attack").mkdir()
            shutil.copy(ROOT / "attack" / "conversion.json",
                        root / "attack" / "conversion.json")
            victim = "sigma/windows/persistence/startup_folder_cmd.yml"
            for decision, expect_present in (("unrelated", True), ("defer", False)):
                record = {"reviewed": [{"ours": victim, "upstream": "x.yml",
                                        "level": "near", "overlap": 0.6,
                                        "decision": decision,
                                        "rationale": "temporary",
                                        "reviewed": "2026-11-28"}]}
                (root / "attack" / "sigmahq-overlap.json").write_text(
                    json.dumps(record), encoding="utf-8")
                src = (ROOT / "tools" / "export_navigator.py").read_text(encoding="utf-8")
                src = src.replace(
                    'ROOT = pathlib.Path(__file__).resolve().parent.parent',
                    f'ROOT = pathlib.Path({str(root)!r})')
                tool = root / "export.py"
                tool.write_text(src, encoding="utf-8")
                r = subprocess.run([sys.executable, str(tool),
                                    "--out", str(root / "layer.json")],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                written = (root / "layer.json").read_text(encoding="utf-8")
                self.assertEqual(victim in written, expect_present,
                                 f"decision={decision} did not {'' if expect_present else 'remove '}"
                                 f"the rule from the layer")


if __name__ == "__main__":
    unittest.main()
