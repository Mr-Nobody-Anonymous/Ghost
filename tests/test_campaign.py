#!/usr/bin/env python3
"""The campaign layer must fire on 3-of-4 and not on 2-of-4.

Sigma 2.1 has no "at least N of these correlations fired" operator, so the
tempting shortcut is to write it as `temporal` over the four chains. That means
"all four, in order" - a different, much weaker detector. These tests exist so
the shortcut cannot be taken quietly: they assert the 2-of-4 host does *not*
alert, which a temporal-of-four implementation would also pass by accident, and
they assert the 3-of-4 host *does* - which it would fail.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "analytics" / "campaign.py"
SAMPLE = ROOT / "fixtures" / "campaign_sample.json"
RULE = ROOT / "sigma" / "campaign_implant_sequence.yml"


def load_tool():
    sys.path.insert(0, str(ROOT / "detection-as-code"))
    spec = importlib.util.spec_from_file_location("campaign", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CampaignTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.rule = cls.tool.load_rule()
        cls.evaluate = cls.tool.load_evaluator()
        cls.rules = cls.evaluate.load_collection(ROOT)
        cls.payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
        (cls.findings, cls.per_host,
         cls.window) = cls.tool.evaluate_campaign(
            cls.payload["events"], cls.rule, cls.rules, cls.evaluate)

    def test_three_of_four_is_a_campaign(self):
        self.assertEqual(len(self.findings), 1)
        self.assertEqual(self.findings[0]["host"], "LAB-WS01")
        self.assertEqual(self.findings[0]["count"], 3)

    def test_two_of_four_is_not_a_campaign(self):
        host = self.per_host["LAB-WS02"]
        self.assertEqual(sum(host.values()), 2)
        self.assertNotIn("LAB-WS02", [f["host"] for f in self.findings])

    def test_single_chain_is_not_a_campaign(self):
        self.assertEqual(sum(self.per_host["LAB-WS03"].values()), 1)

    def test_members_are_correlations_not_single_event_rules(self):
        """A campaign of plain rules is an event_count wearing a costume."""
        for label, rid in self.tool.labels_from(self.rule).items():
            doc = self.rules.get(rid)
            self.assertIsNotNone(doc, f"campaign member {label} ({rid}) is missing")
            self.assertTrue(doc.get("correlation"),
                            f"campaign member {label} ({rid}) is not a correlation")

    def test_required_count_comes_from_the_rule_file(self):
        self.assertEqual(self.rule["campaign"]["require_at_least"], 3)
        self.assertEqual(len(self.tool.labels_from(self.rule)), 4)

    def test_dropping_to_two_members_would_change_the_verdict(self):
        """Prove the threshold is load-bearing: with require_at_least = 2 the
        WS02 host becomes a campaign."""
        rule = json.loads(json.dumps(self.rule, default=str))
        rule["campaign"]["require_at_least"] = 2
        findings, _per_host, _w = self.tool.evaluate_campaign(
            self.payload["events"], rule, self.rules, self.evaluate)
        self.assertIn("LAB-WS02", [f["host"] for f in findings])
        self.assertGreater(len(findings), 1)

    def test_selftest_passes(self):
        r = subprocess.run([sys.executable, str(TOOL), "--selftest"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("three of four chains is a campaign", r.stdout)

    def test_json_output_is_parseable(self):
        r = subprocess.run([sys.executable, str(TOOL), str(SAMPLE), "--json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(len(data["campaigns"]), 1)

    def test_missing_member_is_a_failure(self):
        with self.assertRaises(SystemExit):
            self.tool.fire_set([], {}, self.evaluate,
                               {"ghost": "00000000-0000-0000-0000-000000000000"})

    def test_rule_declares_it_is_not_portable(self):
        """The rule must not claim a backend converts something it cannot."""
        conv = self.rule["conversion"]
        for backend in ("splunk", "elastic", "kusto"):
            self.assertEqual(conv[backend], "unsupported",
                             f"{backend} claims to convert a campaign; pySigma "
                             f"has no such operator")
        self.assertIn("campaign.py", conv["note"])


if __name__ == "__main__":
    unittest.main()
