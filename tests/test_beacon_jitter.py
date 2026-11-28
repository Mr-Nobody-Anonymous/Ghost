#!/usr/bin/env python3
"""The jitter detector must separate a beacon from a poller, and must say so.

The load-bearing property is not "the maths is right" - it is that a *count*
threshold cannot make this distinction and an interval distribution can. These
tests pin both numbers so a later "simplification" that quietly turns the
detector back into a threshold fails here.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "analytics" / "beacon_jitter.py"
SAMPLE = ROOT / "fixtures" / "beacon_jitter_sample.jsonl"


def load_tool():
    spec = importlib.util.spec_from_file_location("beacon_jitter", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BeaconJitterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_synthetic_beacon_is_beacon_like(self):
        """A real 0.35 uniform jitter, deterministic, 45s base.

        The first version of this test used a 3-value sawtooth (`(i % 3)`),
        which has a standard deviation near the full band rather than a uniform
        draw's 0.577*band, so it was irregular by the detector's own maths. The
        test was wrong, not the detector.
        """
        import random
        rng = random.Random(11)
        t = 0.0
        times = []
        for _ in range(30):
            t += 45.0 * (1 + rng.uniform(-0.35, 0.35))
            times.append(t)
        result = self.tool.analyse(times)
        self.assertEqual(result["verdict"], "beacon_like")
        self.assertLessEqual(result["cv"], self.tool.JITTER_CEILING)

    def test_regular_backup_is_statistically_a_beacon(self):
        """This is the honest limitation, asserted so nobody claims otherwise."""
        backup = [i * 300.0 for i in range(30)]
        self.assertEqual(self.tool.analyse(backup)["verdict"], "beacon_like")

    def test_rule_filter_is_what_removes_the_backup(self):
        backup = [i * 300.0 for i in range(30)]
        kept, filtered = self.tool.apply_rule_filter(
            {("h1", "vault.corp"): backup, ("h1", "cdn.example"): backup})
        self.assertEqual(list(filtered), [("h1", "vault.corp")])
        self.assertEqual(list(kept), [("h1", "cdn.example")])

    def test_two_pairs_with_equal_event_counts_differ_only_by_interval(self):
        """A count threshold is blind here; the detector is not."""
        beacon = [i * 60.0 + (i % 2) * 6.0 for i in range(20)]
        poller = [0, 3, 61, 62, 130, 131, 132, 200, 260, 261, 262, 330, 331, 400,
                  401, 402, 460, 520, 521, 522]
        self.assertEqual(len(beacon), len(poller))
        self.assertEqual(self.tool.analyse(beacon)["verdict"], "beacon_like")
        self.assertNotEqual(self.tool.analyse(poller)["verdict"], "beacon_like")

    def test_too_few_intervals_is_not_a_verdict(self):
        self.assertEqual(self.tool.analyse([0, 60, 120])["verdict"],
                         "insufficient_data")

    def test_flood_is_rejected_on_interval_not_called_a_beacon(self):
        flood = [i * 0.02 for i in range(500)]
        self.assertEqual(self.tool.analyse(flood)["verdict"], "interval_out_of_range")

    def test_selftest_passes_and_reports_its_own_claim(self):
        r = subprocess.run([sys.executable, str(TOOL), "--selftest"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count threshold sees two 30-event flows", r.stdout)

    def test_sample_fixture_yields_one_beacon_and_one_irregular(self):
        r = subprocess.run([sys.executable, str(TOOL), str(SAMPLE), "--json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = {f["dst"]: f for f in json.loads(r.stdout)}
        self.assertEqual(rows["cdn-metrics-sync.net"]["verdict"], "beacon_like")
        self.assertEqual(rows["api.vendor.example"]["verdict"], "irregular")
        self.assertNotIn("vault.corp", rows,
                         "the .corp backup was measured instead of filtered; the "
                         "detector now disagrees with beacon_interval_shift.yml")

    def test_no_rule_filter_shows_the_limitation_on_demand(self):
        r = subprocess.run([sys.executable, str(TOOL), str(SAMPLE),
                            "--no-rule-filter", "--json"],
                           capture_output=True, text=True)
        rows = {f["dst"]: f for f in json.loads(r.stdout)}
        self.assertEqual(rows["vault.corp"]["verdict"], "beacon_like")

    def test_malformed_flow_is_a_failure_not_a_skip(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write('{"src": "a", "dst": "b"}\n')
            path = fh.name
        r = subprocess.run([sys.executable, str(TOOL), path],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("needs src/SourceAddress", r.stderr)


if __name__ == "__main__":
    unittest.main()
