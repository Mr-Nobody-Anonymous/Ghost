"""Precision measurement has to be arithmetically right before it is useful.

G-03 says precision is unknown. A tool that reports a wrong precision number is
worse than no tool, because it turns an honest unknown into a confident error -
which is the exact failure mode this repository keeps finding elsewhere (a broken
join that prints "0 overlap" and reads as "unique").

These tests use synthetic corpora where the right answer is countable by hand.
"""
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "detection-as-code"))

import benign_corpus as B  # noqa: E402
import evaluate  # noqa: E402


def a_benign_run_key_write():
    """A signed installer writing a Run key - the archetypal benign event that
    the persistence rule will select."""
    return {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\7-Zip",
        "Details": r"C:\Program Files\7-Zip\7zFM.exe",
        "Image": r"C:\Windows\System32\msiexec.exe",
    }


def a_benign_process_start():
    return {
        "EventID": 1,
        "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "CommandLine": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
        "ParentImage": r"C:\Windows\explorer.exe",
    }


class MeasureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = evaluate.load_collection(ROOT)

    def test_a_clean_corpus_reports_no_trips(self):
        events = [a_benign_process_start() for _ in range(5)]
        report = B.measure(events, self.rules)
        noisy = B.verdict(report)
        tripped = {r for r, _c, _w in noisy}
        # Whatever else happens, chrome starting must not trip the Run-key rule.
        self.assertNotIn("1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a01", tripped)

    def test_the_installer_filter_actually_filters(self):
        """The rule carries `filter_installer: Image|endswith msiexec.exe` and
        `condition: selection and not filter_installer`. So a signed MSI writing
        a Run key must score ZERO - and the first version of this test asserted
        one, which would have reported a precision problem that does not exist.

        Both directions matter. A filter that never excludes anything is the
        failure this whole repository keeps finding; a filter that excludes
        everything makes the rule dead and looks identical on a clean corpus.
        """
        events = [a_benign_run_key_write()]
        report = B.measure(events, self.rules)
        rule = report["1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a01"]
        self.assertEqual(rule["selected"], 0, "msiexec is filtered by design")

    def test_the_same_key_written_by_an_unfiltered_image_does_trip(self):
        """The other direction, on the same rule and the same key: change only
        the image to something the filter does not cover."""
        event = a_benign_run_key_write()
        event["Image"] = r"C:\Users\lab\AppData\Local\Temp\installer.exe"
        report = B.measure([event], self.rules)
        rule = report["1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a01"]
        self.assertEqual(rule["selected"], 1,
                         "without the installer image the rule must fire, or "
                         "the rule cannot fire at all")

    def test_rate_is_selected_over_total(self):
        filtered = a_benign_run_key_write()
        unfiltered = a_benign_run_key_write()
        unfiltered["Image"] = r"C:\Temp\x.exe"
        events = [filtered, unfiltered, a_benign_process_start(),
                  a_benign_process_start()]
        report = B.measure(events, self.rules)
        rule = report["1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a01"]
        self.assertEqual((rule["selected"], rule["of"]), (1, 4))
        self.assertAlmostEqual(rule["rate"], 0.25, places=4)

    def test_every_rule_gets_a_row(self):
        """A rule missing from the report reads as a clean rule. It is not -
        it is an unmeasured one, and the difference matters."""
        report = B.measure([a_benign_process_start()], self.rules)
        self.assertEqual(set(report), set(self.rules))

    def test_a_correlation_is_measured_over_the_sequence_not_per_event(self):
        """Per-event evaluation of a correlation is always false, which would
        report free precision that does not exist."""
        report = B.measure([a_benign_process_start() for _ in range(3)],
                           self.rules)
        corr = [r for r, row in report.items() if row.get("kind") == "correlation"]
        self.assertTrue(corr, "no correlation rules found in the collection")
        for rule_id in corr:
            self.assertIn("reason", report[rule_id])


class VerdictTest(unittest.TestCase):
    def test_anything_that_trips_is_named(self):
        report = {"r1": {"selected": 2, "of": 10, "rate": 0.2},
                  "r2": {"selected": 0, "of": 10, "rate": 0.0}}
        noisy = B.verdict(report)
        self.assertEqual([n[0] for n in noisy], ["r1"])

    def test_a_crashing_rule_is_a_finding_not_a_clean_row(self):
        report = {"r1": {"error": "TypeError: nope"}}
        noisy = B.verdict(report)
        self.assertEqual(noisy[0][1], "crashed")


class InputTest(unittest.TestCase):
    def test_jsonl_parsing_skips_blank_lines_and_reports_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = pathlib.Path(tmp) / "ok.jsonl"
            good.write_text('{"EventID": 1}\n\n{"EventID": 2}\n', encoding="utf-8")
            self.assertEqual(len(B.parse_jsonl(good)), 2)

            bad = pathlib.Path(tmp) / "bad.jsonl"
            bad.write_text('{"EventID": 1}\nnot json\n', encoding="utf-8")
            with self.assertRaises(SystemExit):
                B.parse_jsonl(bad)

    def test_xml_parsing_reads_eventdata_names(self):
        events = B.parse_xml(ROOT / "tests" / "data" / "sample_capture.xml")
        self.assertTrue(events)
        self.assertIn("EventID", events[0])
        self.assertIn("Image", events[0])

    def test_an_empty_corpus_is_refused_not_reported_clean(self):
        """The whole point: `0/0` must not print as `0%`. An empty corpus and a
        clean corpus are different claims and must not look the same."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = pathlib.Path(tmp) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            import subprocess
            r = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "benign_corpus.py"),
                 "--from-jsonl", str(empty)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn("empty corpus measures nothing", r.stderr)


class ClassListTest(unittest.TestCase):
    def test_every_class_names_rules_that_exist(self):
        """A class list pointing at rules that do not exist sends the operator
        looking for an alert that will never fire."""
        names = {p.stem for p in (ROOT / "sigma").rglob("*.yml")}
        for entry in B.CLASSES:
            for rule in entry["expected_trips"]:
                self.assertIn(rule, names,
                              f"{entry['class']} expects {rule}, which is not "
                              f"a rule in this repository")

    def test_every_class_says_how_long_it_takes(self):
        for entry in B.CLASSES:
            self.assertTrue(entry["duration"])
            self.assertGreater(len(entry["why"]), 40)

    def test_the_class_list_is_not_trivially_short(self):
        """One software class is not a precision measurement."""
        self.assertGreaterEqual(len(B.CLASSES), 6)


if __name__ == "__main__":
    unittest.main()
