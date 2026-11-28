"""A deployment procedure that has never been executed still rots (G-27).

The page was honest that it had never run. It was not honest about the
repository it described: it said "38 rules" when there were 39, and sent the
reader to `response/rules/<id>.md`, which is a pattern, not a file. Both survive
review because the prose reads correctly. This reads it mechanically.
"""
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_deployment_doc as D  # noqa: E402


class ReferenceTest(unittest.TestCase):
    def test_every_repo_path_the_doc_names_exists(self):
        missing = sorted(p for p in D.referenced_paths(D.DOC.read_text(
            encoding="utf-8")) if not (ROOT / p).exists())
        self.assertEqual(missing, [],
                         "a procedure that tells the operator to use a file "
                         "that is not there is worse than no procedure")

    def test_no_placeholder_paths_are_left_as_instructions(self):
        text = D.DOC.read_text(encoding="utf-8")
        self.assertNotIn("response/rules/<id>.md", text,
                         "<id> is not a filename; send the reader to the "
                         "directory and let them pick")
        self.assertNotIn("fixtures/per_rule/<id>.json", text)


class CountTest(unittest.TestCase):
    def test_the_doc_states_no_wrong_total(self):
        problems = D.stated_counts(D.DOC.read_text(encoding="utf-8"))
        self.assertEqual(problems, [])

    def test_a_wrong_rule_count_is_caught(self):
        problems = D.stated_counts("The repo emits 38 rules and 12 queries.")
        self.assertTrue(problems, "38 is not the rule total; this must fail")

    def test_a_wrong_backend_ratio_is_caught(self):
        problems = D.stated_counts("| Splunk | 30/39 |")
        self.assertTrue(problems)

    def test_a_true_subset_statement_is_not_flagged(self):
        """34 of the 39 rules are Windows-only - true, and not a total."""
        self.assertEqual(D.stated_counts("34 of the 39 rules are Windows-only"), [])

    def test_no_document_quotes_a_stale_rule_total(self):
        """The 38-vs-39 drift was in six files at once. Each one read correctly.
        A subset statement - "32 of the 39 rules" - is fine and must stay fine,
        or people stop writing useful sentences to appease the checker."""
        import subprocess
        r = subprocess.run([sys.executable, str(ROOT / "tools" /
                                                "check_deployment_doc.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("says '", r.stderr)

    def test_a_subset_sentence_is_not_flagged(self):
        self.assertEqual(
            D.stated_counts("32 of the 39 rules read EventID."), [])
        self.assertEqual(
            D.stated_counts("Windows 2003/2102 events cover device arrival"), [])

    def test_a_stale_total_in_any_document_is_flagged(self):
        self.assertTrue(D.stated_counts("The gate converts 38/38 rules."))

    def test_the_deployability_numbers_come_from_the_matrix(self):
        total, per_backend = D.deployability()
        self.assertEqual(total, len(list((ROOT / "sigma").rglob("*.yml"))))
        for backend, count in per_backend.items():
            self.assertGreater(count, 0, f"{backend} converts nothing")
            self.assertLessEqual(count, total)


class CommandTest(unittest.TestCase):
    def test_the_runnable_half_of_the_procedure_actually_runs(self):
        runs = D.run_commands()
        bad = [r for r in runs if r["exit"] != 0]
        self.assertEqual(bad, [], f"commands the doc tells the operator to run "
                                 f"failed here: {bad}")

    def test_the_unverified_steps_are_named(self):
        self.assertGreaterEqual(len(D.NEEDS_A_DEPLOYMENT), 5,
                                "shrinking this list without doing the work is "
                                "how a deployment page starts lying")
        joined = " ".join(D.NEEDS_A_DEPLOYMENT)
        for word in ("Splunk", "Elastic", "Windows"):
            self.assertIn(word, joined)

    def test_the_whole_check_exits_zero(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" /
                                                "check_deployment_doc.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("procedure commands run here", r.stdout)

    def test_running_the_check_leaves_conversion_json_alone(self):
        """The bug this tool shipped with for one gate run.

        `convert_check.py` rewrites attack/conversion.json as a side effect. The
        tool ran the Splunk-only command the doc shows, which wrote a file where
        elastic and kusto were blank - and a test two stages later failed on
        "matrix is stale" with no visible connection to this file. A checker may
        change nothing.
        """
        def snapshot():
            data = json.loads((ROOT / "attack" / "conversion.json").read_text(
                encoding="utf-8"))
            return {b: sum(1 for e in data["results"].values()
                           if (e.get(b) or {}).get("actual") == "supported")
                    for b in ("splunk", "elastic", "kusto")}

        before = snapshot()
        D.run_commands()
        self.assertEqual(before, snapshot(),
                         "the deployment check must not rewrite the evidence "
                         "it is checking")

    def test_every_conversion_command_names_all_backends(self):
        """One backend means two blank columns in the file it writes."""
        for cmd in D.RUNNABLE:
            if "convert_check.py" in " ".join(cmd):
                joined = " ".join(cmd)
                for backend in ("splunk", "elastic", "kusto"):
                    self.assertIn(backend, joined,
                                  "convert_check.py writes the whole file; "
                                  "running it per-backend erases the others")

    def test_json_mode_reports_the_skipped_steps(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" /
                                                "check_deployment_doc.py"),
                            "--json"], capture_output=True, text=True)
        report = json.loads(r.stdout)
        self.assertEqual(report["problems"], [])
        self.assertTrue(report["not_runnable_here"])


if __name__ == "__main__":
    unittest.main()
