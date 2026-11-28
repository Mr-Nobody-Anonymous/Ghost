"""The gap register must not lie about what is closed.

Twice during this project a gap row was edited to describe a fix while the row
stayed in the Open section, so the document said both things at once and read as
"open" to anyone skimming it. The section a row lives in is the claim; this test
enforces that the claim is unambiguous.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTER = ROOT / "docs" / "gap-register.md"

# Every gap that is closed, and the gate stage or test that closes it. If a row
# moves out of Open, it must appear here and the referenced evidence must exist.
CLOSED_WITH_EVIDENCE = {
    "G-08": "deploy/telemetry/set-sacls.ps1",
    "G-27": "tools/check_deployment_doc.py",
    "G-33": "telemetry/data-sources.md",
    "G-12": "analytics/beacon_jitter.py",
    "G-13": "analytics/stage_join.py",
    "G-14": "ci/convert_check.py",
    "G-15": "sigma/campaign_implant_sequence.yml",
    "G-16": "tools/build_yara_corpus.py",
    "G-18": "response/check_playbooks.py",
    "G-19": "tools/verify_pins.py",
    "G-20": ".githooks/pre-commit",
    "G-28": "telemetry/field-map.json",
    "G-29": "deploy/build_bundle.py",
    "G-30": "tools/tuning_log.py",
    "G-31": "requirements.txt",
    "G-32": "emulation/verify_emulation.py",
    "G-34": "tests/test_scope.py",
    "G-35": "pyproject.toml",
    "G-36": "tools/release.py",
    "G-37": "tools/sigmahq_overlap.py",
}


def section_of_rows(text):
    section, where = None, {}
    for line in text.splitlines():
        if line.startswith("## "):
            section = line
        match = re.match(r"^\|\s*(G-\d+)\s*\|", line)
        if match:
            where.setdefault(match.group(1), []).append(section)
    return where


class RegisterTest(unittest.TestCase):
    def setUp(self):
        self.text = REGISTER.read_text(encoding="utf-8")
        self.where = section_of_rows(self.text)

    def test_no_gap_appears_twice(self):
        dupes = {k: v for k, v in self.where.items() if len(v) > 1}
        self.assertEqual(dupes, {},
                         "a gap listed in two sections makes the register read "
                         "as open and closed at once")

    def test_every_gap_is_accounted_for(self):
        missing = [f"G-{i:02d}" for i in range(1, 38)
                   if f"G-{i:02d}" not in self.where]
        self.assertEqual(missing, [], "a gap was dropped from the register")

    def test_closed_gaps_are_not_in_the_open_section(self):
        wrong = [g for g in CLOSED_WITH_EVIDENCE
                 if any(s and "Open" in s for s in self.where.get(g, []))]
        self.assertEqual(wrong, [],
                         "these are implemented but still listed as open")

    def test_every_closed_gap_names_evidence_that_exists(self):
        absent = {g: path for g, path in CLOSED_WITH_EVIDENCE.items()
                  if not (ROOT / path).exists()}
        self.assertEqual(absent, {},
                         "a gap closed by a file that does not exist is a gap "
                         "closed by a sentence")

    def test_open_gaps_are_all_blocked_on_the_physical_lab_or_a_platform(self):
        """The honest boundary. An 'open' gap that could be closed with code
        means the work stopped early, not that the work needs a VM."""
        exempt = {
            "G-27",  # deployment procedure: written and reviewed, never run
            "G-33",  # Zeek blocks: labelled pseudocode, cannot be run here
        }
        open_gaps = {g for g, secs in self.where.items()
                     if any(s and "Open" in s for s in secs)}
        for gap in open_gaps - exempt:
            row = next(line for line in self.text.splitlines()
                       if re.match(rf"^\|\s*{gap}\s*\|", line))
            self.assertTrue(
                any(word in row.lower() for word in
                    ("lab", "capture", "vm", "sample", "host", "edr", "proxy",
                     "baseline", "measured", "bench", "run", "platform")),
                f"{gap} is open and its row does not say what it needs: {row[:160]}")

    def test_the_register_states_the_count_it_actually_has(self):
        open_n = len([g for g, s in self.where.items()
                      if any(x and "Open" in x for x in s)])
        closed_n = len(self.where) - open_n
        self.assertEqual(open_n + closed_n, 37)
        self.assertIn(f"{open_n}", self.text,
                      "the prose count and the row count disagree")


if __name__ == "__main__":
    unittest.main()
