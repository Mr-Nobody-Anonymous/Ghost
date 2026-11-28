#!/usr/bin/env python3
"""The YARA rule must match the implant shape and stay quiet on real software.

Before this, the only proof was `yara.compile()`, which checks syntax and
nothing else. `tests/test_rules.py::test_yara_matching_logic` used ad-hoc byte
blobs built inside the test; this suite reads committed files, one per
false-positive hypothesis, so each quiet file is a named claim rather than a
side effect of how the blob was assembled.

The corpus is synthetic and small. Six benign files cannot measure a
false-positive rate - that stays open in the gap register. They can prove the
rule is not trivially wrong in the six ways that matter most.
"""
import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "yara" / "corpus"
BUILDER = ROOT / "tools" / "build_yara_corpus.py"
RULE = ROOT / "yara" / "ghost_implant_structural.yar"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_yara_corpus", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class YaraCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import yara
        except ImportError:
            raise unittest.SkipTest("yara-python not installed")
        cls.yara = yara
        cls.rules = yara.compile(filepath=str(RULE))

    def test_corpus_is_current(self):
        r = subprocess.run([sys.executable, str(BUILDER), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_generator_is_deterministic(self):
        builder = load_builder()
        a = builder.files()
        b = builder.files()
        self.assertEqual(sorted(a), sorted(b))
        for key in a:
            self.assertEqual(a[key], b[key], f"{key} is not deterministic")

    def test_implant_matches(self):
        hit = self.rules.match(filepath=str(CORPUS / "implant" /
                                            "ghost_implant_synthetic.bin"))
        self.assertTrue(hit, "the implant stand-in did not match")

    def test_every_benign_file_stays_quiet(self):
        for path in sorted((CORPUS / "benign").glob("*")):
            if path.name == "README.md":
                continue
            with self.subTest(file=path.name):
                self.assertFalse(self.rules.match(filepath=str(path)),
                                 f"false positive on benign/{path.name}")

    def test_every_partial_file_stays_quiet(self):
        for path in sorted((CORPUS / "partial").glob("*")):
            with self.subTest(file=path.name):
                self.assertFalse(self.rules.match(filepath=str(path)),
                                 f"partial indicator fired on partial/{path.name}")

    def test_the_benign_corpus_is_not_empty_or_trivial(self):
        """A corpus of six empty files would pass every test above."""
        files = [p for p in (CORPUS / "benign").glob("*")
                 if p.name != "README.md"]
        self.assertGreaterEqual(len(files), 6)
        for path in files:
            self.assertGreater(path.stat().st_size, 200,
                               f"benign/{path.name} is too small to be evidence")

    def test_each_benign_file_carries_a_real_indicator(self):
        """The quiet result must be a near-miss, not a file with nothing in it."""
        indicators = [b"AmsiScanBuffer", b"EtwEventWrite", b"_MEI", b"X-Id",
                      b"PSK", b"DGA_SEED", b"svc_update.exe"]
        for path in sorted((CORPUS / "benign").glob("*")):
            if path.name == "README.md":
                continue
            data = path.read_bytes()
            present = [i for i in indicators if i in data]
            with self.subTest(file=path.name):
                self.assertTrue(present,
                                f"benign/{path.name} shares no indicator with "
                                f"the rule; it cannot be a near-miss")

    def test_documented_benign_reasons_match_the_files(self):
        """Every file in benign/ is explained in the README, by name."""
        readme = (CORPUS / "README.md").read_text(encoding="utf-8")
        for path in sorted((CORPUS / "benign").glob("*")):
            if path.name == "README.md":
                continue
            self.assertIn(path.name, readme,
                          f"benign/{path.name} has no documented reason")

    def test_editing_a_corpus_file_is_detected(self):
        """`--check` must fail if someone hand-edits a corpus file."""
        target = CORPUS / "benign" / "python_embed.bin"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"hand edit")
            r = subprocess.run([sys.executable, str(BUILDER), "--check"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("stale", r.stderr)
        finally:
            target.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
