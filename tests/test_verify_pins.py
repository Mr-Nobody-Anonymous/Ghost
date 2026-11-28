"""Pins must describe the artifact the code was measured against (G-19).

Both large inputs are gitignored, so the interesting failure is not a wrong
hash - it is a *stale* one: a review measured against one upstream tree that is
still being cited after the tree moved. That is silent, and it is what these
tests pin.
"""
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import verify_pins as V  # noqa: E402


class DerivedDigestTest(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self):
        a = {"techniques": ["T1", "T2"], "tactics": ["attack.execution"]}
        b = {"tactics": ["attack.execution"], "techniques": ["T1", "T2"]}
        self.assertEqual(V.canonical_digest(a), V.canonical_digest(b),
                         "a digest that depends on dict order fails on a "
                         "rewritten file that is otherwise identical")

    def test_reordering_a_list_changes_the_digest(self):
        self.assertNotEqual(
            V.canonical_digest({"techniques": ["T1", "T2"]}),
            V.canonical_digest({"techniques": ["T2", "T1"]}),
            "sorting hides a genuine reorder only if the sort is applied "
            "consistently; the raw digest must still distinguish them")


class AttackPinTest(unittest.TestCase):
    def test_the_pin_names_a_hash_and_a_size(self):
        data = json.loads(
            (ROOT / "attack" / "attack-bundle-pin.json").read_text(encoding="utf-8"))
        self.assertRegex(data["bundle_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(data["bundle_bytes"], 10_000_000)

    def test_a_missing_cache_is_reported_as_derived_only_not_verified(self):
        """The distinction the whole tool exists for. Without a cache, the
        bytes were not checked, and saying `verified` would be a lie."""
        rows = V.check_attack()
        status = {name: status for name, status, _ in rows}["attack"]
        cache = ROOT / json.loads(
            (ROOT / "attack" / "attack-bundle-pin.json").read_text(
                encoding="utf-8"))["bundle_path"]
        self.assertEqual(status, "verified" if cache.is_file() else "derived-only")

    def test_strict_fails_when_the_bytes_were_not_hashed(self):
        import subprocess
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_pins.py"),
                            "--strict"], capture_output=True, text=True)
        cache_present = all(
            (ROOT / json.loads(p.read_text(encoding="utf-8"))["bundle_path"]).is_file()
            for p in [ROOT / "attack" / "attack-bundle-pin.json"])
        if not cache_present:
            self.assertEqual(r.returncode, 1,
                             "--strict must fail when an artifact is uncached")


class SigmaPinTest(unittest.TestCase):
    def test_the_record_and_the_cache_agree_on_the_commit(self):
        rows = V.check_sigmahq()
        self.assertTrue(rows)
        self.assertEqual(rows[0][1], "verified",
                         "the overlap review must describe the tree that is "
                         "actually cached; a review of a different tree is the "
                         "exact failure G-19 names")

    def test_a_review_of_a_different_tree_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "attack" / "cache" / "sigmahq").mkdir(parents=True)
            record = json.loads((ROOT / "attack" / "sigmahq-overlap.json").read_text(
                encoding="utf-8"))
            record["snapshot_commit"] = "f" * 40
            (root / "attack" / "sigmahq-overlap.json").write_text(
                json.dumps(record), encoding="utf-8")
            shutil.copy(ROOT / "attack" / "cache" / "sigmahq" / "index.json",
                        root / "attack" / "cache" / "sigmahq" / "index.json")
            saved = V.ROOT
            try:
                V.ROOT = root
                rows = V.check_sigmahq()
            finally:
                V.ROOT = saved
            self.assertEqual(rows[0][1], "MISSING")
            self.assertIn("different upstream tree", rows[0][2])

    def test_an_unreviewed_snapshot_is_not_a_pass(self):
        """An empty cache must never read as 'no overlap'. tools/sigmahq_overlap
        already exits 1 in that case; this asserts the pin check agrees."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "attack").mkdir(parents=True)
            record = json.loads((ROOT / "attack" / "sigmahq-overlap.json").read_text(
                encoding="utf-8"))
            (root / "attack" / "sigmahq-overlap.json").write_text(
                json.dumps(record), encoding="utf-8")
            saved = V.ROOT
            try:
                V.ROOT = root
                rows = V.check_sigmahq()
            finally:
                V.ROOT = saved
            self.assertEqual(rows[0][1], "derived-only")


if __name__ == "__main__":
    unittest.main()
