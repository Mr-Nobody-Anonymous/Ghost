#!/usr/bin/env python3
"""Offline test suite: schema, fixtures, telemetry/response/metrics contracts.

These tests assert structure and field values. They do NOT prove detection on
real telemetry; that requires an independent blind capture from a pinned sample.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import unittest

try:
    import yaml
except ImportError:
    raise SystemExit("FAIL: PyYAML is required - validation must not fail open")

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "sigma").rglob("*.yml"))


def load(f):
    return yaml.safe_load(f.read_text(encoding="utf-8")) if yaml is not None else None


class RuleTests(unittest.TestCase):
    def test_rules_exist(self):
        self.assertGreaterEqual(len(RULES), 31, "rule corpus shrank")

    def test_unique_ids(self):
        ids = []
        for f in RULES:
            doc = load(f)
            self.assertIsInstance(doc, dict, f"{f.name} did not parse")
            self.assertIn("id", doc, f"{f.name} has no id")
            ids.append(doc["id"])
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule id")

    def test_schema_validator_passes(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "detection-as-code" / "validate_rules.py")],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_tactics_not_in_tags(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            for t in d.get("tags", []) or []:
                self.assertRegex(str(t), r"^attack\.t\d{4}", f"{f.name}: {t} in tags")

    def test_yara_compiles(self):
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python not installed")
        for f in (ROOT / "yara").rglob("*.yar"):
            try:
                yara.compile(filepath=str(f))
            except Exception as exc:
                self.fail(f"{f.name}: {exc}")


class FixtureTests(unittest.TestCase):
    def test_positive_fixture_per_rule(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            rid = d.get("id")
            fx = ROOT / "fixtures" / "per_rule" / (rid + ".json")
            with self.subTest(rule=rid):
                self.assertTrue(fx.exists(), f"missing positive fixture for {rid}")
                data = json.loads(fx.read_text(encoding="utf-8"))
                self.assertTrue(data["events"], "no concrete events")
                self.assertTrue(data["assert_fields"], "no field assertions")
                self.assertEqual(data["rule_id"], rid)
                self.assertEqual(data["status"], "designed")

    def test_negative_fixture_per_rule(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            rid = d.get("id")
            nf = ROOT / "fixtures" / "negative" / (rid + ".json")
            with self.subTest(rule=rid):
                self.assertTrue(nf.exists(), f"missing negative fixture for {rid}")
                data = json.loads(nf.read_text(encoding="utf-8"))
                self.assertEqual(data["rule_id"], rid)
                self.assertTrue(data["must_not_match"]["events"], "no concrete negative event")
                self.assertTrue(data["benign_lookalikes"])

    def test_field_assertions_are_real_fields(self):
        """Assert real field names, not Sigma modifier tokens like `Image|endswith`."""
        for f in RULES:
            d = load(f)
            if not d:
                continue
            det = d.get("detection", {}) or {}
            selected = set()
            for name, body in det.items():
                if name == "condition" or name.startswith("filter") or not isinstance(body, dict):
                    continue
                for k, v in body.items():
                    if k == "condition":
                        continue
                    if "|exists" in k or (isinstance(v, dict) and v.get("exists") is False):
                        continue  # absence is the assertion, not a field value
                    selected.add(k.split("|", 1)[0])
            if not selected:
                continue
            fx = ROOT / "fixtures" / "per_rule" / (d["id"] + ".json")
            data = json.loads(fx.read_text(encoding="utf-8"))
            event_fields = set()
            for ev in data["events"]:
                event_fields.update(ev.keys())
            with self.subTest(rule=d["id"]):
                missing = selected - event_fields - {"_ts"}
                self.assertFalse(missing, f"event lacks fields {missing}")
                for token in event_fields:
                    self.assertNotIn("|", token, f"modifier token leaked into event: {token}")


class ContractTests(unittest.TestCase):
    def test_response_step_per_rule(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            p = ROOT / "response" / "rules" / (d["id"] + ".md")
            self.assertTrue(p.exists(), f"no triage step for {d['id']}")
            self.assertIn("Severity:", p.read_text(encoding="utf-8"))

    def test_metrics_ceiling_per_rule(self):
        ceilings = json.loads((ROOT / "metrics" / "ceilings.json").read_text(encoding="utf-8"))
        for f in RULES:
            d = load(f)
            if not d:
                continue
            self.assertIn(d["id"], ceilings, f"no volume ceiling for {d['id']}")
            self.assertGreater(ceilings[d["id"]]["events_per_day_ceiling"], 0)

    def test_baseline_config_drift(self):
        manifest = json.loads((ROOT / "baseline" / "manifest.json").read_text(encoding="utf-8"))
        for key, path in (
            ("sysmon_config_sha256", ROOT / "telemetry" / "sysmon-config.xml"),
            ("auditpol_doc_sha256", ROOT / "telemetry" / "auditpol.md"),
        ):
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(manifest[key], actual,
                             f"{path.name} changed without a baseline re-pin")
        # A missing golden capture is recorded as a coverage gap in docs/maturity.md,
        # not silently treated as a pass.


    def test_level_distribution(self):
        counts = {}
        for f in RULES:
            d = load(f)
            if d:
                counts[d.get("level")] = counts.get(d.get("level"), 0) + 1
        self.assertLessEqual(counts.get("high", 0), len(RULES) // 2,
                             "too many high-severity rules - no triage priority")
        self.assertGreaterEqual(len(counts), 2, "all rules have the same severity")

    def test_sample_ref_resolves(self):
        pins = (ROOT / "samples" / "PINS.md").read_text(encoding="utf-8")
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            fx = json.loads(f.read_text(encoding="utf-8"))
            ref = fx.get("sample_ref", "")
            self.assertTrue(ref, f"{f.name}: no sample_ref")
            self.assertIn(ref, pins, f"{f.name}: sample_ref {ref} not in PINS.md")
            if fx.get("status") == "captured":
                self.assertNotEqual(ref, "PIN-0000", "captured fixture cannot use schema placeholder")

    def test_status_state_machine(self):
        allowed = {"designed", "captured", "validated", "deployed", "stale", "deprecated"}
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            fx = json.loads(f.read_text(encoding="utf-8"))
            self.assertIn(fx.get("status"), allowed, f"{f.name}: bad status")
        for f in RULES:
            d = load(f)
            if d:
                self.assertIn(d.get("status"), allowed, f"{f.name}: bad rule status")

    def test_min_eval_interval_present(self):
        for f in RULES:
            d = load(f)
            if d:
                self.assertTrue(d.get("min_eval_interval"), f"{f.name}: no min_eval_interval")
                self.assertTrue(d.get("dedup_window"), f"{f.name}: no dedup_window")


if __name__ == "__main__":
    unittest.main(verbosity=2)
