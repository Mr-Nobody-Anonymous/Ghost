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
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "sigma").rglob("*.yml"))


def load(f):
    return yaml.safe_load(f.read_text(encoding="utf-8")) if yaml is not None else None


class RuleTests(unittest.TestCase):
    def test_rules_exist(self):
        self.assertGreater(len(RULES), 0)

    def test_unique_ids(self):
        ids = [load(f).get("id") for f in RULES if load(f)]
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
                self.assertTrue(data["fields_rule_reads"], "no field assertions")
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
                self.assertTrue(data["benign_lookalikes"] or data["expected_events"])

    def test_field_assertions_match_rule_fields(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            det = d.get("detection", {}) or {}
            selected = set()
            for name, body in det.items():
                if name == "condition" or not isinstance(body, dict):
                    continue
                selected.update(body.keys())
            if not selected:
                continue
            fx = ROOT / "fixtures" / "per_rule" / (d["id"] + ".json")
            data = json.loads(fx.read_text(encoding="utf-8"))
            with self.subTest(rule=d["id"]):
                self.assertTrue(selected.issubset(set(data["fields_rule_reads"])),
                                f"fixture does not assert {selected - set(data['fields_rule_reads'])}")


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


if __name__ == "__main__":
    import sys
    unittest.main(verbosity=2)
