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
sys.path.insert(0, str(ROOT / "detection-as-code"))
import evaluate  # noqa: E402

RULES = sorted((ROOT / "sigma").rglob("*.yml"))


def load(f):
    return yaml.safe_load(f.read_text(encoding="utf-8"))


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
        # A correlation rule may not share an id with its member rule, or
        # pySigma resolves the correlation to itself and conversion fails.
        for f in RULES:
            doc = load(f)
            if "correlation" in doc:
                self.assertNotIn(doc["id"], doc["correlation"]["rules"],
                                 f"{f.name}: correlation lists its own id as a member")

    def test_schema_validator_passes(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "detection-as-code" / "validate_rules.py")],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_sigma_status_not_repo_lifecycle(self):
        """`status` is parsed by pySigma; a repo-only value stops conversion."""
        allowed = {"stable", "test", "experimental", "deprecated", "unsupported"}
        for f in RULES:
            doc = load(f)
            if doc:
                self.assertIn(doc.get("status"), allowed, f"{f.name}: non-Sigma status")
                self.assertIn(doc.get("lifecycle"),
                              {"designed", "captured", "validated", "deployed",
                               "stale", "deprecated"},
                              f"{f.name}: lifecycle must use the repo vocabulary")

    def test_tactics_not_in_tags(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            for t in d.get("tags", []) or []:
                self.assertRegex(str(t), r"^attack\.t\d{4}", f"{f.name}: {t} in tags")

    def test_no_double_escaped_paths(self):
        """`'\\\\autorun.inf'` is a YAML literal yielding a real backslash; two
        real backslashes never occur in a Windows path, so it is always a bug."""
        offenders = []
        for f in RULES:
            doc = load(f) or {}
            stack = [doc.get("detection", {}), doc.get("correlation", {})]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    stack.extend(node.values())
                elif isinstance(node, list):
                    stack.extend(node)
                elif isinstance(node, str) and "\\\\" in node:
                    offenders.append(f"{f.name}: {node!r}")
        self.assertEqual(offenders, [], "double-escaped path literal(s) found")

    def test_correlation_join_keys_exist_in_members(self):
        """Every group-by field must be selectable from each member rule."""
        collection = evaluate.load_collection(ROOT)
        for f in RULES:
            doc = load(f)
            if not doc or "correlation" not in doc:
                continue
            for key, missing in evaluate._join_values(doc, collection).items():
                self.assertEqual(missing, [],
                                 f"{f.name}: group-by field {key} is not in member detection(s)")

    def test_correlation_types_are_sigma_21(self):
        allowed = {"event_count", "value_count", "temporal", "temporal_ordered",
                   "value_sum", "value_avg", "value_percentile", "value_median"}
        for f in RULES:
            doc = load(f)
            if not doc or "correlation" not in doc:
                continue
            self.assertIn(doc["correlation"].get("type"), allowed,
                          f"{f.name}: {doc['correlation'].get('type')} is not a Sigma 2.1 type")
            self.assertNotIn("|", json.dumps(doc.get("detection", {})),
                             f"{f.name}: deprecated pipe aggregation in a detection condition")

    def test_conversion_claim_is_declared_and_valid(self):
        for f in RULES:
            doc = load(f)
            if not doc:
                continue
            conv = doc.get("conversion")
            self.assertIsInstance(conv, dict, f"{f.name}: no conversion block")
            for backend in ("splunk", "elastic", "kusto"):
                self.assertIn(conv.get(backend), ("supported", "unsupported"),
                              f"{f.name}: conversion.{backend} invalid")

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

    def test_fixtures_are_current(self):
        """A fixture that no longer matches its rule is stale, not passing."""
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "generate_fixtures.py"), "--check"],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_assert_fields_are_on_the_matched_event(self):
        """Every asserted field must exist on an event the rule actually matches.

        Asserting a field that only appears in a different OR-branch of the rule
        is not a true-positive proof: it is a field the alert would never carry.
        """
        collection = evaluate.load_collection(ROOT)
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            doc = collection[data["rule_id"]]
            matched = evaluate.eval_rule(doc, data["events"], collection)
            with self.subTest(rule=data["rule_id"]):
                self.assertTrue(matched[0], matched[1])
                if "correlation" in doc:
                    continue
                hits = [ev for ev in data["events"] if evaluate.eval_detection(doc, ev)]
                present = set()
                for ev in hits:
                    present.update(ev.keys())
                missing = set(data["assert_fields"]) - present
                self.assertFalse(missing, f"assert_fields not on matching event: {missing}")

    def test_fixture_paths_and_path_like_values(self):
        """No fixture may contain a value no Windows host could emit."""
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            for ev in data["events"]:
                for key, value in ev.items():
                    if key.startswith("_"):
                        continue
                    if key in ("TargetObject", "ObjectName", "RegistryKey"):
                        self.assertFalse(str(value).startswith("C:\\"),
                                         f"{f.name}: registry key rendered as a path: {value}")
                    if key in ("Image", "TargetFilename", "ParentImage") and value:
                        self.assertTrue(
                            str(value).startswith(("C:\\", "\\\\")) or "_MEI" in str(value),
                            f"{f.name}: {key}={value!r} is not a Windows path")
                        self.assertNotRegex(str(value).lower(), r"\.(bmp|db|enc|zip)/",
                                            f"{f.name}: extension used as a directory")

    def test_per_rule_status_never_claims_capture(self):
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("status") == "captured":
                self.assertNotEqual(data.get("sample_ref"), "PIN-0000",
                                    f"{f.name}: captured fixture needs a real pin")


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

    def test_status_state_machine(self):
        allowed = {"designed", "captured", "validated", "deployed", "stale", "deprecated"}
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            fx = json.loads(f.read_text(encoding="utf-8"))
            self.assertIn(fx.get("status"), allowed, f"{f.name}: bad status")
        for f in RULES:
            d = load(f)
            if d:
                self.assertIn(d.get("lifecycle"), allowed, f"{f.name}: bad lifecycle")

    def test_min_eval_interval_present(self):
        for f in RULES:
            d = load(f)
            if d:
                self.assertTrue(d.get("min_eval_interval"), f"{f.name}: no min_eval_interval")
                self.assertTrue(d.get("dedup_window"), f"{f.name}: no dedup_window")


if __name__ == "__main__":
    unittest.main(verbosity=2)
