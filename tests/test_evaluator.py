#!/usr/bin/env python3
"""Per-rule TP/FP evaluation, semantics checks, and gate-component tests."""
import copy
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "detection-as-code"))
import evaluate

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = evaluate.load_collection(ROOT)
FIXTURES = sorted((ROOT / "fixtures" / "per_rule").glob("*.json"))


class EvaluatorTests(unittest.TestCase):
    def test_all_rules_match_positive_fixture(self):
        self.assertGreater(len(FIXTURES), 0)
        for f in FIXTURES:
            fx = json.loads(f.read_text(encoding="utf-8"))
            with self.subTest(rule=fx["rule_id"]):
                doc = RULES.get(fx["rule_id"])
                self.assertIsNotNone(doc, f"rule {fx['rule_id']} not in collection")
                ok, reason, _ = evaluate.run_fixture(doc, fx, RULES)
                self.assertTrue(ok, f"{fx['fixture_id']}: {reason}")

    def test_all_rules_silent_on_negative_fixture(self):
        for f in FIXTURES:
            fx = json.loads(f.read_text(encoding="utf-8"))
            neg = json.loads((ROOT / "fixtures" / "negative" / f.name).read_text(encoding="utf-8"))
            with self.subTest(rule=fx["rule_id"]):
                doc = RULES[fx["rule_id"]]
                merged = dict(fx)
                merged["events"] = fx["events"]
                merged["must_not_match"] = neg.get("must_not_match", {})
                ok, reason, _ = evaluate.run_fixture(doc, merged, RULES)
                self.assertTrue(ok, f"{neg['fixture_id']}: {reason}")

    def test_modifiers(self):
        ev = {"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "create /SC ONLOGON"}
        cases = [
            ({"Image|endswith": "\\schtasks.exe"}, True),
            ({"Image|startswith": "C:\\Windows"}, True),
            ({"CommandLine|contains": "/SC"}, True),
            ({"EventID": 1}, True),
            ({"EventID|re": "^1$"}, True),
            ({"Image|endswith": "powershell.exe"}, False),
        ]
        for selection, expected in cases:
            with self.subTest(selection=selection):
                self.assertEqual(evaluate.match_selection(ev, selection), expected)

    def test_condition_grammar(self):
        results = {"a": True, "b": False, "filter_ok": True}
        for cond, expected in [
            ("a", True), ("not b", True), ("a and not b", True),
            ("b or a", True), ("a and b", False), ("1 of a*", True),
            ("a and not filter_ok", False),
        ]:
            with self.subTest(condition=cond):
                self.assertEqual(evaluate.eval_condition(cond, results), expected)

    def test_temporal_sequence_outside_window_does_not_match(self):
        corr = [d for d in RULES.values()
                if (d.get("correlation") or {}).get("type") == "temporal"]
        self.assertTrue(corr, "no temporal correlation rule to test")
        doc = corr[0]
        events = evaluate.sequence_events(doc, RULES)
        self.assertTrue(evaluate.eval_rule(doc, events, RULES)[0])
        moved = copy.deepcopy(events)
        for ev in moved[1:]:
            ev["_ts"] = 3600
        ok, reason = evaluate.eval_rule(doc, moved, RULES)
        self.assertFalse(ok, f"out-of-window sequence matched: {reason}")

    def test_temporal_sequence_requires_every_member(self):
        doc = next(d for d in RULES.values()
                   if (d.get("correlation") or {}).get("type") == "temporal")
        events = evaluate.sequence_events(doc, RULES)
        missing = events[:-1] or events
        self.assertFalse(evaluate.eval_rule(doc, missing, RULES)[0],
                         "a partial sequence must not satisfy a temporal rule")

    def test_event_count_respects_group_by(self):
        doc = next(d for d in RULES.values()
                   if (d.get("correlation") or {}).get("type") == "event_count")
        events = evaluate.sequence_events(doc, RULES)
        group = (doc["correlation"].get("group-by") or [None])[0]
        if group:
            spread = [dict(ev, **{group: f"host-{i}"}) for i, ev in enumerate(events)]
            ok, reason = evaluate.eval_rule(doc, spread, RULES)
            self.assertFalse(ok, f"count split across {group} still matched: {reason}")

    def test_correlation_join_key_present(self):
        for doc in RULES.values():
            if "correlation" not in doc:
                continue
            with self.subTest(rule=doc["id"]):
                for key, missing in evaluate._join_values(doc, RULES).items():
                    self.assertEqual(missing, [], f"group-by {key} absent from members {missing}")

    def test_wrong_field_value_fails_assertion(self):
        fx = json.loads(FIXTURES[0].read_text(encoding="utf-8"))
        bad = copy.deepcopy(fx)
        field = next(iter(bad["assert_fields"]), None)
        if field:
            bad["assert_fields"][field] = "definitely-wrong-value"
            ok, reason, _ = evaluate.run_fixture(RULES[bad["rule_id"]], bad, RULES)
            self.assertFalse(ok)
            self.assertIn(field, reason)

    def test_mutation_typo_goes_red(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = next((ROOT / "sigma").rglob("*.yml"))
            text = src.read_text(encoding="utf-8").replace("EventID", "EventCode", 1)
            (pathlib.Path(tmp) / "mutant.yml").write_text(text, encoding="utf-8")
            mutant = evaluate.yaml.safe_load(text)
            fx = json.loads(FIXTURES[0].read_text(encoding="utf-8"))
            ok, reason, _ = evaluate.run_fixture(mutant, fx, RULES)
            self.assertFalse(ok, f"mutant rule still passed: {reason}")


class GateComponentTests(unittest.TestCase):
    def test_validator_catches_duplicate_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "sigma").mkdir()
            good = """title: t
id: 11111111-1111-4111-8111-111111111111
dedup_key: "rule:x:host:user"
status: experimental
description: d
author: a
date: 2026-11-27
tags: [attack.t1059]
tactics: [attack.execution]
references: [ref]
logsource: {product: windows, service: sysmon}
detection: {sel: {EventID: 1}, condition: sel}
falsepositives: [none]
level: low
dedup_window: "5m"
min_eval_interval: "10s"
min_os: "Windows 10 21H2"
sigma_spec_version: "2.1.0"
sample_ref: PIN-0000
"""
            (d / "sigma" / "good.yml").write_text(good, encoding="utf-8")
            (d / "sigma" / "dup.yml").write_text(good + "level: high\n", encoding="utf-8")
            script = ROOT / "detection-as-code" / "validate_rules.py"
            r = subprocess.run([sys.executable, str(script), "--path", str(d / "sigma")],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("duplicate", r.stdout)

    def test_matrix_counts_techniques_not_tactics(self):
        text = (ROOT / "attack" / "matrix.md").read_text(encoding="utf-8")
        m = re.search(r"distinct techniques: (\d+)", text)
        self.assertIsNotNone(m)
        self.assertGreater(int(m.group(1)), 0)
        self.assertNotIn("attack.tactic", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
