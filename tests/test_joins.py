#!/usr/bin/env python3
"""The generated cross-platform joins must be current, and must be *right*.

The interesting bug here is not a missing file. It is a translation that looks
plausible and changes meaning. This suite caught one in its own generator: the
first version substituted selection names into the condition string and left the
`or`/`and` words alone, so `a or b or c or d` came out as
`(a and b and c) or (d) or (e) and f or ...` - EQL would have matched almost
anything. `test_condition_grouping_preserves_or_of_ands` is that regression.
"""
import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "deploy" / "build_joins.py"
JOINS = ROOT / "deploy" / "joins"


def load_tool():
    spec = importlib.util.spec_from_file_location("build_joins", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConditionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_condition_grouping_preserves_or_of_ands(self):
        """`a or b` must not become `a and b`; every disjunct stays bracketed."""
        out = self.tool.expand_condition(
            "sel_a or sel_b",
            {"sel_a": "X == 1 and Y == 2", "sel_b": "Z == 3"},
            join=None)
        self.assertEqual(out, "((X == 1 and Y == 2) or (Z == 3))")

    def test_nested_parentheses_and_not(self):
        out = self.tool.expand_condition(
            "(sel_a and sel_b) and not sel_c",
            {"sel_a": "A", "sel_b": "B", "sel_c": "C"}, join=None)
        self.assertEqual(out, "(((A) and (B)) and NOT ((C)))")

    def test_unbalanced_parentheses_is_an_error(self):
        with self.assertRaises(self.tool.TranslationError):
            self.tool.expand_condition("(sel_a or sel_b",
                                       {"sel_a": "A", "sel_b": "B"}, join=None)

    def test_unknown_selection_is_an_error(self):
        with self.assertRaises(self.tool.TranslationError):
            self.tool.expand_condition("sel_a or sel_zzz", {"sel_a": "A"}, join=None)

    def test_regex_beyond_a_literal_is_refused_for_eql(self):
        """EQL has no regex. Emitting a loose LIKE would match the wrong events."""
        with self.assertRaises(self.tool.TranslationError):
            self.tool.eql_clause("query|re", "^[a-z]{13,}\\.(com|net)$")

    def test_regex_is_translated_exactly_where_the_language_has_it(self):
        esql = self.tool.esql_clause("QueryName|re", "^[a-z]{14,}\\.com$")
        self.assertIn("RLIKE", esql)
        kql = self.tool.kusto_clause("QueryName|re", "^[a-z]{14,}\\.com$")
        self.assertIn("matches regex", kql)

    def test_exists_becomes_a_null_check_not_a_literal(self):
        self.assertEqual(self.tool.eql_clause("Computer|exists", True),
                         "host.name != null")
        self.assertEqual(self.tool.esql_clause("Computer|exists", True),
                         "host.name IS NOT NULL")
        self.assertEqual(self.tool.kusto_clause("Computer|exists", True),
                         "isnotempty(Computer)")

    def test_contains_all_is_an_and(self):
        out = self.tool.eql_clause("cs-uri-query|contains|all", ["id=", "seq="])
        self.assertEqual(out.count(" and "), 1)
        self.assertEqual(out.count(" or "), 0)


class GeneratedJoinsTest(unittest.TestCase):
    def test_generated_files_are_current(self):
        r = subprocess.run([sys.executable, str(TOOL), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_unsupported_correlation_has_both_platforms(self):
        """A rule that claims `unsupported` on Elastic and Kusto must have an
        emitted query for each, or the claim is still a dead end for users."""
        import yaml
        missing = []
        for path in sorted((ROOT / "sigma").rglob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not data.get("correlation"):
                continue
            conv = data.get("conversion") or {}
            for platform, ext in (("elastic", "eql"), ("kusto", "kql")):
                if conv.get(platform) == "unsupported":
                    candidates = [JOINS / f"{path.stem}.{ext}",
                                  JOINS / f"{path.stem}.esql"]
                    if not any(c.is_file() for c in candidates):
                        missing.append(f"{path.name} claims {platform}: "
                                       f"unsupported with no {ext} query")
        self.assertEqual(missing, [])

    def test_no_sequence_has_an_unsupported_eql_operator(self):
        """A guard against a future member rule using a modifier the translator
        silently mangles: the generator must still exit 0 today."""
        r = subprocess.run([sys.executable, str(TOOL)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_sequence_members_appear_in_rule_order(self):
        text = (JOINS / "wmi_subscription_triple.eql").read_text(encoding="utf-8")
        first = text.index('"19"')
        second = text.index('"20"')
        third = text.index('"21"')
        self.assertLess(first, second)
        self.assertLess(second, third)

    def test_maxspan_and_group_key_are_present(self):
        text = (JOINS / "patch_sequence.eql").read_text(encoding="utf-8")
        self.assertIn("sequence by host.name with maxspan=5m", text)


if __name__ == "__main__":
    unittest.main()
