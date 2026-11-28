"""A playbook is prose until something executes it (G-18).

The previous files told the analyst to check `rule:<id>:host:user`, which is not
a field, not a query, and not a thing that exists. Nothing caught it because
nothing read a playbook. These tests read every one.
"""
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "response"))
sys.path.insert(0, str(ROOT / "tools"))

import check_playbooks as C  # noqa: E402
import generate_playbooks as G  # noqa: E402


class GeneratedPlaybookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = G.load_rules()          # list of (path, doc)
        cls.by_id = {doc["id"].lower(): (p, doc) for p, doc in cls.rules}

    def test_there_is_one_playbook_per_rule(self):
        ids = {doc["id"].lower() for _p, doc in self.rules}
        on_disk = {p.stem.lower() for p in C.PLAYBOOKS.glob("*.md")}
        self.assertEqual(ids, on_disk,
                         "a rule without a playbook has no triage path, and a "
                         "playbook without a rule is a leftover")

    def test_committed_playbooks_match_their_rules(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" /
                                                "generate_playbooks.py"),
                            "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_every_playbook_passes_the_checker(self):
        r = subprocess.run([sys.executable, str(ROOT / "response" /
                                                "check_playbooks.py"), "--json"],
                           capture_output=True, text=True)
        findings = json.loads(r.stdout)
        bad = {f["playbook"]: f["errors"] for f in findings if f["errors"]}
        self.assertEqual(bad, {}, f"playbooks that cannot be carried out: {bad}")

    def test_triage_lists_fields_the_rule_actually_reads(self):
        """The original defect, precisely: a step naming an identifier that
        exists nowhere. Checked against the rule's own detection block."""
        for _path, doc in self.rules:
            text = G.render(_path, doc)
            fields = G.fields_of(doc)
            triage = text.split("## Triage", 1)[1].split("## Containment", 1)[0]
            for line in triage.splitlines():
                if not line.startswith("- `"):
                    continue
                field = line.removeprefix("- ").strip("`")
                self.assertIn(field, fields,
                              f"{doc['id']} triage names {field}, which the "
                              f"rule does not read ({fields})")

    def test_a_correlation_playbook_names_its_member_rules(self):
        corr = [(p, d) for p, d in self.rules
                if isinstance(d.get("correlation"), dict)]
        self.assertTrue(corr, "no correlation rules found - the class exists")
        for path, doc in corr:
            text = G.render(path, doc)
            for member in G.sub_rules_of(doc):
                self.assertIn(member, text,
                              "a correlation alert that does not name its "
                              "members sends the analyst to an aggregate with "
                              "nothing underneath")

    def test_containment_is_an_action_not_an_intention(self):
        for path, doc in self.rules:
            text = G.render(path, doc)
            containment = text.split("## Containment", 1)[1].split("##", 1)[0]
            self.assertTrue(
                any(a in containment for a in C.CONTAINMENT_ACTIONS),
                f"{doc['id']} containment names no action from the vocabulary")

    def test_preservation_never_says_delete(self):
        for path, doc in self.rules:
            text = G.render(path, doc)
            preserve = text.split("## What to preserve", 1)[1].split("##", 1)[0]
            for verb in ("delete", "wipe", "reimage"):
                self.assertNotIn(verb, preserve.lower(),
                                 f"{doc['id']} tells the analyst to {verb}")


class CheckerTest(unittest.TestCase):
    def test_the_original_placeholder_fails(self):
        """The exact file that shipped: a rule:<id>:host:user reference and no
        sections. If this passes, the checker has stopped checking."""
        old = ("# 1a2b3c4d\n\n- First triage step: confirm field values from "
               "`rule:1a2b3c4d:host:user` against a clean baseline.\n")
        rules = {d["id"].lower(): (p, d) for p, d in G.load_rules()}
        # check_playbooks wants (doc, fields, path) per id.
        rules = {k: (d, set(G.fields_of(d)), p) for k, (p, d) in rules.items()}
        errors, _warnings = C.check_one(
            "1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a01", old, rules, set())
        self.assertTrue(any("missing section" in e for e in errors), errors)

    def test_an_invented_field_is_a_warning_not_a_pass(self):
        rules = {d["id"].lower(): (p, d) for p, d in G.load_rules()}
        doc_id, (path, doc) = next(iter(rules.items()))
        text = G.render(path, doc)
        bad = text.replace("- `EventID`", "- `EventID`\n- `NoSuchField`")
        _errors, warnings = C.check_one(doc_id, bad, rules, set())
        self.assertTrue(any("NoSuchField" in w for w in warnings))

    def test_containment_must_name_a_known_action(self):
        rules = {d["id"].lower(): (p, d) for p, d in G.load_rules()}
        doc_id, (path, doc) = next(iter(rules.items()))
        text = G.render(path, doc).replace("`isolate-host`", "`look at it`")
        text = text.replace("`block-domain`", "`look at it`")
        text = text.replace("`collect-memory`", "`look at it`")
        text = text.replace("`revoke-session`", "`look at it`")
        text = text.replace("`kill-process`", "`look at it`")
        text = text.replace("`quarantine-file`", "`look at it`")
        text = text.replace("`disable-account`", "`look at it`")
        errors, _ = C.check_one(doc_id, text, rules, set())
        self.assertTrue(any("containment names no action" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
