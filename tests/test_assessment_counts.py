"""`docs/assessment.md` says every number in it came from a command.

It was written from one. Then nine rules landed, the gate doubled in stages,
the test suite quintupled, and the table went on saying 38 rules, 11 stages and
53 tests. A document whose whole premise is "these numbers are measured" is the
worst place for a stale count, because it is the document a reader trusts
*because* it claims to be mechanical.

So the table is now mechanical in both directions: every number it states is
recomputed here from the tree, and a mismatch fails the gate. Nothing in this
file knows that 39 is correct - it knows that 39 is what is there.
"""
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "assessment.md"
GATE = ROOT / "ci" / "gate.sh"


def rules():
    out = []
    for path in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        # A rule is any of the three shapes: a single-event `detection`, a
        # `correlation`, or a `campaign`. Requiring `detection` silently
        # excluded the five correlations and reported 33 rules out of 39.
        if isinstance(doc, dict) and ({"detection", "correlation", "campaign"}
                                      & set(doc)):
            out.append(doc)
    return out


def single_event(docs):
    return [d for d in docs if "detection" in d]


def fields_of(doc):
    """Distinct field names a detection block constrains."""
    names = set()
    for name, body in (doc.get("detection") or {}).items():
        if name == "condition" or not isinstance(body, dict):
            continue
        names |= {k.split("|")[0] for k in body}
    return names


def actual():
    """Everything the inventory table claims, derived from the tree."""
    docs = rules()
    correlations = sum(1 for d in docs if isinstance(d.get("correlation"), dict))
    campaigns = sum(1 for d in docs if isinstance(d.get("campaign"), dict))
    singles = single_event(docs)
    techniques = set()
    for d in docs:
        for tag in d.get("tags") or []:
            if str(tag).startswith("attack.t"):
                techniques.add(str(tag).upper())
    stages = {int(n) for n in re.findall(
        r"^echo \"\[\d+[a-z]?/(\d+)\]", GATE.read_text(encoding="utf-8"), re.M)}
    assert len(stages) == 1, stages
    yara = sum(len(re.findall(r"^rule\s", p.read_text(encoding="utf-8"), re.M))
               for p in (ROOT / "yara").rglob("*.yar"))
    levels = [d.get("level") for d in docs]
    return {
        "rules": len(docs),
        "correlations": correlations,
        "campaigns": campaigns,
        "single_event": len(singles),
        "filtered": sum(1 for d in singles
                        if any(k.startswith("filter") for k in d["detection"])),
        "two_or_fewer": sum(1 for d in singles if len(fields_of(d)) <= 2),
        "high": levels.count("high"),
        "medium": levels.count("medium"),
        "low": levels.count("low"),
        "techniques": len(techniques),
        "positive": len(list((ROOT / "fixtures" / "per_rule").glob("*.json"))),
        "negative": len(list((ROOT / "fixtures" / "negative").glob("*.json"))),
        "suricata": sum(len(re.findall(r"^alert\s", p.read_text(encoding="utf-8"), re.M))
                        for p in (ROOT / "sigma").rglob("*.rules")),
        "yara": yara,
        "stages": stages.pop(),
    }


class InventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")
        cls.counts = actual()

    def row(self, label):
        """The whole row for `label`, minus the label cell.

        The table is `| Component | Count | What it is |`: the count sits in
        its own cell and the qualifiers (how many of the 39 are correlations)
        sit in the description. Reading only up to the second pipe found a
        bare number and then looked for "39 positive" inside it.
        """
        match = re.search(rf"^\| {re.escape(label)} \| (.+)$", self.text, re.M)
        self.assertIsNotNone(match, f"the inventory no longer has a {label!r} row")
        return match.group(1)

    def count(self, label):
        """Just the Count cell - the table's second column."""
        first = self.row(label).split("|")[0].strip()
        return int(re.sub(r"[^0-9]", "", first))

    def test_rule_counts(self):
        cell = self.row("Sigma rules")
        self.assertEqual(self.count("Sigma rules"), self.counts["rules"],
                         f"Sigma rules row says {cell!r}, tree has "
                         f"{self.counts['rules']}")
        self.assertIn(f"{self.counts['single_event']} single-event", cell)
        self.assertIn(f"{self.counts['campaigns']} campaign", cell)
        self.assertIn(f"{self.counts['correlations']} correlations", cell)
        self.assertIn(f"{self.counts['techniques']} ATT&CK techniques", cell)

    def test_fixture_counts(self):
        cell = self.row("Fixtures")
        total = self.counts["positive"] + self.counts["negative"]
        self.assertEqual(self.count("Fixtures"), total,
                         f"Fixtures row says {cell!r}, tree has {total}")
        self.assertIn(f"{self.counts['positive']} positive", cell)
        self.assertIn(f"{self.counts['negative']} negative", cell)

    def test_suricata_and_yara_counts(self):
        self.assertEqual(self.count("Suricata rules"), self.counts["suricata"])
        self.assertEqual(self.count("YARA rules"), self.counts["yara"])

    def test_gate_stage_count(self):
        cell = self.row("Gate stages")
        self.assertEqual(self.count("Gate stages"), self.counts["stages"],
                         f"Gate stages says {cell!r}, ci/gate.sh runs "
                         f"{self.counts['stages']}")

    def test_open_gap_count(self):
        register = (ROOT / "docs" / "gap-register.md").read_text(encoding="utf-8")
        stated = re.search(r"\*\*Now: (\d+) gaps - (\d+) open", register)
        self.assertIsNotNone(stated, "the register stopped stating its own count")
        cell = self.row("Open gaps")
        self.assertIn(f"{stated.group(2)} of {stated.group(1)}", cell,
                      "assessment and register disagree about the gap count")

    def test_rule_quality_profile(self):
        """The profile table is labelled "measured, not asserted"."""
        filtered = re.search(r"^\| Rules with a filter/allowlist \| (\d+) / (\d+)",
                             self.text, re.M)
        self.assertIsNotNone(filtered, "the filter/allowlist row is gone")
        self.assertEqual(int(filtered.group(1)), self.counts["filtered"])
        self.assertEqual(int(filtered.group(2)), self.counts["single_event"])

        thin = re.search(r"^\| Rules selecting .2 fields \| (\d+) / (\d+)",
                         self.text, re.M)
        self.assertIsNotNone(thin, "the narrow-selection row is gone")
        self.assertEqual(int(thin.group(1)), self.counts["two_or_fewer"])
        self.assertEqual(int(thin.group(2)), self.counts["single_event"])

        levels = re.search(r"^\| Level distribution \| (\d+) high / (\d+) medium / (\d+) low",
                           self.text, re.M)
        self.assertIsNotNone(levels, "the level-distribution row is gone")
        self.assertEqual(
            [int(levels.group(i)) for i in (1, 2, 3)],
            [self.counts["high"], self.counts["medium"], self.counts["low"]])

    def test_the_unfiltered_rule_count_matches_the_profile(self):
        """The risk section repeats the unfiltered number; it must agree."""
        unfiltered = self.counts["single_event"] - self.counts["filtered"]
        for match in re.finditer(r"(\d+) of the (?:\d+) single-event rules have no filter",
                                 self.text):
            self.assertEqual(int(match.group(1)), unfiltered,
                             "the risk section's unfiltered count disagrees with "
                             "the profile table")

    def test_no_retired_number_survives_elsewhere_in_the_document(self):
        """The old totals, named so they cannot quietly come back."""
        for stale in ("38 rules", "34 single-event", "11 stages", "53 tests",
                      "20 / 38", "18 / 38"):
            self.assertNotIn(stale, self.text,
                             f"assessment.md still says {stale!r}")


class NoStaleTotalTest(unittest.TestCase):
    """A stale total anywhere in prose is the defect this file exists for.

    `docs/assessment.md` was the worst offender, but it was not the only one:
    `docs/maturity.md` said "all 38 are `designed`" and "37 each", and
    `metrics/README.md` said "an entry for all 38 rules". Each was true when
    written and each was read by someone who had no reason to doubt it. This
    scans the prose for a total that contradicts the tree.

    The changelog is exempt: it records what was true at the time, and
    rewriting history to match the present is the opposite of a changelog.
    """

    def test_prose_does_not_state_a_superseded_total(self):
        counts = actual()
        n_rules = counts["rules"]
        offenders = []
        for path in sorted(ROOT.rglob("*.md")):
            if any(part in (".git", "dist", "node_modules", "attack")
                   for part in path.parts):
                continue
            if path.name == "CHANGELOG.md":
                continue
            text = path.read_text(encoding="utf-8")
            for pattern, correct in (
                    (r"\ball (\d+) rules\b", n_rules),
                    (r"\b(\d+) rules\b(?! [a-z])", n_rules),
                    (r"\b(\d+) each\b", None)):
                for match in re.finditer(pattern, text):
                    claimed = int(match.group(1))
                    if correct is not None and claimed == correct:
                        continue
                    if correct is None:
                        # "N each" is only a claim when it matches the
                        # per-rule fixture count, and only wrong when the
                        # fixtures are a different size.
                        if claimed in (counts["positive"], counts["negative"]):
                            continue
                        if claimed < 20:
                            continue    # "two of each", "three each"
                    offenders.append(
                        f"{path.relative_to(ROOT)}: {match.group(0)!r} "
                        f"(tree has {correct if correct else 'a different count'})")
        self.assertEqual(offenders, [], "\n".join(sorted(set(offenders))))


if __name__ == "__main__":
    unittest.main()
