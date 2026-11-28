#!/usr/bin/env python3
"""The saved-search file must stay installable and stay off.

A conf file that ships enabled is a paper cut that becomes an outage: 38
searches first evaluated in a production search head. These tests read the
generated artifact rather than the generator, so a change to the bundle or the
converter cannot silently make it wrong.
"""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONF = ROOT / "dist" / "savedsearches.conf"
MANIFEST = ROOT / "dist" / "splunk-manifest.json"


class SavedSearchesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CONF.is_file():
            raise unittest.SkipTest("dist/savedsearches.conf not built (run ci/gate.sh)")
        cls.raw = CONF.read_text(encoding="utf-8")
        # Splunk stanzas are `[name]` with `key = value`. configparser would
        # eat `%` and `=` inside SPL, so parse by hand.
        cls.stanzas = {}
        name, body = None, {}
        for line in cls.raw.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            if line.startswith("[") and line.endswith("]"):
                if name:
                    cls.stanzas[name] = body
                name, body = line[1:-1], {}
            elif name and "=" in line:
                key, value = line.split("=", 1)
                body[key.strip()] = value.strip()
        if name:
            cls.stanzas[name] = body

    def test_stanzas_parse_and_are_english(self):
        """The exact bug this replaced: 'alert.schedule — not faster than 10s'."""
        self.assertTrue(self.stanzas, "no stanzas parsed")
        for name, keys in self.stanzas.items():
            self.assertRegex(name, r"^Ghost - (high|medium|low) - .+ \[[0-9a-f]{8,32}\]$",
                             f"stanza name does not follow the convention: {name!r}")
            for key in keys:
                self.assertRegex(key, r"^[a-zA-Z_][a-zA-Z0-9_.]*$",
                                 f"{name}: {key!r} is not a legal conf key")

    def test_every_search_ships_disabled(self):
        for name, keys in self.stanzas.items():
            self.assertEqual(keys.get("enableSched"), "0",
                             f"{name} ships enabled; installing the file would "
                             f"start alerting")
            self.assertEqual(keys.get("runOnStartup"), "0", name)

    def test_no_search_runs_faster_than_five_minutes(self):
        for name, keys in self.stanzas.items():
            cron = keys.get("cron_schedule", "")
            m = re.match(r"^\*/(\d+) \* \* \* \*$", cron)
            if m:
                self.assertGreaterEqual(int(m.group(1)), 5,
                                        f"{name}: {cron} is faster than the 5m floor")
            m = re.match(r"^0 \*/(\d+) \* \* \*$", cron)
            if m:
                self.assertGreaterEqual(int(m.group(1)), 1, f"{name}: {cron}")

    def test_alerts_on_presence_not_count(self):
        for name, keys in self.stanzas.items():
            self.assertEqual(keys.get("quantity"), "0", f"{name}: alerts on a count")
            self.assertEqual(keys.get("relation"), "greater than", name)
            self.assertEqual(keys.get("counttype"), "number of events", name)

    def test_no_severity_carried_from_unmeasured_confidence(self):
        """high/medium/low in the rule is a design judgement; it maps to Splunk's
        1-5 but must not invent a 'critical' the rules never claimed."""
        for name, keys in self.stanzas.items():
            self.assertIn(keys.get("alert.severity"), {"2", "3", "4"},
                          f"{name}: severity {keys.get('alert.severity')!r}")

    def test_covers_every_deployable_non_correlation_rule(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        expected = sum(1 for r in manifest["deployable"] if not r.get("correlation"))
        self.assertEqual(len(self.stanzas), expected,
                         f"{len(self.stanzas)} stanzas for {expected} rules")
        ids = {r["id"] for r in manifest["deployable"] if not r.get("correlation")}
        width = len(re.search(r"\[([0-9a-f]+)\]$", next(iter(self.stanzas))).group(1))
        got = {re.search(r"\[([0-9a-f]+)\]$", n).group(1) for n in self.stanzas}
        self.assertEqual(got, {i[-width:] for i in ids})

    def test_suppression_matches_the_rule_s_own_dedup_fields(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        rows = [r for r in manifest["deployable"] if not r.get("correlation")]
        width = len(re.search(r"\[([0-9a-f]+)\]$", next(iter(self.stanzas))).group(1))
        by_tag = {r["id"][-width:]: r for r in rows}
        self.assertEqual(len(by_tag), len(rows), "tags are not unique")
        for name, keys in self.stanzas.items():
            row = by_tag[re.search(r"\[([0-9a-f]+)\]$", name).group(1)]
            note = row.get("dedup_note") or {}
            fields = note.get("suppress_fields") or []
            if fields:
                self.assertEqual(keys.get("alert.suppress"), "1", name)
                self.assertEqual(keys.get("alert.suppress.fields"), ", ".join(fields), name)
                self.assertEqual(keys.get("alert.suppress.period"),
                                 note.get("suppress_period"), name)
            else:
                self.assertEqual(keys.get("alert.suppress"), "0", name)

    def test_no_search_is_empty_or_multiline(self):
        for name, keys in self.stanzas.items():
            search = keys.get("search", "")
            self.assertTrue(search.strip(), f"{name}: empty search")
            self.assertNotIn("\n", search, f"{name}: search spans lines; the conf "
                                           f"parser would treat the rest as keys")


if __name__ == "__main__":
    unittest.main()
