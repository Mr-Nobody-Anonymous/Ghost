"""The field map is the seam between "a rule exists" and "a rule can fire".

A rule that reads `EventID` on Splunk, where the field is `EventCode`, evaluates
against a null and matches nothing. It does not error. It looks like a rule for
a behaviour that never happened. These tests pin the three ways that goes wrong:
a field with no mapping, a mapping in the wrong sourcetype, and a generated
config that no longer matches the map.
"""
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))

import build_field_map as B  # noqa: E402


class CoverageTest(unittest.TestCase):
    def test_every_field_a_rule_reads_is_mapped(self):
        data = B.load_map()
        missing = sorted(B.rule_fields() - set(data["fields"]))
        self.assertEqual(missing, [],
                         "a rule reads a field that no platform names; on "
                         "Splunk it evaluates against a null and matches "
                         "nothing without erroring")

    def test_every_mapped_field_names_all_three_platforms(self):
        for field, meta in B.load_map()["fields"].items():
            for platform in B.PLATFORMS:
                self.assertIn(platform, meta, f"{field} has no {platform} name")

    def test_eventid_is_eventcode_on_splunk(self):
        # The single most common alias omission, and the subject of G-28.
        self.assertEqual(
            B.load_map()["fields"]["EventID"]["splunk"], "EventCode")

    def test_linux_and_windows_fields_do_not_collide_silently(self):
        # Image is Sysmon's process image on Windows. If a Linux rule reading
        # Image were mapped to the same Splunk field, a Windows query would
        # satisfy it and the platform distinction in the rules would vanish.
        self.assertEqual(B.load_map()["fields"]["Image"]["splunk"], "Image")


class SourcetypeTest(unittest.TestCase):
    def setUp(self):
        self.data = B.load_map()
        self.fields = B.rule_fields()
        self.text = B.build_splunk(self.fields, self.data)

    def stanza(self, name):
        """The lines under one [sourcetype], up to the next stanza."""
        out, inside = [], False
        for line in self.text.splitlines():
            if line.startswith("["):
                inside = line.strip("[]") == name
                continue
            if inside:
                out.append(line)
        return "\n".join(out)

    def test_proxy_headers_are_not_in_the_sysmon_stanza(self):
        sysmon = self.stanza("WinEventLog:Microsoft-Windows-Sysmon/Operational")
        self.assertNotIn("cs-header-X-Id", sysmon,
                         "a proxy header alias in the Sysmon stanza parses "
                         "and never matches - worse than absent, because it "
                         "looks configured")

    def test_proxy_headers_are_in_the_proxy_stanza(self):
        squid = self.stanza("squid:access")
        self.assertIn("cs-header-X-Id", squid)
        self.assertIn("cs-header-X-Seq", squid)

    def test_zeek_dns_fields_are_in_the_dns_stanza(self):
        dns = self.stanza("zeek:dns")
        self.assertIn("query", dns)
        self.assertIn("rcode", dns)

    def test_no_alias_is_emitted_for_a_field_no_rule_reads(self):
        for line in self.text.splitlines():
            if line.startswith("FIELDALIAS-"):
                field = line.rsplit(" AS ", 1)[1]
                self.assertIn(field, self.fields,
                              f"{field} has an alias but no rule reads it")


class DerivedFieldTest(unittest.TestCase):
    def test_self_signed_certificate_is_computed_not_renamed(self):
        """Subject == issuer is the definition. Aliasing CertificateSelfSigned
        to the issuer's value produces a string where a rule tests a boolean,
        so every comparison is silently false."""
        data = B.load_map()
        self.assertIn("CertificateSelfSigned", data["derived"])
        self.assertIn("==", data["derived"]["CertificateSelfSigned"]["splunk"])
        text = B.build_splunk(B.rule_fields(), data)
        self.assertIn("EVAL-", text)
        for line in text.splitlines():
            if "CertificateSelfSigned" in line and line.startswith("FIELDALIAS"):
                self.fail("CertificateSelfSigned must not be a plain rename")


class GeneratedConfigTest(unittest.TestCase):
    def test_committed_configs_match_the_map(self):
        r = subprocess.run([sys.executable, str(ROOT / "pipeline" /
                                               "build_field_map.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_hand_edited_config_is_detected(self):
        """The mechanism the gate relies on is an exact string comparison. The
        `--check` subprocess reads the real deploy/fieldmap, so this drives the
        comparison directly rather than pretending to redirect the tool."""
        data, fields = B.load_map(), B.rule_fields()
        generated = B.build_splunk(fields, data)
        edited = generated.replace("# hand edit", "") + "# hand edit\n"
        self.assertNotEqual(generated, edited,
                            "an edited file must not compare equal to a fresh "
                            "render, or --check passes a config that no longer "
                            "matches the map")
        self.assertEqual(generated, B.build_splunk(fields, data),
                         "the render must be deterministic, or --check fails "
                         "on an unmodified tree")

    def test_elastic_pipeline_is_valid_json_with_one_processor_per_field(self):
        doc = json.loads(B.build_elastic(B.rule_fields(), B.load_map()))
        self.assertIn("processors", doc)
        set_fields = [p["set"]["field"] for p in doc["processors"]]
        self.assertEqual(len(set_fields), len(set(set_fields)),
                         "two processors setting one field: order decides, "
                         "which is an unreviewable dependency")
        for processor in doc["processors"]:
            self.assertIn("description", processor["set"])
            value = processor["set"]["value"]
            self.assertRegex(value, r"^\{\{[^}]+\}\}$",
                             "mustache templates need double braces; a "
                             ".format() call collapses them and every alias "
                             "resolves to the literal string")

    def test_kusto_view_projects_the_fields_the_rules_read(self):
        text = B.build_kusto(B.rule_fields(), B.load_map())
        self.assertIn("let Sigma_SecurityEvent", text)
        self.assertIn("EventID = EventID", text)


if __name__ == "__main__":
    unittest.main()
