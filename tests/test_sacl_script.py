"""A SACL script that is wrong is worse than none: the rule stays quiet and
looks healthy (G-08).

There is no PowerShell on the build host, so these tests cannot execute the
script. They check the properties that would make it fail silently on Windows:
a target that is not a valid path, a missing guard for an absent object, a
rollback that does not exist, and - the important one - a 4663 rule whose path
no SACL covers, which is a rule that cannot fire on any host.
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build_sacl_script as B  # noqa: E402


class CoverageTest(unittest.TestCase):
    def test_every_4663_rule_has_a_target(self):
        missing = sorted(set(B.rules_reading_objectname()) - set(B.SACL_HINTS))
        self.assertEqual(missing, [],
                         "a rule reads 4663 and no SACL covers the path it "
                         "reads, so it can never fire and never says why")

    def test_each_target_names_the_rule_it_serves(self):
        for rule, spec in B.SACL_HINTS.items():
            self.assertTrue(rule.strip(), "a hint serves no rule")
            self.assertGreater(len(spec["why"]), 20, f"{rule} has no reason")

    def test_targets_are_absolute_and_specific(self):
        for spec in B.SACL_HINTS.values():
            path = spec["path"]
            self.assertTrue(path.startswith(("HKLM\\", "HKCU\\", "C:\\")),
                            f"{path} is not an absolute Windows path")
            self.assertNotIn("*", path,
                             "a wildcard target is a volume event, not a SACL")
            # A SACL on a whole user tree is millions of events a day. The
            # first version of this file had `C:\Users` and it served no rule
            # at all: credential_file_access reads Sysmon 11, not 4663.
            self.assertGreater(path.count("\\"), 2,
                               f"{path} is too broad to be a SACL")

    def test_no_target_serves_a_rule_that_does_not_read_4663(self):
        readers = set(B.rules_reading_objectname())
        for rule in B.SACL_HINTS:
            self.assertIn(rule, readers,
                          f"{rule} is given a SACL but reads no 4663 field - "
                          f"that is event volume for nothing")


class ScriptShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = B.SCRIPT.replace(
            "__TARGETS__", B.ps_list_for(B.SACL_HINTS))

    def test_the_template_has_no_unfilled_placeholder(self):
        self.assertNotIn("__TARGETS__", self.text)

    def test_it_enables_the_subcategory_before_adding_any_ace(self):
        """A SACL on an object whose subcategory is off produces nothing."""
        auditpol = self.text.index('auditpol /set /subcategory:"Registry Object"')
        first_ace = self.text.index("AddAuditRule")
        self.assertLess(auditpol, first_ace)

    def test_it_backs_up_before_it_changes(self):
        save = self.text.index("/save $bak")
        first_change = self.text.index("SetAccessControl")
        self.assertLess(save, first_change,
                        "an ACL change with no saved copy cannot be undone")

    def test_it_has_a_rollback_path(self):
        self.assertIn("[switch]$Rollback", self.text)
        self.assertIn("/restore $bak", self.text)
        self.assertGreaterEqual(self.text.count("$Rollback"), 2)

    def test_it_verifies_the_sacl_reads_back(self):
        """The silent failure: a SACL that does not stick. The script must
        check what the host says, not what the script intended."""
        self.assertIn("GetAuditRules", self.text)
        self.assertIn("read back empty", self.text)

    def test_it_skips_absent_objects_instead_of_failing(self):
        self.assertIn("absent on this host, skipping", self.text)

    def test_it_warns_about_baseline_before_enabling(self):
        self.assertIn("baseline", self.text.lower())

    def test_it_uses_a_nt_account_not_a_string_sid(self):
        self.assertIn('New-Object System.Security.Principal.NTAccount("Everyone")',
                      self.text)

    def test_it_audits_success_not_both(self):
        # Read access failures are noise: a denied read did not happen, so it
        # is not the behaviour these rules describe.
        self.assertIn("AuditFlags]::Success", self.text)
        self.assertNotIn("Failure,", self.text)


class StalenessTest(unittest.TestCase):
    def test_committed_script_matches_the_generator(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "build_sacl_script.py"), "--check"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
