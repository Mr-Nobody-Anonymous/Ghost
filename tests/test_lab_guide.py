"""Every rule the repository ships must be testable from the lab guide (G-01).

The guide exists because 39 rules had never fired and no document said what to
run. That is only worth anything if it is complete: a technique with no section
is a rule nobody can exercise, and a section for a technique no rule covers is
prose that will rot.

These tests are deliberately checkable rather than editorial. They cannot tell
whether a test procedure actually works - that needs a VM - but they can tell
whether the guide has quietly stopped covering a rule.
"""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "technique-lab-guide.md"

sys.path.insert(0, str(ROOT / "tools"))


def rule_techniques():
    """technique -> set of rule stems that cite it."""
    import yaml
    found = {}
    for path in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        for tag in doc.get("tags", []):
            tag = str(tag)
            if tag.lower().startswith("attack.t"):
                found.setdefault(tag.split(".", 1)[1].upper(), set()).add(path.stem)
    return found


def guide_techniques(text):
    """Technique IDs that have a `###` section heading."""
    return set(re.findall(r"^### (T\d{4}(?:\.\d{3})?)", text, re.M))


class CoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = GUIDE.read_text(encoding="utf-8")
        cls.rules = rule_techniques()

    def test_every_technique_has_a_section(self):
        missing = sorted(set(self.rules) - guide_techniques(self.text))
        self.assertEqual(missing, [],
                         "a rule citing this technique has no lab procedure - "
                         "it can never be proven beyond `designed`")

    def test_every_section_corresponds_to_a_rule(self):
        extra = sorted(guide_techniques(self.text) - set(self.rules))
        self.assertEqual(extra, [],
                         "a guide section for a technique no rule covers is "
                         "prose that will rot")

    def test_every_rule_is_named_somewhere(self):
        named = set()
        for match in re.finditer(r"`([a-z0-9_]+\.yml)`", self.text):
            named.add(pathlib.Path(match.group(1)).stem)
        all_rules = {s for stems in self.rules.values() for s in stems}
        missing = sorted(all_rules - named)
        self.assertEqual(missing, [],
                         f"rules never named in the guide: {missing}")


class SafetyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = GUIDE.read_text(encoding="utf-8")

    def test_every_section_states_expected_telemetry(self):
        """A test with no expected result cannot fail, and a test that cannot
        fail is not a test - it is a ritual."""
        sections = re.split(r"^### ", self.text, flags=re.M)[1:]
        self.assertGreaterEqual(len(sections), 18)
        for section in sections:
            heading = section.splitlines()[0]
            self.assertTrue(
                re.search(r"[Ee]xpect|Sysmon \d+|4663|4698|NXDOMAIN", section),
                f"{heading} does not say what telemetry the test should produce")

    def test_every_section_has_a_cleanup(self):
        """Half-cleaned WMI subscriptions and leftover Run keys are how a lab
        poisons its own baseline."""
        stateful = [s for s in re.split(r"^### ", self.text, flags=re.M)[1:]
                    if "Set-WmiInstance" in s or "New-ItemProperty" in s
                    or "Register-ScheduledTask" in s or "Set-Content" in s
                    or "Copy-Item" in s]
        self.assertTrue(stateful, "the guide should contain stateful tests")
        for section in stateful:
            heading = section.splitlines()[0]
            self.assertTrue(
                re.search(r"Remove-|Unregister-|Cleanup|Remove-Item|Cleanup",
                          section),
                f"{heading} changes state and never says how to undo it")

    def test_the_guide_does_not_contain_working_offensive_code(self):
        """The scope claim, applied to this page. Naming an API is fine - the
        rules do it. Calling one to defeat a control is not."""
        forbidden = [
            "VirtualProtect(", "WriteProcessMemory(", "CreateRemoteThread(",
            "CryptUnprotectData(", "SetWindowsHookEx(", "NtUnmapViewOfSection(",
            "minidump", "lsass", "sekurlsa",
        ]
        for name in forbidden:
            self.assertNotIn(name, self.text,
                             f"the guide contains {name}; it explains "
                             f"mechanisms and must not implement them")

    def test_it_points_at_the_repositorys_own_scope_policy(self):
        self.assertIn("SCOPE.md", self.text)

    def test_every_command_block_is_labelled_with_its_shell(self):
        for block in re.finditer(r"^```(\w*)", self.text, re.M):
            self.assertIn(block.group(1), ("powershell", "bash", "console", ""),
                          "an unlabelled block is one a reader will paste into "
                          "the wrong shell")

    def test_it_says_what_running_it_does_not_prove(self):
        self.assertIn("Cannot close", self.text)
        for gap in ("G-01", "G-02", "G-03"):
            self.assertIn(gap, self.text)


class AnchorTest(unittest.TestCase):
    """The index table is generated, and a generated link is a link nobody
    clicks until it is wrong. All 18 were broken the first time I built it:
    the slug kept the dots from the technique ID, so `T1547.001` became
    `t1547001--1547001` instead of `t1547001--registry-run-keys-and-startup-folder`."""

    def test_every_index_link_resolves_to_a_heading(self):
        import re
        text = GUIDE.read_text(encoding="utf-8")

        def slug(heading):
            s = heading.lower()
            s = re.sub(r"[^\w\s-]", "", s)
            return re.sub(r"\s+", "-", s.strip())

        headings = re.findall(r"^### (.+)$", text, re.M)
        anchors = {slug(h) for h in headings}
        links = re.findall(r"\]\(#([^)]+)\)", text)
        broken = [link for link in links if link not in anchors]
        self.assertEqual(broken, [], f"broken in-page links: {broken}")

    def test_the_index_covers_every_section(self):
        import re
        text = GUIDE.read_text(encoding="utf-8")
        index = text.split("## Rule index by technique")[1]
        indexed = set(re.findall(r"\| \[(T\d{4}(?:\.\d{3})?)\]", index))
        sections = set(re.findall(r"^### (T\d{4}(?:\.\d{3})?)", text, re.M))
        self.assertEqual(indexed, sections)


class ReferencedToolsTest(unittest.TestCase):
    def test_every_repo_path_it_names_exists(self):
        text = GUIDE.read_text(encoding="utf-8")
        missing = []
        for match in re.finditer(r"`((?:tools|telemetry|deploy|docs|analytics|"
                                 r"baseline|metrics)/[^`\s]+)`", text):
            path = match.group(1).rstrip(".,;")
            if "*" in path:
                continue
            if not (ROOT / path).exists():
                missing.append(path)
        self.assertEqual(sorted(set(missing)), [])


if __name__ == "__main__":
    unittest.main()
