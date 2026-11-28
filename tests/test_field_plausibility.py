"""A rule can read a field that cannot exist on the event it selects.

`tests/test_field_map.py` asks a different question: is every field a rule
reads *mapped* to a backend column? That check passed for
`runkey_schtask_startup_persistence` while the rule was broken. The rule
filtered its registry branch on `ParentImage`, but a Sysmon 12/13/14 event has
no parent field at all - the writer is `Image`. On every real MSI install the
filter evaluated against a missing key, returned False, and the rule fired on
the installer it was written to ignore. The map did not care, because
`ParentImage` *is* a mapped field; it just never arrives on that event.

So this file asks the narrower question the map cannot: **given the event IDs a
selection accepts, can the fields it reads actually be present?** The table is
taken from `telemetry/data-sources.md` and the Sysmon schema, not invented here.

A rule that trips on every Chrome update is worse than no rule (G-03). This is
the cheapest version of that failure to catch, because it needs no corpus: the
event is wrong on its face.
"""
import contextlib
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Which fields exist on which Sysmon events. Only the fields this repository's
# rules actually read are listed; adding a rule that reads a new field is the
# moment to check what carries it. Source: telemetry/data-sources.md.
SYSMON_FIELDS = {
    1: {"Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
        "IntegrityLevel", "Hashes", "CurrentDirectory", "ProcessId",
        "ParentProcessId", "OriginalFileName", "Company", "Description"},
    3: {"Image", "DestinationHostname", "DestinationIp", "DestinationPort",
        "SourceIp", "SourcePort", "Protocol", "Initiated"},
    5: {"Image", "ProcessId"},
    7: {"Image", "ImageLoaded", "Hashes", "Signed", "Signature",
        "SignatureStatus"},
    8: {"SourceImage", "TargetImage", "NewThreadId", "StartAddress",
        "StartModule", "StartFunction"},
    10: {"SourceImage", "TargetImage", "GrantedAccess", "CallTrace"},
    11: {"Image", "TargetFilename", "CreationUtcTime", "ProcessId"},
    12: {"Image", "TargetObject", "EventType", "ProcessId"},
    13: {"Image", "TargetObject", "Details", "EventType", "ProcessId"},
    14: {"Image", "TargetObject", "EventType", "ProcessId"},
    15: {"Image", "TargetFilename", "Hashes"},
    17: {"Image", "PipeName"},
    18: {"Image", "PipeName"},
    22: {"Image", "QueryName", "QueryResults", "QueryStatus"},
    23: {"Image", "TargetFilename"},
    25: {"Image", "Type"},
}

# Fields that exist on every Sysmon event because they come from the System
# block rather than EventData. Rules read these as scalar keys.
UNIVERSAL = {"EventID", "Computer", "User", "UtcTime", "Channel", "Provider",
             "ProcessGuid", "ProcessId"}

# Windows Security events the rules read, same idea.
SECURITY_FIELDS = {
    4624: {"TargetUserName", "LogonType", "IpAddress", "SubjectUserName"},
    4663: {"SubjectUserName", "ObjectName", "AccessMask", "ProcessName"},
    4688: {"NewProcessName", "CommandLine", "ParentProcessName",
           "SubjectUserName"},
    4698: {"TaskName", "Command", "SubjectUserName"},
    1102: {"SubjectUserName"},
}

# Field names the rules use that mean a Sysmon event but are not EventData
# keys on the events above. A `contains`/`endswith` on `ParentImage` in a
# selection restricted to registry events is precisely the bug this catches.
PROCESS_ONLY = {"ParentImage", "ParentCommandLine", "CommandLine", "Hashes",
                "CurrentDirectory", "ParentProcessId", "IntegrityLevel"}


def _eventids(body):
    """The event IDs a selection body accepts, or None if it does not say.

    None means "unrestricted", and this test deliberately says nothing about
    those selections: a rule may legitimately read a field that only some of
    its accepted events carry, as long as one of them does.
    """
    for key, value in body.items():
        if key == "EventID" or key.startswith("EventID|"):
            if isinstance(value, list):
                with_ids = set()
                for item in value:
                    with contextlib.suppress(TypeError, ValueError):
                        with_ids.add(int(item))
                return with_ids or None
            try:
                return {int(value)}
            except (TypeError, ValueError):
                return None
    return None


def _fields_read(body):
    """Field names a selection tests, ignoring modifiers and values.

    A Sigma value is often a LIST (`Image|endswith: [a, b]`) and a keyword
    group has no field name at all. Reading only scalar values made every
    filter look empty, which made the reachability test below vacuously true -
    the check passed on the very rule it was written for. Read the key, not
    the value.
    """
    names = set()
    if not isinstance(body, dict):
        return names
    for key, value in body.items():
        if key == "condition":
            continue
        name = key.split("|")[0]
        if name in ("keywords", "keyword"):
            continue
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            names.add(name)
        if isinstance(value, dict):
            names |= _fields_read(value)
    return names


def _can_exist(field, event_ids):
    """Could `field` be present on at least one of these Sysmon event IDs?"""
    if field in UNIVERSAL:
        return True
    known = set().union(*(SYSMON_FIELDS.get(i, set()) for i in event_ids))
    if not known:
        return True          # an event ID we have not modelled: stay silent
    return field in known


class PlausibleFieldTest(unittest.TestCase):
    def rules(self):
        for path in sorted((ROOT / "sigma").rglob("*.yml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            if isinstance(doc.get("correlation"), dict):
                continue
            yield path, doc

    def test_no_sysmon_selection_reads_a_field_its_events_cannot_carry(self):
        problems = []
        for path, doc in self.rules():
            det = doc["detection"]
            for name, body in det.items():
                if name == "condition" or not isinstance(body, dict):
                    continue
                ids = _eventids(body)
                if not ids:
                    continue
                # only judge selections that are Sysmon registry/process/etc,
                # i.e. ones that name an event ID we model
                if not ids & set(SYSMON_FIELDS):
                    continue
                for field in _fields_read(body):
                    if field in SECURITY_FIELDS.get(0, set()):
                        continue
                    if field in PROCESS_ONLY and field not in UNIVERSAL:
                        if not _can_exist(field, ids):
                            problems.append(
                                f"{path.relative_to(ROOT)}: {name} reads "
                                f"{field} on EventID {sorted(ids)}, which "
                                f"never carries it")
                    elif not _can_exist(field, ids) and field not in (
                            "TargetFilename", "Details"):
                        problems.append(
                            f"{path.relative_to(ROOT)}: {name} reads {field} "
                            f"on EventID {sorted(ids)}, which never carries it")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_no_branch_escapes_every_filter(self):
        """Each branch must be excludable by at least one filter.

        This is the property the original bug violated, and it is stronger than
        "does some filter read a field no branch can carry". In
        `runkey_schtask_startup_persistence` the single filter read
        `ParentImage`, which the registry branch (`sel_runkey`, Sysmon 12-14)
        cannot carry. The schtasks and Startup branches *could* carry it, so a
        check that only asked "is this filter ever reachable" was satisfied -
        while the registry branch was left with no working filter at all and
        fired on every MSI install.

        The question has to be asked per branch: pick any event this branch
        selects, and is there a filter that would reject it? If not, the branch
        is unconditionally on, and whatever it selects - including an installer
        - is an alert.
        """
        problems = []
        for path, doc in self.rules():
            det = doc["detection"]
            cond = str(det.get("condition", ""))
            if "not" not in cond:
                continue
            branches = [n for n in det if not n.startswith("filter")
                        and n != "condition" and isinstance(det[n], dict)]
            filters = {n: _fields_read(det[n]) for n in det
                       if n.startswith("filter") and isinstance(det[n], dict)}
            # A filter is only useful on a branch if that branch's events can
            # carry the field it tests.
            usable = {n: f for n, f in filters.items()
                      if any(_can_exist(fld, _eventids(det[b]) or set())
                             for fld in f for b in branches
                             if _eventids(det[b]))}
            covered = set()
            for branch in branches:
                ids = _eventids(det[branch])
                branch_fields = _fields_read(det[branch])
                for name, fields in usable.items():
                    if ids and all(f in UNIVERSAL or _can_exist(f, ids)
                                   for f in fields):
                        covered.add(branch)
                        break
                    if not ids and (fields & branch_fields or not ids):
                        covered.add(branch)
                        break
            for branch in branches:
                if branch in covered:
                    continue
                # An unconditional branch is only a problem if some sibling
                # branch IS filtered: that asymmetry is the bug - one event
                # type is protected from installers, another silently is not.
                if usable and len(covered) > 0:
                    problems.append(
                        f"{path.relative_to(ROOT)}: branch `{branch}` is "
                        f"selected but no filter can reject it, while sibling "
                        f"branches are filtered - installers and other benign "
                        f"writers reach this branch unfiltered")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_the_installer_case_behaves(self):
        """The bug and its fix, asserted on behaviour rather than on shape."""
        import sys
        sys.path.insert(0, str(ROOT / "detection-as-code"))
        import evaluate
        doc = next(d for k, d in evaluate.load_collection(ROOT).items()
                   if k.startswith("b6d4a2f8"))
        msi = {"EventID": 13,
               "Image": r"C:\Windows\System32\msiexec.exe",
               "ParentImage": r"C:\Windows\explorer.exe",
               "TargetObject": r"HKLM\Software\Microsoft\Windows"
                               r"\CurrentVersion\Run\SevenZip"}
        self.assertFalse(evaluate.eval_detection(doc, msi),
                         "a signed MSI install is the exact false positive the "
                         "installer filter exists to prevent")
        attacker = dict(msi, Image=r"C:\Windows\System32\WindowsPowerShell"
                                  r"\v1.0\powershell.exe")
        self.assertTrue(evaluate.eval_detection(doc, attacker),
                        "removing the filter must not remove the detection")


if __name__ == "__main__":
    unittest.main()
