#!/usr/bin/env python3
"""Generate a response playbook that an analyst can follow, per rule (G-18).

The previous `response/rules/*.md` files were one sentence each: a severity, an
ATT&CK id, and "confirm field values from `rule:<id>:host:user` against a clean
baseline". That identifier exists nowhere in the repository. So 39 playbooks
pointed their reader at a field that cannot be looked up, and nothing noticed,
because a playbook is prose and nobody executes prose.

This generates the playbook from the rule itself:

  * What fired     - the rule's own title, detection summary and event IDs
  * Triage         - the fields the rule reads, in the order to check them, with
                     the baseline to compare against
  * Containment    - an action chosen from a fixed vocabulary by ATT&CK tactic,
                     so "investigate further" is not an option
  * What to preserve - artifacts named per technique, not per rule
  * False positives - the benign behaviour that produces the same telemetry

Then `response/check_playbooks.py` verifies the result, and this generator's
own tests fail if a rule gets a playbook whose fields it does not read.

Usage:
    python3 tools/generate_playbooks.py
    python3 tools/generate_playbooks.py --check
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "response" / "rules"

# Containment by tactic. Every rule cites at least one technique, so every rule
# gets at least one action; a rule with no tactic is a schema failure upstream.
CONTAINMENT_BY_TACTIC = {
    "persistence": ("disable-account",
                    "Remove the persistence entry only after capturing its "
                    "command line and the writing process. Then disable the "
                    "account that created it: `net user <account> /active:no`."),
    "privilege-escalation": ("isolate-host",
                             "Isolate the host from the network before touching "
                             "anything: a tampered token invalidates every "
                             "subsequent judgement on that box."),
    "defense-evasion": ("collect-memory",
                        "Capture memory first. If a security component was "
                        "tampered with, the on-disk image tells you what it "
                        "looks like now, not what it looked like when it ran."),
    "credential-access": ("revoke-session",
                          "Reset the credential and invalidate live sessions. "
                          "Assume the material left the host the moment it was "
                          "read: a read is not a maybe."),
    "command-and-control": ("block-domain",
                            "Block the destination at the resolver and the "
                            "proxy. Record the full URI and every header the "
                            "proxy retained before the block goes in."),
    "exfiltration": ("block-domain",
                     "Block the destination, then size the transfer from the "
                     "proxy or flow logs before isolating: the volume decides "
                     "whether this is a report or an incident."),
    "execution": ("kill-process",
                  "Stop the process by PID after capturing the image. Then "
                  "check what its parent did, because the parent chose it."),
    "discovery": ("isolate-host",
                  "Enumeration alone is not damage, so isolate rather than "
                  "erase: the value of this alert is the next step it "
                  "predicts, not the enumeration itself."),
    "impact": ("isolate-host",
               "Isolate immediately. Impact techniques destroy the evidence "
               "that would explain them, so the order matters more than the "
               "action."),
    "lateral-movement": ("isolate-host",
                         "Isolate both hosts, the source and the target. "
                         "Isolating one leaves the other compromised and "
                         "unwatched."),
    "collection": ("quarantine-file",
                   "Quarantine the archive rather than deleting it, and "
                   "record its hash before it moves."),
    "initial-access": ("quarantine-file",
                       "Quarantine the delivering file and preserve its hash. "
                       "The same file almost certainly reached other hosts."),
}

# Preserve lists by technique family. Naming the artifact rather than the
# category is the difference between a list and a platitude.
PRESERVE = {
    "T1547": ("- The registry key's full path and its last-write time\n"
              "- The `Details` value verbatim, including quoting\n"
              "- The `Image` process that wrote it, and its parent\n"
              "- A copy of the value before any cleanup"),
    "T1053": ("- The scheduled task XML (`schtasks /query /xml`)\n"
              "- The task's author and registration date\n"
              "- The command the task runs, as stored, not as displayed"),
    "T1562": ("- The process image that performed the change\n"
              "- The previous value of any registry setting that was altered\n"
              "- A memory image if on-disk tampering is suspected\n"
              "- The Defender operational log, which records its own disabling"),
    "T1685": ("- A memory image of the target process\n"
              "- The loaded-module list at the time of the alert\n"
              "- The EDR/AV product logs for the host, if present"),
    "T1071": ("- The full URI, including query string\n"
              "- Every proxy-retained header, particularly the custom ones\n"
              "- The process that owned the socket, if the proxy export joins it"),
    "T1041": ("- Flow records with byte counts, not just connection records\n"
              "- The destination's reputation at the time of the alert\n"
              "- The full URI and headers for any HTTP transfer"),
    "T1003": ("- The Security log for the host, before log rotation\n"
              "- The process command line and the account it ran under\n"
              "- Any file the process wrote, including temporary ones"),
    "T1059": ("- The full command line, not the truncated display form\n"
              "- The parent process and its command line\n"
              "- Any script file the command referenced, with its hash"),
}

DEFAULT_PRESERVE = ("- The alert's raw event, verbatim, before any field is "
                    "normalised\n"
                    "- The host's clock offset from the collector\n"
                    "- The rule version that fired, from the rule's own id")

# The benign behaviour that produces the same telemetry, by family. This is the
# section that decides whether a rule is usable: a false-positive section that
# says "may be benign" is not triage.
FALSE_POSITIVES = {
    "T1547": ("An approved installer writing a Run key, and the software "
              "update mechanism refreshing it afterwards. Both are legitimate "
              "and both look identical at the registry level - the "
              "discriminator is the writing process's signature and path, not "
              "the key."),
    "T1053": ("Software updaters register scheduled tasks with SYSTEM "
              "context and a path under `Program Files`. Check the task's "
              "author and the signature of the binary it runs; a vendor task "
              "resolves to a signed path and a stable author."),
    "T1562": ("Endpoint management tools legitimately stop and start security "
              "services during an upgrade. The discriminator is whether the "
              "service comes back and whether the change came from a signed "
              "management agent rather than `sc.exe` in a user's session."),
    "T1685": ("Anti-cheat and DRM components patch their own process memory. "
              "They do it from their own process, with a signed image, at "
              "startup - the same telemetry but a stable parent."),
    "T1071": ("Legitimate applications use HTTP for telemetry and updates. "
              "The custom-header pair is what separates this: a normal client "
              "does not send `X-Id` and `X-Seq` together with no cookie."),
    "T1041": ("Backup agents and cloud sync clients upload large volumes on a "
              "schedule. They resolve to a vendor domain and run from a "
              "service account, not from a user's interactive session."),
    "T1003": ("Backup software reads SAM and NTDS through the Volume Shadow "
              "Copy API, as SYSTEM, on a schedule. The discriminator is the "
              "parent: a backup service, not `cmd.exe` under a user."),
    "T1059": ("IT automation runs PowerShell and WMI on managed hosts. The "
              "discriminator is the execution context: a management tool's "
              "signed binary and a service account, not `explorer.exe`."),
}

# How to check each field, by tactic. The generic sentence ("compare against a
# clean baseline") is true and useless: what a run key looks like on a clean box
# has nothing to do with what a DNS query looks like.
TRIAGE_HINT = {
    "persistence": "Compare the registry/task/file artifact against a host at "
                   "the same patch level. Persistence is not abnormal; "
                   "unsigned persistence written from a user's session is.",
    "execution": "Read the parent process before the command line. The command "
                 "line tells you what ran; the parent tells you who chose it.",
    "defense-evasion": "Check whether the component came back. A service that "
                       "was stopped and stayed stopped is the signal; one that "
                       "restarted during an upgrade is not.",
    "credential-access": "Identify the account and the process. A backup agent "
                         "reading SAM as SYSTEM is ordinary; cmd.exe reading it "
                         "from a user session is not.",
    "command-and-control": "Compare the destination against the process that "
                           "resolved it. A browser is expected to resolve "
                           "unfamiliar names; an Office process is not.",
    "exfiltration": "Get byte counts, not connection counts. A blocked "
                    "connection is not an incident; 400 MB out of a workstation "
                    "is.",
    "discovery": "Enumeration is usually the quiet step before a loud one. Look "
                 "for what the same process did next, not at the enumeration.",
    "impact": "Establish scope before cause. Impact techniques spread, so the "
              "question is how many hosts, not which one.",
}

DEFAULT_TRIAGE = ("Check each field for presence before checking its value. A "
                  "missing field means the collector never populated it, and a "
                  "rule matching on nulls is quiet rather than empty.")

DEFAULT_FP = ("The behaviour this rule matches has legitimate causes on a "
              "managed host. Before closing, identify the parent process and "
              "whether the binary is signed; a signed path under `Program "
              "Files` with a service-account parent is the ordinary case.")


def load_rules():
    import yaml
    rules = []
    for path in sorted((ROOT / "sigma").rglob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or "id" not in doc:
            continue
        rules.append((path, doc))
    return rules


def fields_of(doc):
    """Leaf fields for a detection rule, group-by fields for a correlation.

    A correlation rule has no `detection` block at all: it aggregates other
    rules. Its triage fields are the ones it grouped by, and the rules it
    aggregates are what to open. Returning an empty list here produced six
    playbooks with an empty triage section - a page that tells an analyst
    nothing at the moment they need it.
    """
    corr = doc.get("correlation")
    if isinstance(corr, dict):
        return list(corr.get("group-by") or [])
    out = []
    for name, body in (doc.get("detection") or {}).items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for key in body:
            field = key.split("|", 1)[0]
            if field not in out:
                out.append(field)
    return out


def techniques_of(doc):
    return [str(t).split(".", 1)[1].upper() for t in doc.get("tags", [])
            if str(t).lower().startswith("attack.t")]


def tactics_of(doc):
    import yaml
    pin = yaml.safe_load((ROOT / "attack" / "attack-bundle-pin.json")
                         .read_text(encoding="utf-8"))
    mapping = pin.get("technique_tactics", {})
    out = []
    for tech in techniques_of(doc):
        for tactic in mapping.get(tech, []) or []:
            if tactic not in out:
                out.append(tactic)
    return out


def sub_rules_of(doc):
    corr = doc.get("correlation")
    if isinstance(corr, dict):
        return [str(r) for r in (corr.get("rules") or [])]
    return []


def event_ids_of(doc):
    ids = []
    for name, body in (doc.get("detection") or {}).items():
        if name == "condition" or not isinstance(body, dict):
            continue
        value = body.get("EventID")
        if isinstance(value, list):
            ids.extend(value)
        elif value is not None:
            ids.append(value)
    return sorted({int(v) for v in ids if str(v).isdigit()})


def family_of(techniques):
    """The 5-character technique family, e.g. T1547 from T1547.001."""
    for tech in techniques:
        base = tech.split(".")[0]
        if base in PRESERVE:
            return base
    return None


def render(path, doc):
    rule_id = doc["id"]
    fields = fields_of(doc)
    techniques = techniques_of(doc)
    tactics = tactics_of(doc)
    events = event_ids_of(doc)
    family = family_of(techniques)

    sub_rules = sub_rules_of(doc)
    tactic = next((t for t in tactics if t in CONTAINMENT_BY_TACTIC), None)
    action, action_text = CONTAINMENT_BY_TACTIC.get(
        tactic, ("isolate-host",
                 "Isolate the host pending a decision that needs no further "
                 "telemetry."))

    lines = [f"# {doc.get('title', rule_id)}", "",
             f"- Rule: `{rule_id}`",
             f"- Severity: {doc.get('level', 'medium')}",
             f"- ATT&CK: {', '.join(techniques) or 'none declared'}",
             f"- Tactic: {tactic or 'unmapped'}",
             "- Status: **drafted from the rule, not worked against a live alert**",
             "", "## What fired", "",
             doc.get("description", "").strip(), "",
             f"Event IDs in scope: {', '.join(str(e) for e in events) or 'none'}.", ""]
    if sub_rules:
        corr = doc.get("correlation") or {}
        lines += [f"This is a correlation rule. It fires when {len(sub_rules)} "
                  f"underlying rule(s) reach {corr.get('condition')} within "
                  f"{corr.get('timespan')}, grouped by "
                  f"{', '.join(fields) or 'nothing'}.", "",
                  "Underlying rules:", ""]
        lines += [f"- `{r}`" for r in sub_rules]
        lines += ["", "Open the underlying alert before this one. A correlation "
                  "alert with no visible member event is a gap in the "
                  "underlying rule's collector, not a quiet incident.", ""]
    lines += ["## Triage", "",
              "Check these in order. The first one that is empty means the rule "
              "matched on a field the collector did not populate.", ""]
    for field in fields:
        lines.append(f"- `{field}`")
    lines += ["",
              TRIAGE_HINT.get(tactic, DEFAULT_TRIAGE), "",
              "## Containment", "",
              f"`{action}` - {action_text}", "",
              "Do not close out on the containment action alone. The entry "
              "being removed does not answer how it got there.", "",
              "## What to preserve", "",
              PRESERVE.get(family, DEFAULT_PRESERVE), "",
              "## When this is a false positive", "",
              FALSE_POSITIVES.get(family, DEFAULT_FP), ""]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    rules = load_rules()
    if args.check:
        stale = []
        for path, doc in rules:
            target = OUT / f"{doc['id']}.md"
            if not target.is_file() or target.read_text(encoding="utf-8") != render(path, doc):
                stale.append(target.name)
        if stale:
            for name in stale:
                print(f"FAIL response/rules/{name} is stale; run "
                      f"python3 tools/generate_playbooks.py", file=sys.stderr)
            return 1
        print(f"playbooks: {len(rules)} generated from their rules, none stale")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for path, doc in rules:
        (OUT / f"{doc['id']}.md").write_text(render(path, doc), encoding="utf-8")
    print(f"playbooks: wrote {len(rules)} to response/rules/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
