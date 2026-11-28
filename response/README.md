# Response per rule

Each rule needs a triage step and severity before it can be promoted.

| Rule class | Severity | First triage step |
|---|---|---|
| AMSI/ETW patch | high | Identify the calling process and parent; check for a signed module hooking it |
| WMI subscription triple | high | Enumerate `root\subscription` objects; capture CommandLineTemplate before removal |
| Run key / task / Startup writes | high | Compare the command line against an approved installer list |
| C2 headers | high | Check the destination IP reputation and process owning the socket |
| Beacon periodicity | medium | Verify against known polling software before escalating |
| Credential file access | medium | Confirm the process is not a browser or sanctioned backup agent |
| Packer YARA hits | low | Check signer and path; most will be benign packed tools |

Add a severity and a triage step to any new rule before enabling it. See
`analysis/iocs.md` and `analysis/report-template.md` for evidence minimums.

## Status

Every rule has a playbook in `response/rules/`, generated from the rule by
`tools/generate_playbooks.py`. Each one has five sections, and
`response/check_playbooks.py` reads all 39 of them:

| Section | What makes it pass |
|---|---|
| What fired | the rule's own title, summary and event IDs |
| Triage | the fields *that rule* reads, plus advice chosen by tactic - a run key and a DNS query do not get the same sentence |
| Containment | one action from a fixed vocabulary (`isolate-host`, `disable-account`, `collect-memory`, ...). "Investigate further" is not in the vocabulary |
| What to preserve | artifacts named per technique family, and the section may not contain "delete" |
| False positives | a specific benign behaviour, long enough to describe one |

Correlation rules get a different shape: their triage fields are the `group-by`
keys, and the playbook names the member rules, because an aggregate alert with
nothing underneath it sends the analyst nowhere.

The earlier files were one sentence each and pointed at
`rule:<id>:host:user` - an identifier that existed nowhere in the repository.
Nothing noticed, because a playbook is prose and nothing read it. That is the
gap G-18 named, and it is now a gate stage.

What is still not proven: **no human has worked one of these against a live
alert.** Every file says so in its status line. A playbook that has been read by
a checker is followable, not followed.
