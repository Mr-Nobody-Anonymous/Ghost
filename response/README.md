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

Every rule has a file in `response/rules/`, generated from the rule's own
metadata: severity, ATT&CK IDs, logsource, conversion state, and a first triage
step. What none of them has is a *tested* triage step - **not exercised** is the
literal status in each file, and it stays that way until an alert has been
worked in the lab.
