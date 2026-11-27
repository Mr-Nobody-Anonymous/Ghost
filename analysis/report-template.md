# Finding / analysis report template

## Finding

### [SEVERITY] Title

- **Target / asset:**
- **Status:** confirmed | suspected | needs validation
- **ATT&CK / CWE / CVSS:**
- **Preconditions:**
- **Reproduction:** numbered, minimal, deterministic
- **Evidence:** exact command + output, request/response pair, UTC timestamp, sha256
- **Impact:** technical + business (confidentiality / integrity / availability)
- **Detection:** telemetry source + rule that catches it
- **Remediation:** specific fix + verification step
- **References:**

## Claim provenance

| Statement | Classification | Basis / artifact hash |
|---|---|---|
| | OBSERVED / INFERRED / SUSPECTED / UNKNOWN | |

## Coverage gaps

What the analysis did **not** determine. Example: "No dynamic detonation was
performed, so runtime AMSI patching behavior is unverified; static strings only."

## Emulation result

| Technique | ATT&CK | Expected telemetry | Observed telemetry | Verdict | Residual gap |
|---|---|---|---|---|---|
| | | | | pass / gap / tune | |

## Evidence minimums

- UTC timestamp for every action and captured response.
- Exact command/output or request/response pair.
- sha256 of every artifact.
- Account, role, and privilege level used.
- Before/after state for any write action.
- Note what was redacted and why.
