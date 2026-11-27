# Triage workflow

For a suspected sample of this family. Offline work; no scope signal needed.

## 1. Preserve and hash

```bash
sha256sum sample.bin
file sample.bin
cp sample.bin sample.bin.orig     # working copy vs original
```

Record UTC time, who collected it, and where it was found. Store hashes with
every conclusion (see `report-template.md`).

## 2. Static structure

```bash
python3 ~/security-tools/sec.py triage file sample.bin
python3 ~/security-tools/sec.py triage pe sample.bin --markdown   # if PE
python3 ~/security-tools/sec.py ioc extract --input sample.bin
python3 ~/security-tools/sec.py decode <base64-or-hex-blob>
python3 ~/security-tools/sec.py secrets scan <extracted-tree>
```

Look for: PyInstaller overlay / `_MEI` paths, `AmsiScanBuffer`/`EtwEventWrite`
strings, `X-Id`/`X-Seq`, DGA seed constants, `svc_update.exe` + `autorun.inf`.

## 3. YARA match

```bash
yara -r ../yara/ sample.bin
```

A match is a lead, not a verdict. Correlate with structural observations and
runtime telemetry. Note which rule conditions fired.

## 4. Dynamic (isolated lab only)

- Detonate in an Internal-network VM with a snapshot; no host or LAN egress.
- Capture process creation, registry changes, file writes, DNS, and netflow.
- Use a loopback listener, not an external C2, if beacon behavior is expected.
- Do not supply real credentials or real user data to the sample.

## 5. Map to ATT&CK

Use `../ATT&CK-coverage.md` and `python3 ~/security-tools/sec.py offensive <technique>`
to pair each observed behavior with its detection counterpart.

## 6. Report

Classify every statement as OBSERVED / INFERRED / SUSPECTED / UNKNOWN. State
explicitly what the analysis did **not** determine (coverage gaps). See
`report-template.md`.
