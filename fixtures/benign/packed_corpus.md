# Benign packed corpus (spec)

The packer YARA rules will fire on legitimate software. This corpus is required
before those rules can be enabled in production.

| Class | Example | Expected trips | Decision needed |
|---|---|---|---|
| Self-extracting installer | 7-Zip SFX, NSIS installer | UPX/entropy heuristic | allowlist signer / section names |
| Packed vendor tool | Any commercial packed agent | Nuitka/Go/.NET rules | allowlist signer |
| Go CLI utility | `kubectl`, `terraform` | GoBuildInfo rule | allowlist by signed publisher |
| .NET single-file app | Modern CLI tools | DotNetSingleFile rule | allowlist publisher |
| UPX-packed portable tool | Legitimate portable utilities | Packer_UPX | allowlist path/signer |

A rule with no benign corpus entry is not production-ready. Record each trip in
`docs/tuning-log.md` with the disambiguating field: signer, path, section name,
or file size.
