# Sample pins

Pin format for a reference sample. **No sample binary is stored in this folder.**
All fields below are placeholders. Fill them only from a sample you obtained
legitimately (threat intel feed, sandbox submission, or an IR case) and record
where it came from.

## Pin record template

```yaml
sample_id: PIN-0000                    # placeholder
role: reference-build                 # reference-build | regression | fp-corpus
acquisition:
  source: ""                          # e.g. internal IR case / intel feed / user submission
  case_id: ""
  acquired_utc: ""
  handling: "restricted - do not distribute"
artifact:
  original_filename: ""
  sha256: ""                          # required
  sha1: ""
  md5: ""
  size_bytes: 0
  file_type: ""
toolchain:
  python_version: ""
  packager: ""                        # PyInstaller / Nuitka / UPX / Go / .NET
  packager_version: ""
  build_id: ""
  compiler_version: ""
analysis:
  first_seen_utc: ""
  analyst: ""
  notes: ""
rules_referencing: []                 # rule IDs that claim this sample
immutable_path: ""                    # external, access-controlled store - NOT in this repo
```

## Rules for pinning

1. A rule may reference a sample only by `sample_id`, never by a path inside this
   repository.
2. The hash is the identity. If bytes change, create a new pin; never overwrite.
3. A rebuild invalidates the pin. Regenerate fixtures and re-run the CI gate before
   changing a rule's `sample_ref`.
4. Store the artifact outside the rule repository in an access-controlled,
   hash-addressed store. Add only the metadata above to version control.
5. Every pin must name the acquisition source. A pin with no provenance is not a
   pin — it is an unverifiable claim.

## Current pins

None. `PIN-0000` above is a schema example, not a real sample.

<!-- GENERATED:START -->
## Generated references

| Sample ref | Rules | Fixtures |
|---|---|---|
| PIN-0000 | 37 | 37 |

Staleness rule: when a pin's hash changes, every rule and fixture
listed above must be revalidated and their status set to `stale`.
<!-- GENERATED:END -->
