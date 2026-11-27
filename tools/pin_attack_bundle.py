#!/usr/bin/env python3
"""Regenerate attack/attack-bundle-pin.json from a real ATT&CK STIX bundle.

The previous pin was a hand-written list of technique IDs with a placeholder
hash, so it could not catch what it existed to catch: the list contained T1533,
which is not a technique in ATT&CK 14.1 at all, and validation passed because
the rules were checked against a list derived from the rules.

The bundle is 40+ MB and is not committed. This script fetches it by tag,
verifies or records its sha256, and rewrites the pin from the bundle's own
external_references - so the technique list cannot drift from the source.

Usage:
    python3 tools/pin_attack_bundle.py --version 14.1 --fetch
    python3 tools/pin_attack_bundle.py --bundle ~/attack.json --version 14.1
    python3 tools/pin_attack_bundle.py --verify          # check the cached bundle
"""
import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PIN = ROOT / "attack" / "attack-bundle-pin.json"
CACHE = ROOT / "attack" / "cache"

TAG_URL = ("https://github.com/mitre-attack/attack-stix-data/releases/download/"
           "v{version}/enterprise-attack.json")
API_URL = ("https://api.github.com/repos/mitre-attack/attack-stix-data/contents/"
           "enterprise-attack/enterprise-attack-{version}.json?ref=v{version}")

SLUG = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
    # ATT&CK v19/v20 tactic restructure. Defense Evasion was split; both new
    # tactics must map or the pin build refuses to run.
    "Stealth": "stealth",
    "Defense Impairment": "defense-impairment",
}


def fetch(version):
    """Download the bundle. Falls back to the contents API when the release
    asset host is not reachable from the build network."""
    import urllib.request

    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / f"enterprise-attack-{version}.json"
    for url, headers in (
        (TAG_URL.format(version=version), {}),
        (API_URL.format(version=version), {"Accept": "application/vnd.github.raw"}),
    ):
        try:
            req = urllib.request.Request(url, headers=headers)
            data = urllib.request.urlopen(req, timeout=600).read()
        except Exception as exc:  # noqa: BLE001 - report and try the next source
            print(f"  {url} -> {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        if data[:1] != b"{":
            print(f"  {url} did not return JSON", file=sys.stderr)
            continue
        target.write_bytes(data)
        print(f"  fetched {len(data)} bytes from {url.split('?')[0]}")
        return target
    raise SystemExit("could not fetch the ATT&CK bundle from any source")


def build(bundle_path, version):
    data = json.loads(pathlib.Path(bundle_path).read_bytes())
    by_stix_id = {o["id"]: o for o in data["objects"] if "id" in o}
    revoked_by = {}
    for obj in data["objects"]:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            src, tgt = by_stix_id.get(obj["source_ref"]), by_stix_id.get(obj["target_ref"])
            if not src or not tgt:
                continue
            sid = next((r["external_id"] for r in src.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            tid = next((r["external_id"] for r in tgt.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if sid and tid:
                revoked_by.setdefault(sid, []).append(tid)
    tactics = sorted({o["name"] for o in data["objects"] if o["type"] == "x-mitre-tactic"})
    techniques = []
    for obj in data["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                techniques.append((ref["external_id"],
                                   [p["phase_name"] for p in obj.get("kill_chain_phases", [])]))
    raw = pathlib.Path(bundle_path).read_bytes()
    # Techniques this repo actually uses: surface upstream revocations instead of
    # silently dropping them, because a dropped tag means a rule cites a dead ID.
    in_use = set()
    for rule in (ROOT / "sigma").rglob("*.yml"):
        for line in rule.read_text(encoding="utf-8").splitlines():
            low = line.strip().lower()
            if low.startswith("- attack.t") or low.startswith("tags: [attack.t"):
                for token in low.replace("[", " ").replace("]", " ").replace(",", " ").split():
                    if token.startswith("attack.t"):
                        in_use.add(token.split(".", 1)[1].upper())
    unknown = [t for t in tactics if t not in SLUG]
    if unknown:
        raise SystemExit(f"unknown tactic names, update SLUG: {unknown}")
    return {
        "attack_version": version,
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "source_ref": f"v{version} (tag) / enterprise-attack/enterprise-attack-{version}.json",
        "pin_date": __import__("datetime").date.today().isoformat(),
        "bundle_path": "attack/cache/" + pathlib.Path(bundle_path).name,
        "bundle_sha256": hashlib.sha256(raw).hexdigest(),
        "bundle_bytes": len(raw),
        "generated_by": "tools/pin_attack_bundle.py",
        "notes": [
            "Technique and tactic lists are generated from the pinned STIX bundle, not hand-written.",
            "Revoked and deprecated techniques are excluded.",
            "The bundle itself is not committed (40 MB); --fetch re-downloads it by tag.",
        ],
        "revoked_in_use": {t: revoked_by.get(t, []) for t in sorted(in_use)
                           if t not in {x for x, _ in techniques}},
        "tactics": ["attack." + SLUG[t] for t in tactics],
        "techniques": sorted({t for t, _ in techniques}),
        # technique -> its kill-chain phases, so a rule's tactics: list can be
        # checked against the pinned bundle instead of an editorial guess.
        "technique_tactics": {t: sorted(set(ph)) for t, ph in techniques},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="14.1")
    ap.add_argument("--bundle", help="use an existing STIX bundle instead of downloading")
    ap.add_argument("--fetch", action="store_true", help="download the bundle by tag first")
    ap.add_argument("--verify", action="store_true", help="verify the cached bundle hash only")
    args = ap.parse_args()

    if args.verify:
        pin = json.loads(PIN.read_text())
        path = ROOT / pin["bundle_path"]
        if not path.is_file():
            print(f"MISSING {path} - run --fetch")
            return 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        ok = digest == pin["bundle_sha256"]
        print(f"{'OK  ' if ok else 'FAIL'} {path.name} {digest}")
        return 0 if ok else 1

    bundle = pathlib.Path(args.bundle) if args.bundle else None
    if bundle is None:
        cached = CACHE / f"enterprise-attack-{args.version}.json"
        bundle = cached if (cached.is_file() and not args.fetch) else fetch(args.version)
    pin = build(bundle, args.version)
    PIN.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")
    print(f"pinned ATT&CK {pin['attack_version']}: {len(pin['techniques'])} techniques, "
          f"{len(pin['tactics'])} tactics, sha256 {pin['bundle_sha256']}")
    dropped = pin.get("revoked_techniques") or {}
    if dropped:
        print(f"note: {len(dropped)} in-use technique(s) revoked upstream: "
              + ", ".join(f"{k}->{v}" for k, v in sorted(dropped.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
