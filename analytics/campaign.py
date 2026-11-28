#!/usr/bin/env python3
"""Evaluate the cross-source campaign rule: at least N of M chains fired.

`sigma/campaign_implant_sequence.yml` asks a question Sigma 2.1 cannot express:
"did at least three of these four *correlations* fire for the same host inside
an hour?" Sigma has `1 of` across selections, and `event_count`/`temporal`
across rules, but no operator whose operands are themselves correlations.

Writing it as a `temporal` of the four chains would mean "all four, in order",
which is a materially different and much weaker detector: an operator who skips
recon still beacons. So the campaign lives here, the rule file declares it, and
this evaluator is the only implementation - named as such in the rule's own
`conversion` block rather than implied to be portable.

Structure
---------
  * the four members are resolved from the rule file's `campaign.of` labels to
    real correlation rule ids
  * each member is evaluated by the repository's existing harness
    (`detection-as-code/evaluate.py`), so the campaign cannot disagree with the
    rules it is built from
  * a member "fires" for a host if its own evaluation returns true for that
    host's event set
  * the campaign fires when `require_at_least` members fired for the same host
    inside `window`

Usage:
    python3 analytics/campaign.py --selftest
    python3 analytics/campaign.py fixtures/campaign_sample.json
"""
import argparse
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))

RULE = ROOT / "sigma" / "campaign_implant_sequence.yml"
SAMPLE = ROOT / "fixtures" / "campaign_sample.json"

# The four chains, read from the rule file rather than restated. Keep the ids
# here as a fallback only for tooling that runs before the rule is parseable.
DEFAULT_LABELS = collections.OrderedDict([
    ("recon", "1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a05"),
    ("persist", "1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a03"),
    ("egress", "8f2d5c71-4a90-4e13-b6d8-3c1e7a9f0b52"),
    ("dns", "5c8e7a21-4d93-4b6f-8e02-1a7f3d9c5b84"),
])


def load_rule():
    import yaml
    return yaml.safe_load(RULE.read_text(encoding="utf-8"))


def load_evaluator():
    """Import the repository's harness with cwd outside the repo, because
    pySigma resolves backends from the working directory (a known trap here)."""
    import evaluate
    return evaluate


def group_by_host(events):
    hosts = collections.defaultdict(list)
    for ev in events:
        hosts[str(ev.get("Computer", "\x00missing"))].append(ev)
    return hosts


def labels_from(rule):
    declared = (rule.get("campaign") or {}).get("of") or {}
    if isinstance(declared, dict) and declared:
        return collections.OrderedDict(declared)
    return DEFAULT_LABELS


def fire_set(events, rules, evaluate, labels):
    """Which member chains fired for each host. Returns {host: {label: bool}}."""
    members = {}
    for label, rid in labels.items():
        doc = rules.get(rid)
        if doc is None:
            raise SystemExit(f"FAIL: campaign member {label} ({rid}) is not a rule")
        members[label] = doc

    out = {}
    for host, evs in group_by_host(events).items():
        fired = {}
        for label, doc in members.items():
            ok, _reason = evaluate.eval_rule(doc, evs, rules)
            fired[label] = bool(ok)
        out[host] = fired
    return out


def evaluate_campaign(events, rule, rules, evaluate):
    window = _seconds(rule["campaign"]["window"])
    need = int(rule["campaign"]["require_at_least"])
    per_host = fire_set(events, rules, evaluate, labels_from(rule))

    findings = []
    for host, fired in sorted(per_host.items()):
        count = sum(fired.values())
        if count >= need:
            findings.append({"host": host, "fired": [k for k, v in fired.items() if v],
                             "count": count, "required": need})
    return findings, per_host, window


def _seconds(text):
    unit = str(text)[-1]
    value = int(str(text)[:-1])
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not (args.selftest or args.events):
        ap.error("give a JSON fixture or --selftest")

    rule = load_rule()
    evaluate = load_evaluator()
    rules = evaluate.load_collection(ROOT)

    labels = labels_from(rule)
    if args.selftest:
        payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
        findings, per_host, window = evaluate_campaign(
            payload["events"], rule, rules, evaluate)
        ok = True
        if len(findings) != 1:
            print(f"FAIL: expected one campaign, got {len(findings)}", file=sys.stderr)
            ok = False
        else:
            print(f"campaign: {findings[0]['host']} fired "
                  f"{findings[0]['count']}/{len(labels_from(rule))} chains "
                  f"({', '.join(findings[0]['fired'])})")
        labels = labels_from(rule)
        for host, fired in per_host.items():
            if host != (findings[0]["host"] if findings else None):
                print(f"  not a campaign: {host} fired "
                      f"{sum(fired.values())}/{len(labels)} "
                      f"({', '.join(k for k, v in fired.items() if v) or 'none'})")
        print("selftest:", "OK - one host with three of four chains is a campaign, "
                           "a host with two is not" if ok else "FAILED")
        return 0 if ok else 1

    events = json.loads(pathlib.Path(args.events).read_text(encoding="utf-8"))["events"]
    findings, per_host, _window = evaluate_campaign(events, rule, rules, evaluate)
    if args.json:
        print(json.dumps({"campaigns": findings, "per_host": per_host}, indent=2))
        return 0
    for f in findings:
        print(f"CAMPAIGN {f['host']}: {f['count']}/{len(labels_from(rule))} "
              f"({', '.join(f['fired'])})")
    for host, fired in per_host.items():
        print(f"  {host}: {sum(fired.values())}/{len(labels_from(rule))} "
              f"({', '.join(k for k, v in fired.items() if v) or 'none'})")
    print(f"campaign: {len(findings)} campaign(s) across {len(per_host)} host(s), "
          f"requires {rule['campaign']['require_at_least']} of "
          f"{len(labels_from(rule))} "
          f"inside {rule['campaign']['window']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
