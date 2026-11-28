#!/usr/bin/env python3
"""Offline test suite: schema, fixtures, telemetry/response/metrics contracts.

These tests assert structure and field values. They do NOT prove detection on
real telemetry; that requires an independent blind capture from a pinned sample.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import unittest

try:
    import yaml
except ImportError:
    raise SystemExit("FAIL: PyYAML is required - validation must not fail open")

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection-as-code"))
import evaluate

RULES = sorted((ROOT / "sigma").rglob("*.yml"))


def load(f):
    return yaml.safe_load(f.read_text(encoding="utf-8"))


class RuleTests(unittest.TestCase):
    def test_rules_exist(self):
        self.assertGreaterEqual(len(RULES), 31, "rule corpus shrank")

    def test_unique_ids(self):
        ids = []
        for f in RULES:
            doc = load(f)
            self.assertIsInstance(doc, dict, f"{f.name} did not parse")
            self.assertIn("id", doc, f"{f.name} has no id")
            ids.append(doc["id"])
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule id")
        # A correlation rule may not share an id with its member rule, or
        # pySigma resolves the correlation to itself and conversion fails.
        for f in RULES:
            doc = load(f)
            if "correlation" in doc:
                self.assertNotIn(doc["id"], doc["correlation"]["rules"],
                                 f"{f.name}: correlation lists its own id as a member")

    def test_schema_validator_passes(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "detection-as-code" / "validate_rules.py")],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_sigma_status_not_repo_lifecycle(self):
        """`status` is parsed by pySigma; a repo-only value stops conversion."""
        allowed = {"stable", "test", "experimental", "deprecated", "unsupported"}
        for f in RULES:
            doc = load(f)
            if doc:
                self.assertIn(doc.get("status"), allowed, f"{f.name}: non-Sigma status")
                self.assertIn(doc.get("lifecycle"),
                              {"designed", "captured", "validated", "deployed",
                               "stale", "deprecated"},
                              f"{f.name}: lifecycle must use the repo vocabulary")

    def test_tactics_match_the_pinned_technique_mapping(self):
        """A rule's tactics: list must be reachable from its own technique.

        ATT&CK v20 revoked T1562 and split Defense Evasion into Stealth and
        Defense Impairment. Every rule tagged T1562.001 was citing a dead ID and
        a tactic that no longer exists, and nothing caught it: each value was
        individually valid. The pin now carries technique -> kill-chain phases,
        generated from the bundle, so the pair is checkable offline.
        """
        pin = json.loads((ROOT / "attack" / "attack-bundle-pin.json").read_text())
        mapping, techniques = pin.get("technique_tactics") or {}, set(pin.get("techniques", []))
        self.assertTrue(mapping, "pin has no technique_tactics - regenerate it")
        for f in RULES:
            d = load(f)
            if not d:
                continue
            tags = d.get("tags", []) or []
            techs = [x.split(".", 1)[1].upper() for x in tags
                     if str(x).lower().startswith("attack.t")]
            for tech in techs:
                self.assertIn(tech, techniques,
                              f"{f.name}: {tech} is revoked or absent in the pinned bundle")
            expected = {f"attack.{ph}" for tech in techs for ph in mapping.get(tech, [])}
            stray = set(d.get("tactics", []) or []) - expected
            self.assertFalse(stray, f"{f.name}: tactics {sorted(stray)} unreachable from {techs}")
            self.assertEqual(set(d.get("tactics", []) or []), expected,
                             f"{f.name}: tactics should be exactly {sorted(expected)}")

    def test_deploy_bundle_carries_suppression(self):
        """A bundle of 37 queries with no dedup policy is 37 alert floods.

        Every rule declares dedup_key / dedup_window / min_eval_interval and
        nothing consumed them: pySigma emits the search and the suppression is a
        saved-search setting, so the values have to travel in the manifest or
        they do not exist operationally.
        """
        conv = ROOT / "attack" / "conversion.json"
        if not conv.is_file():
            self.skipTest("no conversion results")
        out = ROOT / "dist" / "suppress-test.spl"
        man = ROOT / "dist" / "suppress-test.json"
        out.parent.mkdir(exist_ok=True)
        r = subprocess.run(
            [sys.executable, str(ROOT / "deploy" / "build_bundle.py"),
             "--backend", "splunk", "--out", str(out), "--manifest", str(man)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        data = json.loads(man.read_text())
        self.assertTrue(data["deployable"])
        for row in data["deployable"]:
            note = row.get("dedup_note") or {}
            self.assertTrue(note.get("suppress_fields"), f"{row['path']} has no fields")
            self.assertTrue(note.get("suppress_period"), f"{row['path']} has no window")
            self.assertFalse(note.get("unknown_tokens"),
                             f"{row['path']}: unmapped dedup tokens {note['unknown_tokens']}")
            self.assertIn("alert.suppress", note.get("splunk_savedsearch", ""))
        out.unlink()
        man.unlink()

    def test_deploy_bundle_refuses_stale_conversion(self):
        """A bundle built from results that predate a rule edit ships an unproven query.

        The first version of this check compared the stored conversion stamp with
        itself, so it could never fail. Prove it fails on an edit.
        """
        conv = ROOT / "attack" / "conversion.json"
        if not conv.is_file():
            self.skipTest("no conversion results; run ci/convert_check.py")
        target = ROOT / "sigma" / "beacon_custom_headers.yml"
        original = target.read_bytes()
        out = ROOT / "dist" / "stale-test.spl"
        out.parent.mkdir(exist_ok=True)
        try:
            target.write_bytes(original + b"\n# touched after conversion\n")
            r = subprocess.run(
                [sys.executable, str(ROOT / "deploy" / "build_bundle.py"),
                 "--backend", "splunk", "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("does not match the rules on disk", r.stdout)
        finally:
            target.write_bytes(original)
        if out.exists():
            out.unlink()

    def test_navigator_layer_is_current_and_honest(self):
        """The layer scores evidence, not rule count.

        Every fixture is `designed`, so every score must be 1. A layer showing
        green would be the repository's own central false claim, rendered as a
        heat map.
        """
        out = ROOT / "attack" / "navigator-layer.json"
        self.assertTrue(out.is_file(), "run tools/export_navigator.py")
        before = out.read_text()
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "export_navigator.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        layer = json.loads(out.read_text())
        self.assertEqual(before, out.read_text(), "navigator layer is stale")
        scores = {t["score"] for t in layer["techniques"]}
        self.assertEqual(scores, {1},
                         f"with no captured fixture every score must be 1, got {scores}")
        self.assertTrue(layer["techniques"])
        for t in layer["techniques"]:
            self.assertRegex(t["techniqueID"], r"^T\d{4}(\.\d{3})?$")

    def test_matrix_is_current(self):
        """attack/matrix.md is generated; a stale copy is a coverage claim nobody re-checked."""
        before = (ROOT / "attack" / "matrix.md").read_text()
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "generate_matrix.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        after = (ROOT / "attack" / "matrix.md").read_text()
        self.assertEqual(before, after,
                         "attack/matrix.md is stale - run tools/generate_matrix.py")

    def test_tactics_not_in_tags(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            for t in d.get("tags", []) or []:
                self.assertRegex(str(t), r"^attack\.t\d{4}", f"{f.name}: {t} in tags")

    def test_regex_selections_are_anchored(self):
        """An unanchored path regex matches any substring and is almost always a bug.

        `TargetFilename|re: 'exe$'` matches everything; `^[D-Z]:\\...$` is a
        deliberate volume test. Requiring an anchor makes the intent explicit.
        """
        for f in RULES:
            doc = load(f)
            if not doc:
                continue
            for name, body in (doc.get("detection") or {}).items():
                if not isinstance(body, dict):
                    continue
                for key, value in body.items():
                    if "|re" not in key:
                        continue
                    for pattern in (value if isinstance(value, list) else [value]):
                        self.assertRegex(
                            str(pattern), r"^(\^\(\?i\)|\^\(\?i:|\^|^\(\?i\))",
                            f"{f.name}: {key} pattern {pattern!r} is not anchored with ^")

    def test_no_double_escaped_paths(self):
        """`'\\\\autorun.inf'` is a YAML literal yielding a real backslash; two
        real backslashes never occur in a Windows path, so it is always a bug."""
        offenders = []
        for f in RULES:
            doc = load(f) or {}
            stack = [doc.get("detection", {}), doc.get("correlation", {})]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    stack.extend((k, v) for k, v in node.items())
                elif isinstance(node, list):
                    stack.extend(node)
                elif isinstance(node, tuple):
                    key, node = node
                    if isinstance(node, str):
                        # A `|re` value is a regex: there, `\\` is how you match
                        # one literal backslash in a Windows path, so two
                        # backslashes are correct and required. Outside a regex
                        # they are always a bug.
                        if "|re" in str(key) or str(key).endswith("|re"):
                            continue
                        if "\\\\" in node:
                            offenders.append(f"{f.name}: {node!r}")
                elif isinstance(node, str) and "\\\\" in node:
                    offenders.append(f"{f.name}: {node!r}")
        self.assertEqual(offenders, [], "double-escaped path literal(s) found")

    def test_filter_sections_can_actually_exclude_something(self):
        """A filter that excludes no reachable event is dead tuning.

        `beacon_interval_shift.yml` selected `destination_port: 443` and filtered
        `destination_port: [80, 8080, 8443]`. Nothing is both, so the filter was
        unreachable while the rule looked tuned - the same class of defect as a
        test that cannot fail.

        Probes are derived from the rule's own positive event rather than written
        by hand, so a path-shaped field is exercised with a real path instead of
        a fabricated string.
        """
        offenders = []
        for f in RULES:
            doc = load(f) or {}
            det = doc.get("detection") or {}
            if not det or "correlation" in doc:
                continue
            sels = {k: v for k, v in det.items()
                    if k != "condition" and not k.startswith("filter") and isinstance(v, dict)}
            filts = {k: v for k, v in det.items()
                     if k.startswith("filter") and isinstance(v, dict)}
            if not filts or not sels:
                continue
            base = evaluate.candidate_events({**doc, "detection": sels})
            if not base:
                continue
            event = base[0]
            sel_fields = {k.split("|")[0] for body in sels.values() for k in body}
            filt_fields = {k.split("|")[0] for body in filts.values() for k in body}
            shared = sel_fields & filt_fields
            # A filter on a field no selection constrains is a context filter
            # (destination reputation, host allowlist) and is out of scope.
            if not shared:
                continue

            # If the selection constrains a field with a regex, a probe for that
            # field has to satisfy the regex too; render one from the pattern.
            from fieldtypes import render_regex
            re_values = {}
            for body in sels.values():
                for k, v in body.items():
                    if k.endswith("|re") and isinstance(v, str):
                        re_values[k.split("|")[0]] = render_regex(v)

            def probes_for(field, fkey, fval, _re=re_values, _ev=event):
                # Defaults bind the loop variables: a closure over a loop
                # variable is the classic late-binding bug (ruff B023), and in a
                # test it produces a pass or fail that depends on the last rule.
                pos = _re.get(field) or str(_ev.get(field, ""))
                mods = fkey.split("|")[1:]
                v = str(fval)
                if "contains" in mods:
                    # prepend, so the selection's own endswith still holds
                    return [v + pos, v + pos.lstrip("C:")]
                if "endswith" in mods:
                    stem = pos.rsplit("\\", 1)[0] if "\\" in pos else ""
                    return [stem + "\\" + v.lstrip("\\"), v]
                if "startswith" in mods:
                    return [v + "artifact.exe", v]
                return [v]

            reachable = False
            for field in sorted(shared):
                for fbody in filts.values():
                    for fkey, fvalue in fbody.items():
                        if fkey.split("|")[0] != field:
                            continue
                        for fv in (fvalue if isinstance(fvalue, list) else [fvalue]):
                            for cand in probes_for(field, fkey, fv):
                                probe = dict(event, **{field: cand})
                                if not evaluate.match_selection(probe, fbody):
                                    continue
                                if any(evaluate.match_selection(probe, sb) for sb in sels.values()):
                                    reachable = True
                                    break
                            if reachable:
                                break
                        if reachable:
                            break
                    if reachable:
                        break
                if reachable:
                    break
            if not reachable:
                offenders.append(f"{f.name} ({sorted(shared)})")
        self.assertEqual(offenders, [],
                         f"filter(s) that can never exclude a selected event: {offenders}")

    def test_correlation_join_keys_exist_in_members(self):
        """Every group-by field must be selectable from each member rule."""
        collection = evaluate.load_collection(ROOT)
        for f in RULES:
            doc = load(f)
            if not doc or "correlation" not in doc:
                continue
            for key, missing in evaluate._join_values(doc, collection).items():
                self.assertEqual(missing, [],
                                 f"{f.name}: group-by field {key} is not in member detection(s)")

    def test_correlation_types_are_sigma_21(self):
        allowed = {"event_count", "value_count", "temporal", "temporal_ordered",
                   "value_sum", "value_avg", "value_percentile", "value_median"}
        for f in RULES:
            doc = load(f)
            if not doc or "correlation" not in doc:
                continue
            self.assertIn(doc["correlation"].get("type"), allowed,
                          f"{f.name}: {doc['correlation'].get('type')} is not a Sigma 2.1 type")
            self.assertNotIn("|", json.dumps(doc.get("detection", {})),
                             f"{f.name}: deprecated pipe aggregation in a detection condition")

    def test_conversion_claim_is_declared_and_valid(self):
        for f in RULES:
            doc = load(f)
            if not doc:
                continue
            conv = doc.get("conversion")
            self.assertIsInstance(conv, dict, f"{f.name}: no conversion block")
            for backend in ("splunk", "elastic", "kusto"):
                self.assertIn(conv.get(backend), ("supported", "unsupported"),
                              f"{f.name}: conversion.{backend} invalid")

    def test_yara_matching_logic(self):
        """Compiling is not matching. Assert the intended shapes fire and that
        partial indicators stay quiet - the rule previously required two of three
        unrelated strings, so the canonical AMSI patch (patch bytes + the symbol
        it overwrites) did not match at all."""
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python not installed")
        r = yara.compile(filepath=str(ROOT / "yara" / "ghost_implant_structural.yar"))
        pe = b"MZ" + b"\x00" * 100
        must_hit = {
            "AMSI patch bytes + symbol": pe + b"AmsiScanBuffer" + bytes.fromhex("B857 0007 80C3"),
            "ETW patch bytes + symbol": pe + b"EtwEventWrite" + bytes.fromhex("33C0C3"),
            "header pair + _MEI": pe + b"X-Id" + b"X-Seq" + b"_MEI",
            "spreader filenames": pe + b"svc_update.exe" + b"autorun.inf",
            "DGA seed + PSK + amsi": pe + b"DGA_SEED" + b"PSK" + b"AmsiScanBuffer",
        }
        must_miss = {
            "one evasion symbol alone": pe + b"AmsiScanBuffer",
            "one C2 header alone": pe + b"X-Id",
            "non-PE carrying everything": b"NOTPE" + b"AmsiScanBuffer" + b"EtwEventWrite"
                                          + bytes.fromhex("33C0C3"),
        }
        for name, data in must_hit.items():
            self.assertTrue(r.match(data=data), f"YARA missed: {name}")
        for name, data in must_miss.items():
            self.assertFalse(r.match(data=data), f"YARA false positive: {name}")

    def test_yara_compiles(self):
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python not installed")
        for f in (ROOT / "yara").rglob("*.yar"):
            try:
                yara.compile(filepath=str(f))
            except Exception as exc:
                self.fail(f"{f.name}: {exc}")


class FixtureTests(unittest.TestCase):
    def test_positive_fixture_per_rule(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            rid = d.get("id")
            fx = ROOT / "fixtures" / "per_rule" / (rid + ".json")
            with self.subTest(rule=rid):
                self.assertTrue(fx.exists(), f"missing positive fixture for {rid}")
                data = json.loads(fx.read_text(encoding="utf-8"))
                self.assertTrue(data["events"], "no concrete events")
                self.assertTrue(data["assert_fields"], "no field assertions")
                self.assertEqual(data["rule_id"], rid)
                self.assertEqual(data["status"], "designed")

    def test_negative_fixture_per_rule(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            rid = d.get("id")
            nf = ROOT / "fixtures" / "negative" / (rid + ".json")
            with self.subTest(rule=rid):
                self.assertTrue(nf.exists(), f"missing negative fixture for {rid}")
                data = json.loads(nf.read_text(encoding="utf-8"))
                self.assertEqual(data["rule_id"], rid)
                self.assertTrue(data["must_not_match"]["events"], "no concrete negative event")
                self.assertTrue(data["benign_lookalikes"])

    def test_fixtures_are_current(self):
        """A fixture that no longer matches its rule is stale, not passing."""
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "generate_fixtures.py"), "--check"],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])

    def test_assert_fields_are_on_the_matched_event(self):
        """Every asserted field must exist on an event the rule actually matches.

        Asserting a field that only appears in a different OR-branch of the rule
        is not a true-positive proof: it is a field the alert would never carry.
        """
        collection = evaluate.load_collection(ROOT)
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            doc = collection[data["rule_id"]]
            with self.subTest(rule=data["rule_id"]):
                if "campaign" in doc:
                    # A campaign produces no matched *event* - it is a verdict
                    # over chains. analytics/campaign.py asserts that verdict
                    # against the same fixture; there is nothing to check here.
                    continue
                matched = evaluate.eval_rule(doc, data["events"], collection)
                self.assertTrue(matched[0], matched[1])
                if "correlation" in doc:
                    continue
                hits = [ev for ev in data["events"] if evaluate.eval_detection(doc, ev)]
                present = set()
                for ev in hits:
                    present.update(ev.keys())
                missing = set(data["assert_fields"]) - present
                self.assertFalse(missing, f"assert_fields not on matching event: {missing}")

    def test_fixture_values_are_not_constraint_literals(self):
        """A fixture is telemetry, not a copy of the rule's constraint values.

        `Source|exists: true` was rendered as `Source: true` because the field
        renderer never handled the `exists` modifier and fell through to the
        literal. No host emits a boolean for a DNS origin.
        """
        for f in sorted((ROOT / "fixtures" / "per_rule").glob("*.json")):
            doc = json.loads(f.read_text())
            for ev in doc.get("events") or []:
                for field, value in ev.items():
                    if field.startswith("_") or field == "CertificateSelfSigned":
                        continue
                    self.assertNotIsInstance(
                        value, bool,
                        f"{f.name}: {field} is the boolean {value} - a constraint "
                        f"literal leaked into the fixture")

    def test_fixture_paths_and_path_like_values(self):
        """No fixture may contain a value no Windows host could emit."""
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            for ev in data["events"]:
                for key, value in ev.items():
                    if key.startswith("_"):
                        continue
                    if key in ("TargetObject", "ObjectName", "RegistryKey"):
                        self.assertFalse(str(value).startswith("C:\\"),
                                         f"{f.name}: registry key rendered as a path: {value}")
                    if key in ("Image", "TargetFilename", "ParentImage") and value:
                        self.assertTrue(
                            (len(str(value)) > 2 and str(value)[1] == ":" and str(value)[2] == "\\")
                            or str(value).startswith("\\\\") or "_MEI" in str(value),
                            f"{f.name}: {key}={value!r} is not a Windows path")
                        self.assertNotRegex(str(value).lower(), r"\.(bmp|db|enc|zip)/",
                                            f"{f.name}: extension used as a directory")

    def test_per_rule_status_never_claims_capture(self):
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("status") == "captured":
                self.assertNotEqual(data.get("sample_ref"), "PIN-0000",
                                    f"{f.name}: captured fixture needs a real pin")


class ContractTests(unittest.TestCase):
    def test_response_step_per_rule(self):
        for f in RULES:
            d = load(f)
            if not d:
                continue
            p = ROOT / "response" / "rules" / (d["id"] + ".md")
            self.assertTrue(p.exists(), f"no triage step for {d['id']}")
            self.assertIn("Severity:", p.read_text(encoding="utf-8"))

    def test_metrics_ceiling_per_rule(self):
        ceilings = json.loads((ROOT / "metrics" / "ceilings.json").read_text(encoding="utf-8"))
        for f in RULES:
            d = load(f)
            if not d:
                continue
            self.assertIn(d["id"], ceilings, f"no volume ceiling for {d['id']}")
            self.assertGreater(ceilings[d["id"]]["events_per_day_ceiling"], 0)

    def test_capture_never_claims_captured_without_a_match(self):
        """A capture the rule does not fire on is a finding, not a fixture.

        The old converter wrote status: captured unconditionally, so a mismatch
        between rule and telemetry silently became "evidence".
        """
        xml = (ROOT / "tests" / "data" / "sample_capture.xml")
        self.assertTrue(xml.is_file(), "missing synthetic capture fixture")
        rule_id = "1a2b3c4d-5e6f-4708-9a0b-1c2d3e4f5a05"  # WMI triple - cannot match a process create
        out = ROOT / "dist" / "test-capture.json"
        out.parent.mkdir(exist_ok=True)
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "evtx_to_fixture.py"),
             "--input", str(xml), "--rule-id", rule_id, "--output", str(out)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(out.exists(), "a failed match must not write a fixture")

    def test_capture_keeps_the_correlation_join_key(self):
        xml = ROOT / "tests" / "data" / "sample_capture.xml"
        out = ROOT / "dist" / "test-capture-ok.json"
        out.parent.mkdir(exist_ok=True)
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "evtx_to_fixture.py"),
             "--input", str(xml), "--rule-id", "5e1c0f27-3a64-4b18-9d75-0c2f8a41b6e3",
             "--output", str(out), "--sample-ref", "PIN-0000"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        fx = json.loads(out.read_text())
        self.assertEqual(fx["status"], "captured")
        self.assertEqual(fx["events"][0]["Computer"], "LAB-WS01",
                         "Computer is a correlation join key and must survive capture")
        self.assertEqual(fx["events"][0]["SubjectUserSid"], "<masked>")
        out.unlink()

    def test_baseline_verifier_reports_unmatched_rules(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_baseline.py"),
             "--input", str(ROOT / "tests" / "data" / "sample_capture.xml")],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, "a 1-event baseline must not pass as complete")
        self.assertIn("have their EventIDs and fields in this capture", r.stdout)

    def test_docs_do_not_cite_missing_rules_or_links(self):
        """Documentation drifts silently; nothing used to check it.

        77 Markdown files name 38 rules, and a renamed rule leaves a citation
        that reads as fact. Links and rule filenames are both checked.
        """
        rules = {p.name for p in (ROOT / "sigma").rglob("*.yml")}
        broken_links, missing_rules = [], []
        for md in ROOT.rglob("*.md"):
            if ".git" in md.parts:
                continue
            text = md.read_text(encoding="utf-8")
            for link in re.findall(r"\]\(([^)#\s]+)\)", text):
                if link.startswith(("http", "mailto", "#")):
                    continue
                if not (md.parent / link).exists() and not (ROOT / link).exists():
                    broken_links.append(f"{md.relative_to(ROOT)}: {link}")
            if md.name == "CHANGELOG.md":
                continue
            for _, name in re.findall(r"`([\w./-]*?([a-z0-9_]+\.yml))`", text):
                if name not in rules:
                    missing_rules.append(f"{md.relative_to(ROOT)}: {name}")
        self.assertEqual(broken_links, [], f"broken relative links: {broken_links}")
        self.assertEqual(missing_rules, [], f"citations of rules that do not exist: {missing_rules}")

    def test_baseline_config_drift(self):
        manifest = json.loads((ROOT / "baseline" / "manifest.json").read_text(encoding="utf-8"))
        for key, path in (
            ("sysmon_config_sha256", ROOT / "telemetry" / "sysmon-config.xml"),
            ("auditpol_doc_sha256", ROOT / "telemetry" / "auditpol.md"),
        ):
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(manifest[key], actual,
                             f"{path.name} changed without a baseline re-pin")
        # A missing golden capture is recorded as a coverage gap in docs/maturity.md,
        # not silently treated as a pass.

    def test_level_distribution(self):
        counts = {}
        for f in RULES:
            d = load(f)
            if d:
                counts[d.get("level")] = counts.get(d.get("level"), 0) + 1
        self.assertLessEqual(counts.get("high", 0), len(RULES) // 2,
                             "too many high-severity rules - no triage priority")
        self.assertGreaterEqual(len(counts), 2, "all rules have the same severity")

    def test_sample_ref_resolves(self):
        pins = (ROOT / "samples" / "PINS.md").read_text(encoding="utf-8")
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            fx = json.loads(f.read_text(encoding="utf-8"))
            ref = fx.get("sample_ref", "")
            self.assertTrue(ref, f"{f.name}: no sample_ref")
            self.assertIn(ref, pins, f"{f.name}: sample_ref {ref} not in PINS.md")

    def test_status_state_machine(self):
        allowed = {"designed", "captured", "validated", "deployed", "stale", "deprecated"}
        for f in (ROOT / "fixtures" / "per_rule").glob("*.json"):
            fx = json.loads(f.read_text(encoding="utf-8"))
            self.assertIn(fx.get("status"), allowed, f"{f.name}: bad status")
        for f in RULES:
            d = load(f)
            if d:
                self.assertIn(d.get("lifecycle"), allowed, f"{f.name}: bad lifecycle")

    def test_min_eval_interval_present(self):
        for f in RULES:
            d = load(f)
            if d:
                self.assertTrue(d.get("min_eval_interval"), f"{f.name}: no min_eval_interval")
                self.assertTrue(d.get("dedup_window"), f"{f.name}: no dedup_window")


if __name__ == "__main__":
    unittest.main(verbosity=2)
