"""Documents state a stage count; the gate script is the only authority.

README said "10 stages" and `docs/test-contract.md` said the same, long after
the gate had grown to 20. Nobody changed the number because changing the gate
does not touch the prose - the two were only ever connected by memory. A reader
who trusts the count is one step from concluding the gate checks less than it
does, which is the failure mode this repository is built to avoid.

So: read the count out of `ci/gate.sh` itself and require every document that
states one to agree. Nothing here knows that 20 is right; it knows that 20 is
what the script does.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "ci" / "gate.sh"

# Documents that describe the gate to a reader. A new one joins this list when
# it starts making the claim, not before.
DOCS = ["README.md", "docs/test-contract.md", "docs/assessment.md",
        "docs/deployment.md", "docs/maturity.md", "CONTRIBUTING.md"]


def stages_run():
    """The number of numbered stages `ci/gate.sh` actually executes.

    Stage banners look like `[7b/20]` - the denominator is the total, and the
    sub-stages (`2b`, `7b`) are inserted between numbered ones without
    renumbering, so the denominator is the only count worth reading.
    """
    text = GATE.read_text(encoding="utf-8")
    denominators = {int(n) for n in re.findall(r"^echo \"\[\d+[a-z]?/(\d+)\]",
                                               text, re.M)}
    assert len(denominators) == 1, f"gate banners disagree: {denominators}"
    return denominators.pop()


class StageCountTest(unittest.TestCase):
    def test_the_gate_banner_denominator_is_consistent(self):
        total = stages_run()
        self.assertGreater(total, 0)
        # Every `[N/total]` should have a distinct N (plus letter), or two
        # stages silently share a slot and one is never announced.
        text = GATE.read_text(encoding="utf-8")
        labels = re.findall(r"^echo \"\[(\d+[a-z]?)/\d+\]", text, re.M)
        self.assertEqual(len(labels), len(set(labels)),
                         f"duplicate stage numbers in ci/gate.sh: {labels}")

    def test_no_document_disagrees_with_the_gate(self):
        total = stages_run()
        wrong = []
        for name in DOCS:
            path = ROOT / name
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"(\d+)-stage\b|\b(\d+)\s+stages\b", text):
                claimed = int(match.group(1) or match.group(2))
                # "the 20 stages" and "20-stage gate" both assert the total.
                if claimed != total:
                    wrong.append(f"{name}: says {claimed} stages, gate has "
                                 f"{total} ({match.group(0)!r})")
        self.assertEqual(wrong, [], "\n".join(wrong))

    def test_the_readme_lists_a_stage_for_every_slot(self):
        """The Quick start comment names what each stage does.

        When the list was written by hand for 10 stages and the gate grew, the
        comment kept describing the old gate. It does not have to be prose, but
        it does have to cover every slot.
        """
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        block = re.search(r"bash ci/gate\.sh\s+# 20 stages: (.*?)\n```",
                          text, re.S)
        self.assertIsNotNone(block, "README no longer summarises the gate")
        named = [s.strip() for s in block.group(1).replace("#", "").split(",")
                 if s.strip()]
        self.assertGreaterEqual(len(named), stages_run() - 2,
                                f"README names {len(named)} of the "
                                f"{stages_run()} stages")


if __name__ == "__main__":
    unittest.main()
