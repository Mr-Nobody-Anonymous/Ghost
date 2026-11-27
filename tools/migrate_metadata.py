#!/usr/bin/env python3
"""Add operational metadata fields to every rule. Safe to re-run."""
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("FAIL: PyYAML required\n")
    raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULTS = {
    "sigma_spec_version": '"2.1.0"',
    "dedup_window": '"5m"',
    "min_eval_interval": '"10s"',
    "min_os": '"Windows 10 21H2"',
    "sysmon_min_version": "13",
}
CORRELATION_WINDOWS = {
    "beaconing_frequency.yml": '"60s"',
    "patch_sequence.yml": '"5s"',
}


def main():
    count = 0
    for f in sorted((ROOT / "sigma").rglob("*.yml")):
        lines = f.read_text(encoding="utf-8").splitlines()
        text = "\n".join(lines)
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            continue
        additions = []
        for key, default in DEFAULTS.items():
            if key in doc:
                continue
            if key == "min_eval_interval" and f.name in CORRELATION_WINDOWS:
                default = CORRELATION_WINDOWS[f.name]
            additions.append(f"{key}: {default}")
        if additions:
            # insert after the date line
            for i, line in enumerate(lines):
                if line.startswith("date:"):
                    lines[i + 1:i + 1] = additions
                    break
            f.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        count += 1
    print(f"metadata present on {count} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
