#!/usr/bin/env python3
"""Backend conversion gate.

Proves each Sigma rule converts to the declared target backends. Without
working backends this test FAILS - an unconverted rule is shelfware, not a
passing rule.
"""
import argparse
import pathlib
import sys

try:
    from sigma.collection import SigmaCollection
except ImportError:
    SigmaCollection = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
BACKENDS = {
    "splunk": "sigma.backends.splunk",
    "kql": "sigma.backends.kql",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backends", nargs="+", default=["splunk", "kql"])
    args = ap.parse_args()

    if SigmaCollection is None:
        print("FAIL: pySigma is not installed - conversion cannot be proven")
        return 1

    available = []
    for name in args.backends:
        module = BACKENDS.get(name)
        if not module:
            print(f"FAIL: unknown backend {name}")
            return 1
        try:
            mod = __import__(module, fromlist=["SplunkBackend", "KqlBackend"])
        except ImportError:
            print(f"FAIL: backend {name} not installed ({module})")
            continue
        available.append((name, mod))

    if not available:
        return 1

    rules = sorted((ROOT / "sigma").rglob("*.yml"))
    failed = 0
    for f in rules:
        for name, mod in available:
            cls = getattr(mod, "SplunkBackend" if name == "splunk" else "KqlBackend", None)
            if cls is None:
                print(f"FAIL {f.name} [{name}]: backend class missing")
                failed += 1
                continue
            try:
                collection = SigmaCollection.from_yaml(f.read_text(encoding="utf-8"))
                result = cls().convert(collection)
                if not result:
                    print(f"FAIL {f.name} [{name}]: empty conversion")
                    failed += 1
            except Exception as exc:
                print(f"FAIL {f.name} [{name}]: {type(exc).__name__}: {exc}")
                failed += 1

    print(f"conversion: {len(rules) * len(available) - failed}/{len(rules) * len(available)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
