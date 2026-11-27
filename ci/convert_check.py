#!/usr/bin/env python3
"""Backend conversion gate.

Loads the whole Sigma collection (not one file at a time) so correlation rules
can resolve referenced IDs, and REQUIRES every declared backend to be present.
A missing backend fails the gate rather than being silently skipped.
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
CLASSES = {"splunk": "SplunkBackend", "kql": "KqlBackend"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backends", nargs="+", default=["splunk", "kql"])
    args = ap.parse_args()

    if SigmaCollection is None:
        print("FAIL: pySigma is not installed - conversion cannot be proven")
        return 1

    backends = []
    for name in args.backends:
        module = BACKENDS.get(name)
        if not module:
            print(f"FAIL: unknown backend {name}")
            return 1
        try:
            mod = __import__(module, fromlist=[CLASSES[name]])
        except ImportError:
            print(f"FAIL: backend {name} not installed ({module}) - partial availability is not a pass")
            return 1
        cls = getattr(mod, CLASSES[name], None)
        if cls is None:
            print(f"FAIL: backend {name} class {CLASSES[name]} missing")
            return 1
        backends.append((name, cls))

    files = sorted((ROOT / "sigma").rglob("*.yml"))
    combined = "\n---\n".join(f.read_text(encoding="utf-8") for f in files)
    try:
        collection = SigmaCollection.from_yaml(combined)
    except Exception as exc:
        print(f"FAIL: collection load error: {type(exc).__name__}: {exc}")
        return 1

    failed = 0
    total = 0
    for name, cls in backends:
        for rule in collection.rules:
            total += 1
            try:
                result = cls().convert(SigmaCollection(rules=[rule]))
                if not result:
                    print(f"FAIL {getattr(rule, 'id', '?')} [{name}]: empty conversion")
                    failed += 1
            except Exception as exc:
                print(f"FAIL {getattr(rule, 'id', '?')} [{name}]: {type(exc).__name__}: {exc}")
                failed += 1
    print(f"conversion: {total - failed}/{total} rule/backend combinations passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
