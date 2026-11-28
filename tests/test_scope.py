#!/usr/bin/env python3
"""Enforce the repository's central claim: this is defensive content only.

SCOPE.md says there is no dropper, no C2 client, no evasion patching, no
credential collector. That claim is the reason the repository is publishable,
and nothing checked it - a single commit could have made it false while every
other test stayed green.

These tests are deliberately blunt. They do not try to detect "malice"; they
assert that the APIs an implant needs are absent from code that is meant to be
inert, and that anything which does import one is on a reviewed allowlist with a
stated reason.
"""
import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Capability-bearing APIs. A detection repository has no reason to call these.
FORBIDDEN_CALLS = {
    "VirtualAlloc", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "QueueUserAPC", "NtUnmapViewOfSection",
    "SetWindowsHookEx", "GetAsyncKeyState", "BitBlt", "CreateDCW",
    "CryptUnprotectData", "BCryptDecrypt", "CryptStringToBinary",
    "WinHttpOpen", "InternetOpenW", "URLDownloadToFileW", "ShellExecuteW",
    "RegSetValueExW", "CreateServiceW", "ChangeServiceConfigW",
}

FORBIDDEN_MODULES = {"ctypes", "winreg", "_winapi", "pywin32", "win32api", "win32con"}

# Files allowed to mention a forbidden name, and why. Empty is the goal; an
# entry here must name the concrete reason it is safe (string, not call).
ALLOWLIST = {
    # Detection rules and fixtures legitimately *name* the APIs they detect.
    "sigma/", "fixtures/", "yara/", "analysis/", "docs/", "telemetry/",
    "network/", "response/", "attack/",
}


def python_files():
    for f in ROOT.rglob("*.py"):
        if ".git" in f.parts or "dist" in f.parts:
            continue
        # tests/test_lab_guide.py declares the forbidden names as a list of
        # strings and asserts they are ABSENT from the guide. That is the
        # opposite of a call, but a name in a list is still a Name node, which
        # a blunt detector reads as a use. This checker is about capability,
        # not vocabulary: skip the two files whose job is to name things.
        if f.name in {"test_scope.py", "test_lab_guide.py"}:
            continue
        yield f


def rel(f):
    return f.relative_to(ROOT).as_posix()


class ScopeTests(unittest.TestCase):
    def test_no_capability_bearing_imports(self):
        offenders = []
        for f in python_files():
            try:
                tree = ast.parse(f.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                for name in names:
                    if name in FORBIDDEN_MODULES:
                        offenders.append(f"{rel(f)}: imports {name}")
        self.assertEqual(offenders, [], f"offensive-capability imports: {offenders}")

    def test_no_capability_bearing_calls(self):
        offenders = []
        for f in python_files():
            if any(str(f.relative_to(ROOT)).startswith(a) for a in ALLOWLIST):
                continue
            text = f.read_text(encoding="utf-8")
            for name in FORBIDDEN_CALLS:
                # a call, not a mention in a string or comment
                if re.search(rf"\b{name}\s*\(", text):
                    offenders.append(f"{rel(f)}: calls {name}()")
        self.assertEqual(offenders, [], f"capability calls outside the allowlist: {offenders}")

    def test_emulator_stays_on_loopback(self):
        """The inert beacon may only ever connect to a loopback address."""
        src = (ROOT / "emulation" / "inert_beacon.py").read_text(encoding="utf-8")
        self.assertIn('default="127.0.0.1"', src,
                      "inert_beacon must default to loopback")
        # no hard-coded public destination anywhere
        for m in re.finditer(r"""["'](https?://[^"']+)["']""", src):
            self.assertIn("127.0.0.1", m.group(1),
                          f"emulator references a non-loopback URL: {m.group(1)}")
        listener = (ROOT / "emulation" / "local_listener.py").read_text(encoding="utf-8")
        self.assertIn('"127.0.0.1"', listener,
                      "local_listener must bind loopback only")
        self.assertNotIn('"0.0.0.0"', listener,
                         "local_listener must never bind all interfaces")

    def test_python_floor_is_syntax_compatible(self):
        """The declared floor is 3.9; nothing tested it.

        CI now matrixes 3.9 and 3.11, but a syntax incompatibility is worth
        catching locally too - a `match` statement or a 3.10-only annotation
        would fail on the floor while passing on CI's default interpreter.
        """
        import ast
        offenders = []
        for f in python_files():
            try:
                ast.parse(f.read_text(encoding="utf-8"), feature_version=(3, 9))
            except SyntaxError as exc:
                offenders.append(f"{rel(f)}:{exc.lineno}: {exc.msg} (needs > 3.9)")
        self.assertEqual(offenders, [], f"Python 3.9 syntax failures: {offenders}")

    def test_no_binary_artifacts_committed(self):
        """A sample is pinned by hash, never stored - SCOPE.md and samples/PINS.md.

        Checks what git tracks, not what the working tree happens to contain:
        __pycache__ is ignored, and a test that fails on a local build artefact
        teaches people to ignore the test.
        """
        import subprocess
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.split()
        binaries, big = [], []
        for name in tracked:
            f = ROOT / name
            if not f.is_file():
                continue
            if f.suffix.lower() in {".exe", ".dll", ".pyc", ".zip", ".7z",
                                    ".bin", ".evtx", ".pcap", ".pcapng", ".msi"}:
                binaries.append(rel(f))
            elif f.stat().st_size > 2 * 1024 * 1024:
                big.append(f"{rel(f)} ({f.stat().st_size // 1024} KiB)")
        self.assertEqual(binaries, [], f"committed binaries: {binaries}")
        self.assertEqual(big, [], f"unexpectedly large files: {big}")


if __name__ == "__main__":
    unittest.main()
