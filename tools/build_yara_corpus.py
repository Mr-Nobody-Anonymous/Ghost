#!/usr/bin/env python3
"""Build the YARA corpus deterministically.

Six synthetic files cannot measure precision, and this tool does not pretend
otherwise - see yara/corpus/README.md. What they do is turn six specific
false-positive hypotheses into failing tests:

  1. a security product that *names* `AmsiScanBuffer` is not a patcher
  2. an ETW consumer that names `EtwEventWrite` is not a patcher
  3. a legitimate PyInstaller app contains `_MEI`
  4. a browser that has an `X-Id` header is not C2
  5. a monitoring agent with both `PSK` and `DGA_SEED` strings is not an implant
  6. an installer that references `svc_update.exe` is not a spreader

Every file is generated from a fixed template with no clock and no randomness,
so `--check` is meaningful: a difference means someone edited a corpus file by
hand or changed the generator, and both should be deliberate.
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "yara" / "corpus"

# A minimal but valid-looking PE header: 'MZ' plus a PE signature at the offset
# the rule checks (uint16(0) == 0x5A4D is the whole PE test).
PE_STUB = (b"MZ" + b"\x90" * 0x3A + b"\x40\x00\x00\x00"
           + b"\x00" * 0x40 + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 200)
PE_TAIL = b"\x00" * 256

# Real patch bytes: mov eax, 0x80070057 ; ret  and  xor eax, eax ; ret
PATCH_AMSI = bytes.fromhex("B857000780C3")
PATCH_ETW = bytes.fromhex("33C0C3")

IMPLANT = (
    PE_STUB
    + b"\x00 PyInstaller\\bootloader\\pyi-windows-spec\x00"
    + b"MZ\x00_MEI64\x00python3.dll\x00"
    + b"AmsiScanBuffer\x00" + PATCH_AMSI
    + b"EtwEventWrite\x00" + PATCH_ETW
    + b"X-Id\x00X-Seq\x00"
    + b"DGA_SEED=0x9e3779b9\x00PSK\x00"
    + b"svc_update.exe\x00autorun.inf\x00"
    + PE_TAIL
)

BENIGN = {
    # A defender that calls the function it also names. No patch bytes.
    "benign/msmpeng_like.bin": (
        PE_STUB + b"\x00Microsoft Defender\x00MpSvc.dll\x00"
        + b"AmsiScanBuffer\x00AmsiOpenSession\x00AmsiCloseSession\x00"
        + b"AMSI provider registration\x00" + PE_TAIL),
    # An ETW consumer: it subscribes to the provider, which requires the name.
    "benign/edr_etw_consumer.bin": (
        PE_STUB + b"\x00EDR sensor\x00EtwEventWrite\x00EtwRegister\x00"
        + b"Microsoft-Windows-Threat-Intelligence\x00" + PE_TAIL),
    # A real PyInstaller application. `_MEI` is the extraction directory of
    # every one-file build on the planet.
    "benign/python_embed.bin": (
        PE_STUB + b"\x00pyinstaller\x00_MEI\x00python3.dll\x00base_library.zip\x00"
        + b"Py_InitializeFromConfig\x00" + PE_TAIL),
    # One header name from the pair, in an enum. Browsers have lots of these.
    "benign/browser_update.bin": (
        PE_STUB + b"\x00Chrome Updater\x00X-Id\x00X-Requested-With\x00"
        + b"User-Agent\x00Accept-Language\x00" + PE_TAIL),
    # Both 'PSK' and 'DGA_SEED' appear - as a config key name and a comment
    # string in a monitoring agent. The rule needs an evasion symbol too.
    "benign/uptime_agent.bin": (
        PE_STUB + b"\x00uptime-agent\x00psk = config.psk\x00DGA_SEED placeholder"
        + b"\x00healthcheck\x00" + PE_TAIL),
    # A signed installer that ships a service binary with that name.
    "benign/installer_signed.bin": (
        PE_STUB + b"\x00Contoso Installer\x00svc_update.exe\x00setup.exe\x00"
        + b"digicert\x00" + PE_TAIL),
}

PARTIAL = {
    # Each carries exactly one strong indicator and nothing to pair it with.
    "partial/amsi_symbol_only.bin": PE_STUB + b"AmsiScanBuffer\x00" + PE_TAIL,
    "partial/etw_symbol_only.bin": PE_STUB + b"EtwEventWrite\x00" + PE_TAIL,
    "partial/patch_bytes_only.bin": PE_STUB + PATCH_AMSI + PE_TAIL,
    "partial/mei_only.bin": PE_STUB + b"_MEI\x00" + PE_TAIL,
    # Not a PE at all, carrying everything the rule looks for.
    "partial/not_a_pe.txt": (b"plain text, not a portable executable\n"
                             b"AmsiScanBuffer EtwEventWrite X-Id X-Seq _MEI "
                             b"DGA_SEED PSK svc_update.exe autorun.inf\n"),
    # Two symbols together is the "evasion pair" branch, but on a file with no
    # patch bytes it is still just an importer table. This file asserts the rule
    # DOES fire (see the test), so it lives in implant/ instead.
}


def files():
    out = {"implant/ghost_implant_synthetic.bin": IMPLANT}
    out.update(BENIGN)
    out.update(PARTIAL)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    stale = []
    for rel, data in files().items():
        path = CORPUS / rel
        if args.check:
            if not path.is_file() or path.read_bytes() != data:
                stale.append(rel)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    if args.check:
        if stale:
            for rel in stale:
                print(f"FAIL yara/corpus/{rel} is stale or missing; run "
                      f"python3 tools/build_yara_corpus.py", file=sys.stderr)
            return 1
        print(f"yara corpus: {len(files())} file(s) current")
        return 0
    print(f"yara corpus: wrote {len(files())} file(s) under yara/corpus/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
