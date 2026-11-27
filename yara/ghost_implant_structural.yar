/*
 * Structural detection for a Python/PyInstaller-style implant.
 * These strings are detection indicators only - they do not implement any
 * behavior. Tune condition thresholds against a clean baseline before use.
 *
 * Matching logic is exercised by tests/test_rules.py::YaraTests, which asserts
 * both that each intended shape fires and that partial indicators do not.
 */
rule Ghost_Implant_Structural
{
    meta:
        description = "PyInstaller-packaged Python implant with evasion, DGA and custom-header C2 indicators"
        author = "ghost-detection-lab"
        date = "2026-11-27"
        attack = "T1685, T1568.002, T1071.001, T1027.002"
        severity = "high"
        note = "T1685 replaced T1562.001 when ATT&CK v20 revoked it"

    strings:
        $amsi_fn   = "AmsiScanBuffer" ascii wide
        $etw_fn    = "EtwEventWrite" ascii wide
        $vp        = "VirtualProtect" ascii wide
        $patch1    = { B8 57 00 07 80 C3 }      // mov eax,0x80070057; ret
        $patch2    = { 33 C0 C3 }               // xor eax,eax; ret
        $xid       = "X-Id" ascii
        $xseq      = "X-Seq" ascii
        $mei       = "_MEI" ascii
        $dga       = "DGA_SEED" ascii
        $psk       = "PSK" ascii
        $svc       = "svc_update.exe" ascii
        $autorun   = "autorun.inf" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            // the patch and the name of what it patches, in the same file
            (any of ($patch1, $patch2) and 1 of ($amsi_fn, $etw_fn, $vp)) or
            // evasion pair only: two of the three patch targets named together
            (2 of ($amsi_fn, $etw_fn, $vp)) or
            (all of ($xid, $xseq) and $mei) or
            ($svc and $autorun) or
            ($dga and $psk and any of ($amsi_fn, $etw_fn))
        )
}
