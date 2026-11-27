/*
 * Dedicated PyInstaller overlay detector. Complements the broader structural
 * rule by focusing only on the packager signature, so it can be run at scale
 * with a lower false-positive threshold.
 */
rule PyInstaller_Overlay_Python_Payload
{
    meta:
        description = "PyInstaller onefile/onedir executable carrying embedded Python bytecode"
        author = "ghost-detection-lab"
        date = "2026-11-27"
        attack = "T1027.002"
        severity = "low"

    strings:
        $magic   = "MEI\x0c\x0b\x0a\x0b\x0e"       // PyInstaller cookie magic
        $pyz     = "PYZ-00.pyz" ascii
        $pyi     = "pyi_" ascii
        $boot    = "pyiboot01_bootstrap" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 100KB and
        ($magic or $pyz) and
        ($pyi or $boot)
}
