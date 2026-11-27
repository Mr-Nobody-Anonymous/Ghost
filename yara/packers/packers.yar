/*
 * Packer / toolchain detection rules. Detection signatures only.
 * One rule catches one packer; run the whole set at scale and tune per rule.
 */
import "math"

rule Packer_UPX
{
    meta:
        description = "UPX-packed executable"
        attack = "T1027.002"
        severity = "low"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($upx*)
}

rule Packer_Nuitka
{
    meta:
        description = "Nuitka-compiled Python payload"
        attack = "T1027.002"
        severity = "low"
    strings:
        $n1 = "nuitka" ascii nocase
        $n2 = "__nuitka__" ascii
        $n3 = "onefile" ascii
    condition:
        uint16(0) == 0x5A4D and $n1 and ($n2 or $n3)
}

rule Packer_GoBuildInfo
{
    meta:
        description = "Go buildinfo section present"
        attack = "T1027.002"
        severity = "low"
    strings:
        $go = "go1." ascii
        $bi = "\xFF Go buildinfo:" ascii
    condition:
        uint16(0) == 0x5A4D and ($go or $bi)
}

rule Packer_DotNetSingleFile
{
    meta:
        description = ".NET single-file bundle indicator"
        attack = "T1027.002"
        severity = "low"
    strings:
        $sfx = ".NETCoreApp," ascii
        $hdr = "NETCORE" ascii
    condition:
        uint16(0) == 0x5A4D and $sfx and $hdr
}

rule HighEntropyAppendedSection
{
    meta:
        description = "Executable with a high-entropy final section - generic packed heuristic"
        attack = "T1027.002"
        severity = "low"
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 7.2 and
        filesize > 200KB
}
