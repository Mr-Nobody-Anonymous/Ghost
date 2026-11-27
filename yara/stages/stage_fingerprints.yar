/*
 * Stage-specific structural fingerprints. Detection indicators only - no
 * implementation. Tune against a benign corpus before enabling in production.
 */
rule Stage_Dropper_Fetcher
{
    meta:
        description = "Small fetcher with multi-URL array and HMAC verification"
        attack = "T1105"
        severity = "medium"
    strings:
        $url1 = "https://" ascii
        $hmac = "HMAC" ascii nocase
        $sha  = "sha256" ascii nocase
        $zip  = "PK\x03\x04" ascii
    condition:
        filesize < 64KB and $url1 and $hmac and $sha and $zip
}

rule Stage_C2_Client_Headers
{
    meta:
        description = "C2 client structural indicators"
        attack = "T1071.001"
        severity = "medium"
    strings:
        $xid  = "X-Id" ascii
        $xseq = "X-Seq" ascii
        $ua   = "Mozilla/5.0" ascii
        $oct  = "application/octet-stream" ascii
        $poll = "/poll" ascii
    condition:
        $xid and $xseq and $ua and $oct and $poll
}

rule Config_Encrypted_Constants
{
    meta:
        description = "Build-time encrypted config artifacts"
        attack = "T1027"
        severity = "low"
    strings:
        $psk = "PSK" ascii
        $dga = "DGA_SEED" ascii
        $seed = "DGA_TLD" ascii
        $mutex = "MUTEX" ascii
    condition:
        3 of ($psk, $dga, $seed, $mutex)
}
