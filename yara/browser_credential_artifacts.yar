/*
 * Static indicators associated with browser-credential harvesting.
 * Many of these strings appear in legitimate security/forensics tools, so the
 * condition deliberately requires multiple independent indicators.
 */
rule Browser_Credential_Harvest_Artifacts
{
    meta:
        description = "Strings consistent with Chrome/Edge/Brave/Firefox credential recovery tooling"
        author = "ghost-detection-lab"
        date = "2026-11-27"
        attack = "T1555.003"
        severity = "medium"

    strings:
        $dpapi   = "CryptUnprotectData" ascii wide
        $local   = "Local State" ascii wide
        $login   = "Login Data" ascii wide
        $salt    = "saltysalt" ascii
        $v10     = "v10" ascii
        $v11     = "v11" ascii
        $ff      = "logins.json" ascii
        $bcrypt  = "bcrypt.dll" ascii wide
        $gcm     = "ChainingModeGCM" ascii wide
        $profile = "User Data" ascii wide

    condition:
        filesize < 10MB and
        $dpapi and $profile and
        3 of ($local, $login, $salt, $v10, $v11, $ff, $bcrypt, $gcm)
}
