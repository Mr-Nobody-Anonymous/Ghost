#!/usr/bin/env python3
"""Field-type model: render fixture values that look like the telemetry they claim to be.

A fixture is only useful if it could have come off a real host. Rendering every
constraint into one `C:\\...` string produced registry keys under `C:\\Users`,
URIs as filesystem paths and `.bmp` as a filename - values no Windows box ever
emits, so a passing test proved nothing. This module maps each Sigma field to a
builder that knows what that field contains.
"""
import re

HTTP = re.compile(r"^cs-uri|^url|^uri$")
PATH_FIELDS = {
    "TargetFilename", "Image", "SourceImage", "ParentImage", "ParentCommandLine",
    "Archived", "TargetImage", "CurrentDirectory", "NewName",
}
REGISTRY_FIELDS = {"TargetObject", "ObjectName", "RegistryKey", "ObjectNameKey"}
RULE_HIVE_FIELDS = {"TargetObject", "RegistryKey"}


def _contains(items):
    return [str(v) for mods, v in items if "contains" in mods]


def _endswith(items):
    return [str(v) for mods, v in items if "endswith" in mods]


def _startswith(items):
    return [str(v) for mods, v in items if "startswith" in mods]


def _exact(items):
    return [v for mods, v in items if not mods]


def is_registry(field, items):
    if field in RULE_HIVE_FIELDS:
        return True
    joined = " ".join(_contains(items) + [str(v) for _, v in items])
    return bool(re.search(r"(HKCU|HKLM|HKEY_|CurrentVersion\\|\\Software\\|Protect\\)", joined))


def render_path(items):
    """A Windows path that satisfies every constraint on the field."""
    contains = _contains(items)
    ends = _endswith(items)
    starts = _startswith(items)

    anchor = next((c for c in contains if c.startswith("\\")), "")
    lowered = " ".join(contains + ends).lower()
    if "appdata\\local\\temp" in lowered:
        root = "C:\\Users\\lab\\AppData\\Local\\Temp"
    elif "downloads" in lowered:
        root = "C:\\Users\\lab\\Downloads"
    elif "startup" in lowered:
        root = "C:\\Users\\lab\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    elif "_mei" in lowered:
        root = "C:\\Users\\lab\\AppData\\Local\\Temp\\_MEI153742"
    elif "program files" in lowered:
        root = "C:\\Program Files\\Vendor App"
    elif "appdata\\local\\programs" in lowered:
        root = "C:\\Users\\lab\\AppData\\Local\\Programs\\app"
    elif "appdata\\local" in lowered:
        root = "C:\\Users\\lab\\AppData\\Local"
    elif "appdata\\roaming" in lowered:
        root = "C:\\Users\\lab\\AppData\\Roaming"
    elif re.search(r"(\\|^)(amsi|ntdll|kernel32|kernelbase)\.dll$", lowered):
        root = "C:\\Windows\\System32"
    elif "windows\\system32" in lowered or re.search(r"\\[a-z0-9_.-]+\.exe$", lowered):
        root = "C:\\Windows\\System32"
    else:
        root = "C:\\Users\\lab"

    tail = ""
    for c in contains:
        if c == anchor:
            continue
        piece = c.strip("\\")
        if not piece or re.fullmatch(r"\.[a-z0-9]{1,6}", piece.lower()):
            continue
        if piece.lower() in root.lower() or piece.lower() == "_mei":
            continue
        tail += "\\" + piece
    if starts:
        root = starts[0].rstrip("\\")
    if ends:
        end = ends[0]
        if end.startswith("\\"):
            tail = end
        elif re.fullmatch(r"\.[a-z0-9]{1,8}", end.lower()):
            tail = tail + "\\artifact" + end
        else:
            tail = tail + "\\" + end.lstrip("\\")
    elif not tail:
        tail = "\\artifact.bin"
    return root + tail


def render_registry(items):
    contains = _contains(items)
    ends = _endswith(items)
    hive = "HKLM" if any("SOFTWARE\\Microsoft\\AMSI" in c or "Windows Defender" in c for c in contains + ends) else "HKCU"
    if any("HARDWARE\\DESCRIPTION" in c for c in contains):
        return "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
    parts = []
    for c in contains:
        parts.append(c.strip("\\"))
    if ends:
        parts.append(ends[0].strip("\\"))
    body = "\\".join(p for p in parts if p)
    if not body:
        body = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    if any(c.startswith(("HKCU", "HKLM", "HKEY_")) for c in contains):
        return body
    return f"{hive}\\{body}"


def render_uri(field, items):
    contains = _contains(items)
    ends = _endswith(items)
    if field == "cs-uri-query":
        parts = [c for c in contains if "=" in c]
        if not parts:
            return "id=3f9a1c&seq=17"
        query = []
        for p in parts:
            query.append(p + ("17" if p == "seq=" else "3f9a1c"))
        return "&".join(query)
    stem = "/poll" if ends and "poll" in ends[0] else (ends[0] if ends else "/")
    return stem


def render_commandline(items):
    contains = _contains(items)
    bits = [c for c in contains]
    if not bits:
        return "C:\\Windows\\System32\\cmd.exe /c whoami"
    joined = " ".join(bits)
    if joined.strip().lower() == "view":
        return "net.exe view \\\\fileserver"
    if "_MEI" in joined and " " not in joined.strip():
        return ("C:\\Users\\lab\\AppData\\Local\\Temp\\_MEI153742\\ghost.exe "
                + joined.strip())
    if "schtasks" in joined.lower() or "/Create" in joined:
        return "schtasks.exe /Create /TN Lab\\\\task /SC ONLOGON /TR C:\\Users\\lab\\AppData\\Local\\Temp\\a.exe"
    if "net.exe" in joined.lower() and "view" in joined.lower():
        return "net.exe view \\\\fileserver"
    if "SecurityCenter2" in joined or "AntiVirusProduct" in joined:
        return (
            "powershell.exe -NoP -NonI -C \"Get-CimInstance -Namespace root/SecurityCenter2 "
            "-ClassName AntiVirusProduct\""
        )
    if "stop windefend" in joined.lower():
        return "sc.exe stop windefend"
    if "MpPreference" in joined:
        return "powershell.exe -NoP -NonI -C Set-MpPreference -DisableRealtimeMonitoring $true"
    return "C:\\Windows\\System32\\cmd.exe " + bits[0]


def render(field, items, mods):
    """items: [(mods, value)] for the chosen branch. Returns a concrete value."""
    if field == "EventID":
        value = _exact(items)[0] if _exact(items) else (items[0][1])
        return int(value) if str(value).isdigit() else 1
    if field == "rcode":
        return str(_exact(items)[0]) if _exact(items) else "NXDOMAIN"
    if field == "AccessMask":
        return "0x1"
    if field == "GrantedAccess":
        return "0x1F0FFF"
    if field == "ProcessGuid":
        return "{8b1c9a10-5f2e-6a31-0b7d-1c2d3e4f5a60}"
    if field == "ProcessId":
        return 4821
    if field in ("User", "SubjectUserName", "TargetUserName"):
        return "LAB\\labuser"
    if field == "Computer":
        return "LAB-WS01"
    if field == "Signature":
        return "Microsoft Windows Publisher"
    if field == "IntegrityLevel":
        return "Medium"
    if field == "Details":
        return "DWORD (0x00000001)"
    if field == "Type":
        return "CommandLineEventConsumer"
    if field in ("QueryName", "query"):
        pats = _exact(items) + [v for _, v in items]
        if any("[a-z]{14,}" in str(p) for p in pats):
            return "kxvqmzwprtbnlcd.top"
        if any("a-z]{13," in str(p) for p in pats):
            return "kxvqmzwprtbnl.com"
        return "example.com"
    if field in ("cs-user-agent", "UserAgent"):
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    if field in ("cs-content-type", "ContentType"):
        return "application/octet-stream"
    if field == "cs-uri-query":
        return render_uri(field, items)
    if field == "cs-uri-stem":
        return render_uri(field, items)
    if HTTP.match(field):
        return render_uri(field, items)
    if field in ("CommandLine", "ParentCommandLine"):
        return render_commandline(items)
    if field.startswith("cs-header-"):
        name = field[len("cs-header-"):]
        if name.lower() in ("x-id", "x-seq"):
            return "9f3c1a7e-2b64-4d18-8e75-0c2f8a41b6e3" if name.lower() == "x-id" else "17"
        return "lab-value"
    flat_mods = {m for mod in mods for m in (mod if isinstance(mod, list) else [mod])}
    if "fieldref" in flat_mods or field in PATH_FIELDS:
        return render_path(items)
    if is_registry(field, items) or field in REGISTRY_FIELDS:
        return render_registry(items)
    if field == "DestinationHostname":
        ends = _endswith(items)
        return ends[0] if ends else "cdn.example.net"
    if field in ("DestinationAddress", "host"):
        return "203.0.113.40"
    if field in ("destination_port", "DestinationPort"):
        return 443
    if field in ("CertificateSelfSigned",):
        return True
    exact = _exact(items)
    if exact:
        return exact[0]
    return items[0][1]
