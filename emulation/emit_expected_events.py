#!/usr/bin/env python3
"""Emit structured descriptions of the telemetry each behavior should produce.

Makes no system calls. Use the JSON to validate that your SIEM correlation logic
understands the event shapes, or as input to a tabletop exercise.
"""
import datetime
import json

EVENTS = [
    {
        "technique": "AMSI/ETW function patch",
        "attack": "T1562.001",
        "source": "Sysmon 10 / EDR memory telemetry",
        "expected": {
            "EventID": 10,
            "TargetImage": "C:\\Windows\\System32\\amsi.dll",
            "GrantedAccess": "0x001F0FFF",
        },
        "rule": "sigma/amsi_etw_patch.yml",
    },
    {
        "technique": "WMI event subscription persistence",
        "attack": "T1546.003",
        "source": "Sysmon 19/20/21",
        "expected": {"EventID": 21, "User": "LAB\\testuser"},
        "rule": "sigma/wmi_event_subscription_persistence.yml",
    },
    {
        "technique": "Run key persistence",
        "attack": "T1547.001",
        "source": "Sysmon 12/13/14",
        "expected": {
            "EventID": 13,
            "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\labmarker",
        },
        "rule": "sigma/runkey_schtask_startup_persistence.yml",
    },
    {
        "technique": "Scheduled task persistence",
        "attack": "T1053.005",
        "source": "Sysmon 1 / Security 4698",
        "expected": {"EventID": 1, "Image": "schtasks.exe", "CommandLine": "/Create /SC ONLOGON"},
        "rule": "sigma/runkey_schtask_startup_persistence.yml",
    },
    {
        "technique": "PyInstaller onefile staging",
        "attack": "T1027.002",
        "source": "Sysmon 1",
        "expected": {"EventID": 1, "Image": "C:\\Users\\lab\\AppData\\Local\\Temp\\_MEI123456\\ghost.exe"},
        "rule": "sigma/pyinstaller_onefile_execution.yml",
    },
    {
        "technique": "DGA fallback",
        "attack": "T1568.002",
        "source": "Zeek dns.log",
        "expected": {"rcode": "NXDOMAIN", "query": "abcdefghijklmn.example.com"},
        "rule": "sigma/dga_high_entropy_dns.yml",
    },
    {
        "technique": "Custom-header beacon",
        "attack": "T1071.001",
        "source": "proxy / SWG",
        "expected": {"cs-header-X-Id": "uuid", "cs-header-X-Seq": "3", "cs-uri-stem": "/poll"},
        "rule": "sigma/beacon_custom_headers.yml",
    },
]


def main():
    doc = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "note": "Expected-event descriptors only. No system calls were made.",
        "events": EVENTS,
    }
    print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
