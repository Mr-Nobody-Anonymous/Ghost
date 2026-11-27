# Detection lab setup

Use an isolated VM. This lab generates only inert telemetry; no real malware,
no live C2, no real credentials.

## Network mode

| Goal | Mode |
|---|---|
| Local emulation, no external traffic | Internal Network or Host-only |
| Need package updates but no inbound | NAT |
| Need the host to reach the VM | Host-only with a second NAT adapter |

Do **not** use Bridged on an untrusted or corporate LAN: the VM becomes visible
to the whole segment. Snapshot the VM before running anything.

## Inside the lab VM

```bash
# confirm the adapter and address
ip -br link
ip -br addr

# verify loopback only for the emulator
python3 emulation/local_listener.py --port 8080
# from another terminal
python3 emulation/inert_beacon.py --count 5 --delay 2
```

Expected result: `emulator_traffic.log` contains entries with `X-Id`, `X-Seq`,
`/poll?id=...&seq=...`, and a `Mozilla/5.0` user agent. If your proxy/SWG
telemetry is piped into the SIEM, `sigma/beacon_custom_headers.yml` should fire.

## Data sources to enable for full coverage

- Sysmon (with a config covering process create, file create, registry, WMI events 19/20/21, and process access).
- Windows Security: 4624/4625, 4698/4699/4702, 4662/5136, 4886/4887.
- Zeek DNS and HTTP logs, or equivalent DNS/proxy telemetry.
- EDR memory-protection and process-access telemetry (required for the AMSI/ETW rule).

## Cleanup

Stop the listener, remove any generated `canary_*.txt` / `emulator_traffic.log`,
and restore the snapshot. Leave no artifacts behind.
