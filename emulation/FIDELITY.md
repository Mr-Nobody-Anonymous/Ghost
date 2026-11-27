# Emulation fidelity statement

The loopback emulator is a telemetry-shape tool, not a faithful reimplementation
of the protocol. Do not over-trust a passing emulation result.

| Aspect | Faithful? | Notes |
|---|---|---|
| Endpoints `/register`, `/poll`, `/result` | Yes | same paths as the design |
| `X-Id` / `X-Seq` headers | Yes | same names and shape |
| `Mozilla/5.0` user agent | Yes | same value |
| `Content-Type: application/octet-stream` | Yes | same value |
| `/poll?id=&seq=` query shape | Yes | same keys |
| Long-poll 28s cycle | Partly | emulator uses a configurable short delay for lab speed |
| Jitter 0.35 distribution | No | emulator uses a fixed delay; real intervals vary 29-61s |
| Sealed/encrypted body | No | emulator sends plain JSON; cipher not reproduced |
| Self-signed TLS / `CERT_NONE` | No | emulator is plain HTTP on loopback |
| 204 empty response | Partly | emulator always returns JSON `{"ok":true}` |

Consequences:

- Header-based proxy rules can be exercised with fidelity.
- TLS/JA3/x509 rules and beacon-interval analytics cannot be validated by the
  emulator; they require the network twin or a real capture.
- A passing emulator run does not prove the cryptographic layer or the kill
  switch. Record this statement alongside any emulation result.
