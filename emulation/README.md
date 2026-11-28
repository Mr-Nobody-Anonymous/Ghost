# Inert emulation

Generates the *telemetry* of the behavior without performing the behavior.
Nothing here patches AMSI/ETW, reads credentials, establishes persistence, or
talks to anything but `127.0.0.1`.

## Run (disposable lab VM only)

```bash
# terminal 1 - loopback collector
python3 local_listener.py

# terminal 2 - beacon-like traffic with canary data
python3 inert_beacon.py --count 5 --delay 2

# terminal 3 - structured expected-event descriptors for rule validation
python3 emit_expected_events.py
```

## What each script produces

| Script | Telemetry generated | Rule it should exercise |
|---|---|---|
| `local_listener.py` | HTTP POST/GET on 127.0.0.1:8080 with canary body | proxy/beacon rules (after adapting fields) |
| `inert_beacon.py` | `X-Id` / `X-Seq` headers, `/poll?id=&seq=` URI, `Mozilla/5.0` UA | `sigma/beacon_custom_headers.yml` |
| `emit_expected_events.py` | the event each rule should see, **run through the evaluator**; no system calls | proves each rule matches its own expected event (37/37) |

`emit_expected_events.py` is not prose. The previous version listed seven
hand-written descriptors that no rule matched (0/32) while calling them
"expected events", and cited two paths that no longer existed. It now derives the
event from the rule and fails if the rule does not match it.

## Observed vs expected

For each test, record: technique, ATT&CK ID, expected telemetry, observed
telemetry, verdict (pass / gap / tune), and residual coverage gap. See
`../analysis/report-template.md`.

## Cleanup

Stop the listener (Ctrl-C), remove any `canary_*.txt` marker files created in the
lab temp directory, and restore the VM snapshot.
