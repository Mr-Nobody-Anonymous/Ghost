#!/usr/bin/env python3
"""Inert beacon-like traffic generator. Loopback only, fake data only.

Sends requests with the custom headers and URI shape used by the design so a
proxy/SWG or local collector produces comparable telemetry. No encryption, no
real C2, no external hosts.
"""
import argparse
import http.client
import json
import time
import uuid

CANARY = "CANARY-EXFIL-TEST-DO-NOT-TREAT-AS-REAL-DATA"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--delay", type=float, default=2.0)
    args = ap.parse_args()

    vid = str(uuid.uuid4())
    for seq in range(1, args.count + 1):
        conn = http.client.HTTPConnection(args.host, args.port, timeout=5)
        path = f"/poll?id={vid}&seq={seq}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "X-Id": vid,
            "X-Seq": str(seq),
            "Content-Type": "application/octet-stream",
        }
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            resp.read()
            print(f"[{seq}/{args.count}] {path} -> {resp.status}")
        except OSError as exc:
            print(f"[{seq}/{args.count}] collector unavailable: {exc}")
        finally:
            conn.close()

        # Canary POST: simulates an exfil-shaped request with no real data.
        conn = http.client.HTTPConnection(args.host, args.port, timeout=5)
        body = json.dumps({"job": "canary", "data": CANARY}).encode()
        headers["Content-Length"] = str(len(body))
        try:
            conn.request("POST", "/result", body, headers)
            resp = conn.getresponse()
            resp.read()
        except OSError:
            pass
        finally:
            conn.close()

        if seq < args.count:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
