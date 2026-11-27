#!/usr/bin/env python3
"""Loopback-only HTTP collector for inert beacon emulation.

Binds to 127.0.0.1. Logs each request (UTC timestamp, method, path, selected
headers, body length) to ./emulator_traffic.log. No external network access.
"""
import argparse
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = "emulator_traffic.log"


def log(line):
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{stamp} {line}\n")
    print(f"[{stamp}] {line}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _handle(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n else b""
        log(
            f"{self.command} {self.path} "
            f"X-Id={self.headers.get('X-Id', '-')} "
            f"X-Seq={self.headers.get('X-Seq', '-')} "
            f"UA={self.headers.get('User-Agent', '-')} "
            f"bytes={len(body)}"
        )
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    log(f"listener starting on 127.0.0.1:{args.port}")
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("listener stopped")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
