#!/usr/bin/env python3
"""Local test service. Use only a disposable test key with this program."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


EXPECTED_KEY = os.environ.get("MTL_TEST_APPLICATION_KEY", "third-party-test-key")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        authorized = self.headers.get("Authorization") == f"Bearer {EXPECTED_KEY}"
        status = 200 if authorized and self.path == "/v1/models" else 401
        body = json.dumps(
            {"authenticated": authorized, "path": self.path}, sort_keys=True
        ).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("test upstream: http://127.0.0.1:8765", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
