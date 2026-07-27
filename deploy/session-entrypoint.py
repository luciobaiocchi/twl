#!/usr/bin/env python3
"""Install an agent-visible Towel session manifest, then exec a command."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time


def environment_name(route_id: str) -> str:
    converted = route_id.replace("-", "_").upper()
    if not converted.isascii() or not converted or not all(
        char.isalnum() or char == "_" for char in converted
    ):
        raise RuntimeError("invalid route ID in Towel session manifest")
    return converted


def load_manifest(path: Path) -> dict[str, object]:
    deadline = time.monotonic() + float(os.environ.get("TWL_SESSION_WAIT_SECONDS", "60"))
    while True:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Towel session manifest was not created in time") from None
            time.sleep(0.1)


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit("usage: session-entrypoint.py MANIFEST COMMAND [ARGS...]")
    path = Path(sys.argv[1])
    manifest = load_manifest(path)
    if manifest.get("version") != 1:
        raise RuntimeError("unsupported Towel session manifest")
    broker = manifest.get("broker_url")
    token = manifest.get("session_token")
    routes = manifest.get("routes")
    if not isinstance(broker, str) or not broker.startswith("http://127.0.0.1:"):
        raise RuntimeError("Towel broker is not loopback")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Towel session token is missing")
    if not isinstance(routes, dict) or not routes:
        raise RuntimeError("Towel session has no routes")

    os.environ["TWL_SESSION_FILE"] = str(path)
    os.environ["TWL_BROKER_URL"] = broker
    os.environ["TWL_SESSION_TOKEN"] = token
    for route_id, access in routes.items():
        if not isinstance(route_id, str) or not isinstance(access, dict):
            raise RuntimeError("invalid route in Towel session manifest")
        route_url = access.get("url")
        fake = access.get("credential")
        if not isinstance(route_url, str) or not route_url.startswith(f"{broker}/{token}/"):
            raise RuntimeError("invalid local route URL in Towel session manifest")
        if not isinstance(fake, str) or not fake.startswith("twl-app-"):
            raise RuntimeError("invalid fake credential in Towel session manifest")
        prefix = environment_name(route_id)
        os.environ[f"TWL_ROUTE_{prefix}_URL"] = route_url
        os.environ[f"TWL_ROUTE_{prefix}_CREDENTIAL"] = fake

    if len(routes) == 1:
        access = next(iter(routes.values()))
        os.environ["APP_BASE_URL"] = access["url"]
        os.environ["APP_API_KEY"] = access["credential"]

    os.execvp(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
