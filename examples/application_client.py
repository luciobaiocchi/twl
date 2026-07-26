#!/usr/bin/env python3
"""Small app that calls a service without receiving its real API key."""

import json
import os
import urllib.request


def main() -> None:
    parent_only = ("MTL_APPLICATION_API_KEY", "MTL_APPLICATION_UPSTREAM")
    if any(name in os.environ for name in parent_only):
        raise RuntimeError("a parent-only Mithril input reached the application")

    key = os.environ["APP_API_KEY"]
    base_url = os.environ["APP_BASE_URL"].rstrip("/")
    if not key.startswith("mtl-app-"):
        raise RuntimeError("APP_API_KEY is not a Mithril placeholder")

    request = urllib.request.Request(
        f"{base_url}/v1/models",
        headers={"Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.load(response)

    print(json.dumps({"app": "ok", "upstream": payload}, sort_keys=True))


if __name__ == "__main__":
    main()
