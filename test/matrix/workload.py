#!/usr/bin/env python3
"""Application-side workload for the harness compatibility matrix.

This is the project's own code: it runs inside a `twl demo` session, in the
place where an agent would run `python3 app.py`. It prints one marker per
assertion so a transcript scrape can tell a pass from silence, and it writes
the whole child environment to an evidence file that `run_matrix.py` inspects
after the session has ended.

Nothing here reads a real credential. `twl demo` generates its own canary and
its own upstream, so this runs anywhere without a vault or a provider key.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

PARENT_ONLY = ("TWL_APPLICATION_API_KEY", "TWL_APPLICATION_UPSTREAM")
PLACEHOLDER_PREFIX = "twl-app-"


def base_url() -> str:
    return os.environ["APP_BASE_URL"].rstrip("/")


def get(url: str, key: str, timeout: int = 5) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except OSError as error:
        return 0, str(error)


def check_placeholder() -> str | None:
    key = os.environ.get("APP_API_KEY")
    if not key:
        return "APP_API_KEY is unset: the session contract did not reach the workload"
    if not key.startswith(PLACEHOLDER_PREFIX):
        return f"APP_API_KEY does not look like a Towel placeholder ({key[:12]}...)"
    return None


def check_parent_only() -> str | None:
    leaked = [name for name in PARENT_ONLY if name in os.environ]
    if leaked:
        return f"parent-only variables reached the workload: {', '.join(leaked)}"
    return None


def check_authorized_call() -> str | None:
    """The whole point: the app's request succeeds without holding the key."""
    status, body = get(f"{base_url()}/v1/models", os.environ["APP_API_KEY"])
    if status != 200:
        return f"authorized call returned {status}: {body[:200]}"
    return None


def check_wrong_route_denied() -> str | None:
    """A guessed session prefix must not borrow the real credential."""
    url = base_url()
    parts = url.split("/")
    if len(parts) < 5:
        return f"unexpected broker URL shape: {url}"
    parts[3] = "0" * len(parts[3])
    status, _ = get("/".join(parts) + "/v1/models", os.environ["APP_API_KEY"])
    if 200 <= status < 300:
        return f"a wrong session prefix was served ({status})"
    return None


CHECKS = (
    ("placeholder", check_placeholder),
    ("parent-only-absent", check_parent_only),
    ("authorized-call", check_authorized_call),
    ("wrong-route-denied", check_wrong_route_denied),
)


def main() -> int:
    failures = 0
    for name, check in CHECKS:
        try:
            reason = check()
        except Exception as error:  # a crashed check is a failed check
            reason = f"{type(error).__name__}: {error}"
        if reason is None:
            print(f"MATRIX_OK:{name}", flush=True)
        else:
            failures += 1
            print(f"MATRIX_FAIL:{name}: {reason}", flush=True)

    # An agent would print the environment sooner or later. Do it on purpose,
    # so the runner is scraping a transcript that really contains everything
    # the child could see.
    print(json.dumps(dict(os.environ), sort_keys=True), flush=True)

    evidence = os.environ.get("TWL_MATRIX_EVIDENCE")
    if evidence:
        with open(evidence, "w", encoding="utf-8") as handle:
            json.dump({"environ": dict(os.environ)}, handle, sort_keys=True)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
