#!/usr/bin/env python3
"""Run one cell of the harness compatibility matrix.

A cell is: one agent harness, launched by `twl demo`, asked to run the
project's workload. The session uses a generated canary and a generated
upstream, so a cell needs no vault, no provider account, and no real
credential. After the child exits the runner scrapes everything the child
could have leaked into and asserts the canary is not in it.

    python3 test/matrix/run_matrix.py --list
    python3 test/matrix/run_matrix.py workload
    python3 test/matrix/run_matrix.py --all

Harnesses that are not installed are reported as SKIP, not as failures: the
control cells are meant to run everywhere, the agent cells wherever that agent
is configured.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKLOAD = Path(__file__).resolve().parent / "workload.py"

# `twl demo` mints this shape and never hands it to the child. Finding it
# anywhere downstream of the child is the failure this matrix exists to catch.
CANARY = re.compile(r"twl-demo-canary-[A-Za-z0-9]{8,}")

# Decoys planted in the parent environment. Towel strips these names before
# the child starts; the values must not survive either.
DECOYS = {
    "TWL_APPLICATION_API_KEY": "twl-matrix-decoy-parent-key",
    "TWL_APPLICATION_UPSTREAM": "http://attacker.invalid",
}

REQUIRED_MARKERS = (
    "MATRIX_OK:placeholder",
    "MATRIX_OK:parent-only-absent",
    "MATRIX_OK:authorized-call",
    "MATRIX_OK:wrong-route-denied",
)

TASK = """Run this exact command and print its complete output:

    python3 {workload}

Then stop. Do not edit any file.
"""


def harnesses() -> dict:
    """The matrix. `command` is formatted with `workload` and `task`."""
    return {
        "workload": {
            "probe": "python3",
            "command": ["python3", "{workload}"],
            "note": "control: no harness, the workload runs directly",
        },
        "bash": {
            "probe": "bash",
            "command": ["bash", "-lc", "env; python3 {workload}"],
            "note": "control: a shell that dumps its environment first",
        },
        "codex": {
            "probe": "codex",
            "command": ["codex", "exec", "--skip-git-repo-check", "{task_text}"],
            "note": "watch shell_environment_policy: its default filter strips *_KEY",
        },
        "claude": {
            "probe": "claude",
            "command": ["claude", "-p", "{task_text}"],
            "note": "if the egress allowlist is on, 127.0.0.1 must stay reachable",
        },
        "gemini": {
            "probe": "gemini",
            "command": ["gemini", "-p", "{task_text}"],
            "note": "",
        },
        "openhands-cli": {
            "probe": "openhands",
            "command": ["openhands", "--headless", "--file", "{task_file}"],
            "note": "host process, inherits the parent environment",
        },
    }


def twl_binary(explicit: str | None) -> str:
    if explicit:
        return explicit
    for candidate in (ROOT / "target/debug/twl", ROOT / "target/release/twl"):
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("twl")
    if found:
        return found
    sys.exit("no twl binary: run `cargo build` or pass --twl")


def scan(text: str, label: str, failures: list) -> None:
    match = CANARY.search(text)
    if match:
        failures.append(f"canary found in {label}: {match.group(0)[:24]}...")
    for name, value in DECOYS.items():
        if value in text:
            failures.append(f"parent-only value {name} found in {label}")


def scan_encoded(text: str, failures: list) -> None:
    """Base64 hides a canary from a plain search; check every alignment."""
    for pad in ("", "x", "xx"):
        needle = base64.b64encode((pad + "twl-demo-canary").encode()).decode()
        core = needle[4:-4] if pad else needle[:-4]
        if core and core in text:
            failures.append("base64-encoded canary found in transcript")
            return


def run_cell(name: str, spec: dict, twl: str, timeout: int) -> tuple[str, list]:
    if not shutil.which(spec["probe"]):
        return "SKIP", [f"{spec['probe']} is not on PATH"]

    workspace = Path(tempfile.mkdtemp(prefix=f"twl-matrix-{name}-"))
    task_file = workspace / "TASK.md"
    task_text = TASK.format(workload=WORKLOAD)
    task_file.write_text(task_text, encoding="utf-8")
    evidence = workspace / "evidence.json"

    command = [
        part.format(workload=WORKLOAD, task_file=task_file, task_text=task_text)
        for part in spec["command"]
    ]
    environment = dict(os.environ, TWL_MATRIX_EVIDENCE=str(evidence), **DECOYS)

    session = subprocess.run(
        [twl, "demo", "--"] + command,
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    transcript = session.stdout + session.stderr

    failures: list = []
    if session.returncode != 0:
        failures.append(f"session exited {session.returncode}")
    for marker in REQUIRED_MARKERS:
        if marker not in transcript:
            failures.append(f"missing {marker}")

    scan(transcript, "the transcript", failures)
    scan_encoded(transcript, failures)

    if evidence.is_file():
        scan(evidence.read_text(encoding="utf-8"), "the child environment", failures)
    else:
        failures.append("no evidence file: the workload never ran")

    for path in workspace.rglob("*"):
        if path.is_file() and path != evidence:
            scan(path.read_text(encoding="utf-8", errors="replace"), path.name, failures)

    if failures:
        (workspace / "transcript.txt").write_text(transcript, encoding="utf-8")
        failures.append(f"transcript kept at {workspace / 'transcript.txt'}")
        return "FAIL", failures

    shutil.rmtree(workspace, ignore_errors=True)
    return "PASS", []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cells", nargs="*", help="harness names to run")
    parser.add_argument("--all", action="store_true", help="run every known cell")
    parser.add_argument("--list", action="store_true", help="print the matrix and exit")
    parser.add_argument("--twl", help="path to the twl binary")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--json", action="store_true", help="machine-readable summary")
    arguments = parser.parse_args()

    matrix = harnesses()
    if arguments.list:
        for name, spec in matrix.items():
            installed = "installed" if shutil.which(spec["probe"]) else "not installed"
            print(f"{name:16} {installed:15} {spec['note']}")
        return 0

    selected = list(matrix) if arguments.all else arguments.cells
    if not selected:
        parser.error("name at least one cell, or pass --all or --list")
    unknown = [name for name in selected if name not in matrix]
    if unknown:
        parser.error(f"unknown cell(s): {', '.join(unknown)}")

    twl = twl_binary(arguments.twl)
    results = {}
    for name in selected:
        try:
            status, notes = run_cell(name, matrix[name], twl, arguments.timeout)
        except subprocess.TimeoutExpired:
            status, notes = "FAIL", [f"timed out after {arguments.timeout}s"]
        results[name] = {"status": status, "notes": notes}
        if not arguments.json:
            print(f"{status:5} {name}")
            for note in notes:
                print(f"      {note}")

    if arguments.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    return 1 if any(cell["status"] == "FAIL" for cell in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
