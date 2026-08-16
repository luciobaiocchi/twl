# Harness compatibility matrix

One question, asked once per agent harness: **does the session contract
survive this harness, and does the canary stay hidden?**

`twl demo` generates its own canary credential and its own upstream, so every
cell runs with no vault, no provider account, and no real credential. That is
what makes this safe to run anywhere, including in CI.

```bash
cargo build
python3 test/matrix/run_matrix.py --list      # what is installed
python3 test/matrix/run_matrix.py workload    # control cell
python3 test/matrix/run_matrix.py --all       # every installed harness
```

A harness that is not installed reports `SKIP`, not `FAIL`. The two control
cells run everywhere; the agent cells run wherever that agent is configured.

## The matrix

| Cell | Harness | Status | What it is there for |
|---|---|---|---|
| `workload` | none | **implemented, passing** | Control. Proves the contract and the assertions themselves work. |
| `bash` | none | **implemented, passing** | Control. A shell that dumps its whole environment first. |
| `codex` | Codex CLI | declared, unrun | Already the documented path in `test/README.md`. Watch `shell_environment_policy`: its default filter strips `*_KEY`, which would take Towel's *placeholder* with it. |
| `claude` | Claude Code | declared, unrun | Sandboxed Bash plus an egress allowlist. `127.0.0.1` must stay reachable. |
| `gemini` | Gemini CLI | declared, unrun | Third of the three big CLIs. |
| `openhands-cli` | OpenHands CLI | declared, unrun | Host process, inherits the parent environment. Expected to be the smooth container-less path. |

Not cells yet, and deliberately so:

- **OpenHands SDK, local workspace** — needs a small Python driver rather than
  a CLI invocation. Expected to behave like `openhands-cli`.
- **OpenHands SDK, Docker agent server** — the loopback URL does not cross a
  container boundary. Needs Towel inside the same network namespace; tracked
  separately in #20.

Each cell should eventually be run on both Linux and macOS. The credential
backend is not a matrix dimension here: `demo` never touches the vault, which
is exactly why these cells are portable.

## What every cell asserts

Four inside the session, from `workload.py`, each printing one marker:

| Marker | Claim |
|---|---|
| `placeholder` | The child received `APP_API_KEY` and it is a `twl-app-` placeholder, not a real key. |
| `parent-only-absent` | `TWL_APPLICATION_API_KEY` and `TWL_APPLICATION_UPSTREAM` did not reach the child. |
| `authorized-call` | The application's request through the broker returned 200. The point of the whole exercise: the app works. |
| `wrong-route-denied` | A guessed session prefix is not served, so it cannot borrow the credential. |

Four after the child exits, from `run_matrix.py`:

- No `twl-demo-canary-…` in the transcript (stdout and stderr together).
- No base64-encoded canary in the transcript, checked at all three alignments.
- No canary in the child's captured environment.
- No canary, and no parent-only decoy value, in any file left in the workspace.

The runner plants known decoy values in the parent environment before
launching, so "the child never saw it" is tested against a value that really
existed one process up.

These assertions have been checked against planted leaks — plaintext, base64,
decoy value, and a canary written to a workspace file all produce `FAIL`. A
cell that passes is passing something.

## Adding a harness

Add an entry to `harnesses()` in `run_matrix.py`:

```python
"my-agent": {
    "probe": "my-agent",                      # skip the cell if this is not on PATH
    "command": ["my-agent", "run", "{task_text}"],
    "note": "anything the next person should know",
},
```

`command` is formatted with `{workload}` (absolute path to `workload.py`),
`{task_file}` (a `TASK.md` in a fresh workspace) and `{task_text}` (the same
text inline, for harnesses that take a prompt argument). Use whichever the
harness accepts. Nothing else needs to change.

## Reading a failure

`FAIL` keeps the workspace and prints where the transcript was saved. Start
there: the marker lines say whether the session contract broke *inside* the
run, and the scan lines say what leaked and where it was found.

A missing `MATRIX_OK:authorized-call` with no leak usually means the harness
did not pass the environment through to the command it ran. A leak with all
four markers present means the contract held but the harness copied a value
somewhere it should not have.
