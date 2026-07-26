# Capshell

**The agent never sees your API keys. One command.**

```bash
capshell run --env .env -- codex
```

Capshell starts your agent (Codex, Claude Code, OpenHands, a script) as a
child process with an environment where real keys are replaced by fake
tokens. The real keys stay in the parent process, in memory, and only get
attached to requests by a local proxy with a hardwired destination.

> **Status: v0 in progress.** The core works and is covered by tests.
> Keyring active on macOS, Windows, and Linux; on Linux, the D-Bus channel to
> the child is closed with bubblewrap, when available. 76 dependencies, 53 of
> which are the TLS stack.
> This is not audited security software: until an independent review, use
> test credentials only.

---

## The problem

Giving an autonomous agent an API key means putting it in an environment
variable, and at that point any process in that environment can read it and
send it elsewhere. That's not a bug: it's Unix working correctly.

Masking doesn't solve it — it replaces known literal strings, and gets
sidestepped by encoding, fragmentation, files, and the network. The
primitive itself, *"the secret is a string available to the process,"* is
incompatible with protecting the secret **from** the process.

---

## How it works

Three steps, no configuration beyond a file.

1. **Capshell reads the real secrets** from a source the agent never sees.
2. **Generates a mocked environment** and launches the child process inside
   it: `OPENAI_API_KEY=cs-mock-…`, `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai`.
3. **Exposes a local proxy with static routes.** On the agent's request, it
   swaps the mock for the real key and forwards to a hardwired upstream.

### Why the agent can't just call OpenAI directly

Because it has nothing to use. The token it holds is fake: a direct call to
`api.openai.com` gets a `401`. The only path that works goes through the
proxy, where the key is attached by Capshell and the destination is decided
by Capshell.

You're not forbidding the agent from leaving. You're making it so that
leaving on its own gets it nowhere.

---

## What it is, and what it isn't

Capshell does **one thing**: it stops the value of an API key from entering
the agent's process. Everything else is delegated to tools that already
exist and do it better.

| | |
|---|---|
| The agent is trashing your codebase? | **Use git.** Not Capshell's problem. |
| Want real process and filesystem isolation? | **Use Docker.** Capshell runs inside it unmodified. |
| Want to prevent source code exfiltration? | **Not possible** with a reachable LLM endpoint. We don't claim it. |
| The agent is burning through tokens? | `budget: max_requests`, optional. Per-token cost is on the roadmap. |

---

## The two properties

Testable conditions, not theorems. A test suite makes them pass or fail.

### INV-SECRET — the value never enters the agent's process

> For no managed secret does the real value show up in the child process's
> environment, its descendants, its stdout/stderr, or the logs.

This includes a rule on the proxy: **it never reflects the upstream request
back to the client**, on any error path. Upstream error bodies are
truncated and filtered — otherwise an injected header could find its way
back to the agent.

**Test:** a canary in place of the real key, a scan of the environment
(`/proc/<pid>/environ` for every descendant), output, and logs. Zero
occurrences, in plaintext and in base64.

### INV-DEST — the destination is hardwired

> No input from the agent can make an authenticated request land on a host
> other than the connector's.

`/openai` talks to `api.openai.com` and nothing else. There is no generic
proxy.

Every URL starts with a random **session token**, which the child receives
in its environment. The proxy listens on loopback, reachable by any process
on the machine: without a token, another local user could discover the port
and spend your key. A wrong token gets a `404`, exactly like a missing path,
and the comparison runs in constant time.

**Test — all rejected or forced onto the fixed host:** hostile `Host`
header; request line with an absolute URI; `CONNECT`; `X-Forwarded-Host`,
`X-Original-URL`; path traversal; **and `3xx` redirects from the upstream,
which the proxy never follows and never reattaches the key to.**

Without INV-DEST the proxy isn't a wall: it's an authenticated
exfiltration tunnel.

---

## Configuration

A single file, declaring **names, types, and connectors**. Values don't
live here.

```yaml
# capshell.yaml
secrets:
  - name: OPENAI_API_KEY
    connector: openai        # hardwired upstream: api.openai.com
  - name: ANTHROPIC_API_KEY
    connector: anthropic

budget:                      # optional, absent by default
  max_requests: 500
```

Any variable present in the source and not declared in `capshell.yaml`
passes through to the child **unchanged**. Capshell doesn't guess: it only
touches what you tell it to.

### The usage limit is optional

Without a `budget` block, Capshell prevents the key from being **stolen**,
not from being **used**: the agent can call the declared endpoint for as
long as the session lasts. That's still a real difference — an exfiltrated
key lasts forever, a brokered access dies with the session — but it needs
to be said plainly.

With `max_requests`, request N+1 gets rejected locally. The counter
increments **before** forwarding: counting afterward would let more than N
through under concurrent requests.

---

## Try it

Just `cargo` is needed. The whole round trip can be seen without a real key
and without spending anything: `capshell mock-upstream` is a fake provider
that echoes back what it received.

```bash
cargo build
cargo test                 # 30 tests: INV-SECRET, INV-DEST, budget, channels, attacks

# terminal 1 — the fake provider
./target/debug/capshell mock-upstream --port 9000

# terminal 2 — a shell under Capshell
./target/debug/capshell run \
  --config examples/capshell.yaml \
  --env examples/dev.env \
  -- sh
```

Inside that shell:

```bash
env | grep OPENAI
# OPENAI_API_KEY=sk-capshell...        <- the mock, not your key
# OPENAI_BASE_URL=http://127.0.0.1:PORT/openai

curl -s "$OPENAI_BASE_URL/v1/models"
# "authorization":"<received, 55 bytes, starts with Bearer sk-CANARY-R>"
#  ^ the real key reached the upstream, without ever passing through here

curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:PORT/openai/v1/models"
# 404: without the session token the proxy serves no one, not even
# another process of the same user who found the port

curl -s -H "Host: evil.example" "$OPENAI_BASE_URL/v1/models"
# same response: the Host header doesn't move the destination (INV-DEST)

grep -r "CANARY" /proc/self/environ
# no results (INV-SECRET)

cat "$XDG_RUNTIME_DIR/bus"
# No such file or directory: on Linux with bubblewrap, the keyring
# socket doesn't exist in the child's mount namespace
```

`examples/dev.env` declares `OPENAI_API_KEY` but **not**
`ANTHROPIC_API_KEY`, on purpose: on startup Capshell warns that the latter
passes through in plaintext because it isn't declared. It's the most
likely mistake — adding a key to `.env` and forgetting to declare it — and
the warning is the one place in the project where a heuristic is used: to
flag, never to decide what to protect.

---

## Where the secrets come from

The source is a swappable backend, chosen based on the environment. The
guarantee doesn't change: the value enters Capshell's memory and the child
always and only receives the mock.

| environment | source |
|---|---|
| desktop host (macOS, Windows, Linux with a session) | **OS keyring** |
| container, headless, CI | **environment of the Capshell process**, injected by the runtime |
| first run / migration | `--env .env`, not committed |

The two environments cover for each other: the keyring is easy on a host
and impossible in a container; UID separation is free in a container and
costly on a host.

### The keyring doesn't protect the same way on every platform

Putting the secret in the keyring takes it off the filesystem — no
`cat .env`, no `grep -r`, no accidental commits. But **stopping another
process of your own user from asking for it** is a different property, and
only one platform has it natively.

| | how it authorizes | can the agent ask for it? |
|---|---|---|
| **macOS** — Keychain | ACL per **item** and per **binary signature** | **no**: different binary, prompt or refusal |
| **Windows** — Credential Manager | DPAPI **per user** | yes, any process in the session |
| **Linux** — Secret Service | **per user**, via the session D-Bus | yes, any process that reaches the bus |

**On macOS the barrier is already there**, and just needs to not be thrown
away: the binary has to be **signed** (with an unstable binary, the ACL no
longer matches on every update, the prompt comes back, and the user learns
to click "always allow" without looking), and items need to be created with
an ACL restricted to the creating app — the default for `SecItemAdd`.

**On Linux the barrier has to be built**, and that's what `src/sandbox.rs`
does. The Secret Service is reached through a Unix socket at a path
(`/run/user/<uid>/bus`): it's enough that the path **doesn't exist in the
child's mount namespace** for `connect()` to fail, with no environment
variable able to recover it. The command gets wrapped in bubblewrap with a
tmpfs over that directory.

It's not a sandbox: `--dev-bind / /` leaves the filesystem exactly as it
is. We're not confining anything, we're removing sockets. And
`--unshare-net` is **never** passed, since that would also cut the
loopback and stop the child from reaching the proxy.

Since the namespace is already there, the session's other credential
oracles get closed too: `/run/user/<uid>/keyring/` (gnome-keyring's control
socket), `$SSH_AUTH_SOCK`, the gpg-agent socket, `/var/run/docker.sock`
(which is root-equivalent).

It's not a requirement. If bubblewrap is missing or unprivileged user
namespaces are disabled, **Capshell starts anyway and says so** — *"the
keyring stays reachable from the child process."* Degrade with a warning,
don't refuse to work. bwrap's usability is checked **before** launching the
real command with it: a failure halfway through would be indistinguishable
from an error in the user's own command.

One case is left uncovered and gets flagged: if the bus is on an
**abstract socket** (`unix:abstract=`), it lives in the network namespace
rather than the filesystem, and a mount namespace can't touch it.

You can verify all of this yourself — it's the property Linux support
rests on, so don't take it on faith:

```bash
./scripts/verify-keyring-linux.sh
```

```
--- outside capshell ---
sk-CANARY-MUST-NOT-LEAK
--- inside capshell, same command ---
secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY
```

Same command, same user, same keyring.

### Why Linux calls `secret-tool` and macOS doesn't

On Linux the keyring is reached with **`secret-tool`** (package
`libsecret-tools`), libsecret's command-line client. The equivalent Rust
library costs **79 crates** to implement D-Bus, and wouldn't buy any extra
guarantee: as the table above shows, the Secret Service authorizes by
user, so the barrier against the agent is set by the mount namespace
regardless. The keyring is left with a single job — not leaving the value
in plaintext on disk — and the CLI is enough for that.

On macOS **no, and it's not a matter of taste**: the Keychain's ACL is tied
to the signature of the binary asking. Invoking `/usr/bin/security` from
the command line would attach the guarantee to *that* binary instead, and
any process could obtain it. There, the library is mandatory.

Hence the rule: **library where the caller's identity matters, subprocess
where it doesn't.**

**On Windows** there's no simple equivalent, so the guarantee stops at
protection from exposure.

### `.env` isn't a mode, it's a migration path

```bash
capshell secret import .env
```

Moves the values into the keyring and rewrites `.env` with placeholders.
From that point on the file no longer holds secrets and can safely go into
git. `--env` remains for the first run and for anyone without a keyring.

### Inside a container

A single principle applies:

> **Capshell and the agent need to be separated by something: a UID, a
> container, or a machine.** If they share a UID and namespace, there's
> nothing to protect.

In order of preference:

1. **Two containers** — Capshell in one, the agent in the other, talking to
   the proxy over the internal network. No privileges, no shared
   namespace, ten lines of compose. It's the sidecar pattern with both
   sides containerized.
2. **One container, two UIDs** — Capshell starts as root and spawns the
   child under an unprivileged user. The sequence is `setgroups()` →
   `setgid()` → `setuid()`, **in that order**; then it verifies the drop
   actually happened and fails closed if not, closes inherited file
   descriptors with `close_range()`, and only then `execve()`.
3. **One container, one UID** — survivable but with a single line of
   defense, and not the recommended mode. It relies on
   `prctl(PR_SET_DUMPABLE, 0)`: against a non-dumpable process the kernel
   requires `CAP_SYS_PTRACE` to read `environ`, `mem`, and `maps`, even at
   the same UID. Two conditions are needed for this to work: the secret
   comes from the environment and **not** from a file the agent can read,
   and Capshell is the **entrypoint** — if a shell script launches it, that
   script stays alive as PID 1 with the secret in its own `environ`.

   Yama isn't enough on its own: `ptrace_scope` filters
   `PTRACE_MODE_ATTACH`, while reading `/proc/<pid>/environ` goes through
   `PTRACE_MODE_READ`. It's `dumpable=0` that closes both paths.

### Non-goal: encryption at rest

Capshell **persists nothing**. It reads the source at startup, holds the
value in memory for the life of the process, and dies with it. There's no
"at rest" to encrypt, so there's no cipher to choose, no encryption key to
guard, and no state file to protect.

If secrets ever needed to be persisted to disk, the right answer isn't
adding a cipher: it's using the keyring, or injecting them at runtime.

---

## Platforms

The core — child process, mocked environment, local proxy — is
**cross-platform**: it works on macOS, Windows, and Linux without
namespaces, containers, or privileges.

The only use of namespaces is the one described above: removing credential
sockets from the child's view, on Linux, as optional hardening with a
fallback.

On Linux, two optional packages, on the same `apt` line:

```bash
apt install bubblewrap libsecret-tools
```

`bubblewrap` closes the channels, `libsecret-tools` gives access to the
keyring. Without the first, Capshell works and warns; without the second,
use `--env`. Neither is a build requirement.

**Filesystem confinement built by Capshell is not planned.** Anyone who
wants real filesystem confinement should use Docker, which does it better
and is already on the recommended path.

---

## Roadmap

**v0 — core and desktop keyring.** One command, one config file, connectors
for bearer-token LLM providers (OpenAI, Anthropic, OpenAI-compatible), the
two properties with their test suite, optional `budget`.

Secret source: **OS keyring on macOS and Windows**, with `capshell secret
import` as the migration path from `.env`. This is the starting point
because it's the case where the keyring works without building anything
around it — and on macOS the signature-based ACL gives the project's
strongest guarantee from day one.

> The keyring isn't a detail that can wait: as long as the source is a file
> on disk, it needs masking, and that masking is code. The keyring
> **removes** code from the project instead of adding to it. That's why
> it's in v0, not later.

Linux is covered the same way: Secret Service as the source, and closing
the D-Bus channel to the child via bubblewrap, with a fallback where it
isn't available.

**M1 — containers.** Injecting secrets at runtime, dropping to an
unprivileged UID for the child process, Capshell as the entrypoint.

**M2 — usage control, beyond the counter.** The request cap is already in
v0. What's left is upstream bytes sent and provider-specific per-token
cost: request count is a weak proxy for spend — 500 requests with a full
context are worth hundreds of dollars.

**M3 — coverage.** Protocol-aware connectors (AWS SigV4, clients without a
base-URL override like Stripe). Pre-flight scan for secrets accidentally
committed to the repository — more a git hygiene problem than an agent one,
but easy to flag once you're already there.

Every phase keeps its fallbacks explicit and never silently weakens a
guarantee already made.

---

## What a malicious agent can still do

- **Use** the key through the proxy, toward the declared endpoint, for as
  long as the session lasts — with no limit, if you don't configure
  `budget`.
- **Exfiltrate** code and data by encoding it in a prompt. Not something
  this can stop.
- **Modify or destroy** the files it works on. Use git.
- **Read other credentials** on the machine, if you don't isolate it.
  Use Docker.
- **Ask the keyring for your items on Windows**, where authorization is
  per user rather than per application. Not on macOS: there the ACL is by
  binary signature. Not on Linux either, if bubblewrap is available: the
  bus socket doesn't exist in its mount namespace.
- Exploit a bug in Capshell, the kernel, or the upstream provider.

What it **cannot** do is obtain the value of a managed key **from
Capshell's process**, or use it against a destination you didn't declare.

---

## Project constraints

Three rules that decide what gets in and what doesn't:

1. **Maintainable by one person.** If a feature needs more than one
   maintainer to stay correct, it doesn't get in.
2. **No privilege required.** No root, no setuid, no system daemon on the
   main path.
3. **Composable, not a replacement.** Capshell sits alongside Docker, git,
   and existing keyrings. It doesn't replace them and doesn't require them.

---

## On the claims made here

This document avoids "100% secure," "zero risk," and "mathematically
verifiable." The two properties above are testable conditions, not
proofs: a test suite is not a demonstration. The value is in having
written them so that a test can disprove them.
