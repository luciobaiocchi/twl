# Who else keeps API keys away from coding agents

Snapshot: August 2026. Written to be read quickly, including by people who have
not worked on Towel. Every claim about another product comes from its public
documentation and is linked at the bottom. Claims marked **(unverified)** are
things we believe but have not tested — the harness matrix in
[`test/matrix/`](../../test/matrix/README.md) exists to settle them.

## The problem, once

A coding agent runs your project. The project calls some API, so the key sits
in an environment variable. The agent inherits it, every subprocess inherits
it, and a single `echo` puts it in a transcript that leaves the machine. The
key stays valid afterwards.

This is not theoretical. In 2026, `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` were
read out of Claude Code's inherited environment and printed into public PR
comments (CVE-2026-54316, fixed in 2.1.163), and `GEMINI_API_KEY` was pulled
out of Gemini CLI the same way through a malicious issue comment. The
credential was never the agent's to hold; it was just lying around where the
agent could reach it.

## Four ways people are solving it

| # | Approach | In one line | Who does it | The catch |
|---|----------|-------------|-------------|-----------|
| A | **Filter the environment** | Strip `*_KEY`/`*_TOKEN` before the agent's subprocess starts | Codex CLI (`shell_environment_policy`) | The app *needs* a key to work. Filtering protects the agent's shell, not the app's call. |
| B | **Egress firewall + token swap** | Agent holds a worthless token; a MITM proxy swaps in the real secret on the way out | iron-proxy, Infisical Agent Proxy (was Agent Vault) | You install a CA and terminate TLS for everything. Heavier setup, bigger trusted component. |
| C | **Identity broker upstream** | Vault releases a short-lived credential only to a verified requester | 1Password Credential Broker | The released credential still lands in the workload. Shrinks the window, not the exposure. |
| D | **Loopback route broker** | Agent gets a fake key and a `127.0.0.1` URL; real key is attached only to the one registered destination | **Towel** | Only covers destinations you registered, one static Bearer key each, no streaming yet. |

B and D are the same idea at different costs. B intercepts *everything* and
needs to break TLS to do it. D intercepts *one declared route* and never sees
TLS at all, because the app talks plain HTTP to loopback and Towel makes the
HTTPS call itself.

## Product by product

| Product | Holds the secret | Intercepts at | CA install / TLS MITM | Needs a container | Open source | Aimed at |
|---|---|---|---|---|---|---|
| **1Password Credential Broker** (private beta Jun 2026, GA targeted late 2026) | 1Password vault | Credential *issuance*, per verified requester | No | No | No | CI/CD first (GitHub Actions), agents on the roadmap |
| **1Password for Claude** (Jul 2026) | 1Password vault | Browser autofill, per approved item | No | No | No | Claude signing into **websites** — not API keys for CLI agents |
| **iron-proxy** (`ironsh/iron-proxy`) | Proxy config or backend (AWS, 1Password, Bitwarden, files) | Egress, all traffic, DNS-redirected | **Yes** | Not strictly; DNS redirect + `CAP_NET_ADMIN` for nftables | Yes (Go) | Untrusted workloads generally; lists Claude Code, Cursor, Codex |
| **Infisical Agent Proxy / Agent Vault** | Its own vault (SQLite/Postgres) | Egress, MITM on port 14322 | **Yes** | No (`agent-vault run -- claude`) | Yes | AI agents specifically |
| **Towel (`twl`)** | macOS Keychain / Linux age vault | One loopback route per registered destination | No | No (`twl run --project x -- codex`) | Yes (Rust) | One developer, one machine, one project |

Worth noticing: `agent-vault run -- claude` and `twl run --project x -- codex`
are the same command shape. Users will compare them directly.

## Do the harnesses already do this themselves?

Short answer: they protect the *agent*, nobody brokers the *application's*
credential.

| Harness | What it already has | What it still does not do |
|---|---|---|
| **Claude Code** | Per-action permissions; sandboxed Bash; built-in egress proxy with a domain allowlist; experimental `network.tlsTerminate` (v2.1.199+); `apiKeyHelper` for short-lived *Anthropic* keys | No credential substitution. The allowlist says *where* traffic may go, not *who* holds the key. Third-party app keys are still plain env vars. |
| **Codex CLI** | `shell_environment_policy` with `inherit`/`exclude`, and a default filter that strips anything containing `KEY`, `SECRET`, `TOKEN`; Docker-based sandbox | Filtering removes the key from the subprocess — the app then fails. No path to "app works, key stays hidden". Does not stop reading `.env` as text. |
| **Gemini CLI** | Trusted-folder limits, container launcher | Same env inheritance; the 2026 CVE showed the key reaching public output. |
| **OpenHands** | `SecretsStore` / `SecretRegistry`: secrets are registered centrally, exported to bash commands, and masked in output | Masking is best-effort output filtering. The real value is still in the runtime and can be encoded or reshaped past a mask. |

Claude Code's built-in allowlisting proxy is the closest thing to a native
version of this layer, and it is the one to watch — but it is destination
control, not credential control. Towel's claim is orthogonal: even if the
agent reaches the right destination, it never held anything worth stealing.

## Where this leaves Towel

**Kept:** no CA to install, no TLS interception, no container, no daemon, no
control plane. One authorization per project session. That combination is
currently unique in the table above, and it is the entire reason to prefer
Towel over iron-proxy or Agent Vault for a single developer on a laptop.

**Missing, and now visible by comparison:**

- **Streaming.** Bodies are buffered, so token-by-token responses do not work.
  Every agent workload streams. This is the sharpest gap (issue #5).
- **One static Bearer key per route.** No short-lived credentials, no header
  templates, no non-Bearer schemes (issue #21).
- **No pluggable backend.** Towel is its own vault. iron-proxy takes 1Password
  or AWS as a source; Towel could take an external broker as a *source* of the
  key it injects without changing its own boundary.

The last one is the natural meeting point with 1Password Credential Broker:
let them issue the short-lived credential, let Towel be the thing that keeps
it out of the agent's process. That is complementary, not competing.

## Integrating with the harnesses

Towel's contract is deliberately dumb: the child gets two environment
variables, one fake key and one loopback base URL. Anything that reads
`API_KEY` + `BASE_URL` from the environment works with no adapter at all.

| Harness | Expected to work unchanged | Why / what to check |
|---|---|---|
| Codex CLI | Yes — already exercised in `test/README.md` | Plain env inheritance. Watch `shell_environment_policy`: its default filter strips `*_KEY`, which would remove Towel's *fake* key too. **(unverified)** |
| Claude Code | Expected yes | Env inheritance. If the sandbox's egress allowlist is on, `127.0.0.1` must be reachable. **(unverified)** |
| Gemini CLI | Expected yes | Same shape. **(unverified)** |
| OpenHands CLI | Expected yes | Runs on the host, inherits the parent env. **(unverified)** |
| OpenHands SDK, local workspace | Expected yes | `TerminalTool` spawns bash from the SDK process, which inherits Towel's env. **(unverified)** |
| OpenHands SDK, Docker/K8s agent server | **No, not without work** | The agent server runs in its own container and network namespace. A `127.0.0.1` URL from Towel on the host does not resolve there. |

### OpenHands: CLI or SDK?

**Recommendation: make the CLI path the supported one, and keep the SDK path
honest about its one requirement.**

- The **CLI runs on the host**, so `twl run --project x -- openhands` is the
  whole integration. No container, no adapter, no OpenHands-specific code in
  the broker. This is the smooth, container-less experience for an ordinary
  user, and it is what should appear in the README.
- The **SDK with a local workspace** should work by the same mechanism — same
  process tree, same inherited environment. If it does, we support both for
  free.
- The **SDK with a Docker/remote agent server** needs Towel and the runtime to
  share a network namespace (Towel as entrypoint inside the same container, per
  issue #20). That is a real integration, worth documenting, but it should not
  be the first thing a user meets.

The honest framing for the README: *"Towel works with any agent that reads a
key and a base URL from the environment and runs in the same network namespace
as the broker."* Everything above is a consequence of that sentence.

Whether the top three rows of that table are actually true is exactly what the
matrix measures. Until it runs, they are claims.

## Sources

- [1Password Credential Broker announcement](https://1password.com/press/2026/june/credential-broker) · [product blog](https://1password.com/blog/introducing-1password-credential-broker) · [Help Net Security](https://www.helpnetsecurity.com/2026/06/15/1password-credential-broker-reduces-secret-sprawl-through-identity-based-credential-delivery/) · [SiliconANGLE](https://siliconangle.com/2026/06/15/1password-debuts-credential-broker-release-secrets-needed/)
- [1Password for Claude](https://1password.com/press/2026/july/1password-for-claude) · [Help Net Security](https://www.helpnetsecurity.com/2026/07/17/1password-anthropic-claude-integration/) · [Engadget](https://www.engadget.com/2216405/1password-anthropic-claude-integration/)
- [1Password Privileged Access](https://1password.com/press/2026/july/privileged-access)
- [iron-proxy](https://github.com/ironsh/iron-proxy) · [docs.iron.sh](https://docs.iron.sh/) · [Hermes Agent egress guide](https://hermes-agent.nousresearch.com/docs/user-guide/egress/iron-proxy)
- [Infisical Agent Vault](https://github.com/Infisical/agent-vault) · [Agent Proxy blog](https://infisical.com/blog/agent-proxy) · [Agent Vault blog](https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents)
- [Claude Code sandboxing docs](https://code.claude.com/docs/en/sandboxing)
- [Codex CLI shell environment policy](https://codex.danielvaughan.com/2026/04/28/codex-cli-shell-environment-policy-subprocess-secrets-defence/) · [Codex CLI secrets defence](https://codex.danielvaughan.com/2026/05/10/codex-cli-secrets-defence-env-leakage-agent-vault-runtime-injection/)
- [OpenHands agent SDK](https://github.com/OpenHands/agent-sdk) · [Secret Registry docs](https://docs.openhands.dev/sdk/guides/secrets)
- [Claude Code and Gemini CLI secret-exfiltration flaws](https://thehackernews.com/2026/08/claude-code-and-gemini-cli-flaws-let.html)
