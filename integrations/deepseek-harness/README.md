# Towel for DeepSeek Harness

This out-of-tree plugin exposes Towel's persisted HTTP capabilities as one
DeepSeek Harness tool, `twl_request`. The plugin never resolves or receives a
route credential. It starts a trusted Towel child, discovers non-secret
capability descriptors, sends constrained invocations over private stdio, and
renders only bounded, sanitized results.

V1 compatibility was checked on 2026-08-13 with:

- DeepSeek Harness packages `0.1.0-rc.6` (`@deepseek-ai/dsh-tools`);
- Cordis `4.0.1`;
- Node `22.22.2`;
- Towel at the commit containing this integration.

Issue #49 originally reviewed DeepSeek Harness `0.1.0-rc.5`. That exact
`@deepseek-ai/dsh-tools` version was not published to npm, so the adapter's
compiled compatibility gate uses the next published release candidate,
`0.1.0-rc.6`, after re-checking the current tool, bundle, configuration, and
lifecycle APIs. DeepSeek Harness remains in developer preview; re-run these
checks before releasing the plugin.

## Configure Towel

Build and install a protected Towel binary first. On macOS, real project
sessions require the signed/hardened build described in the repository README.
On Linux, use the release build and encrypted vault.

Create a route without an application environment binding, then add a
capability:

```text
$ twl project add dsh-demo
New route name: github
Exact HTTPS base URL: https://api.github.com
Application environment binding? (y/n) [n]: n
Static Bearer API key: <narrow, disposable token entered securely>
New route name:

$ twl capability add --project dsh-demo
Capability name: github-read
Description: Read one GitHub repository.
Route: github
Allowed methods (comma-separated): GET
Allowed path prefixes (comma-separated): /repos/OWNER/REPOSITORY
Maximum response bytes [1048576]:
```

The `/repos/OWNER/REPOSITORY` prefix matches that path and its child paths, but
not sibling repositories. Policy and the real route credential are stored
together in Towel's protected project record.

## Build and install the bundle

From the integration directory:

```bash
npm ci --ignore-scripts
npm run check
```

For local Harness development, build first, return to the repository root, and
add the checkout to a profile:

```bash
npm run build
cd ../..
dsh plugin --profile towel add ./integrations/deepseek-harness
```

The bundle reads only non-secret startup configuration. The bundled patch uses
`TWL_PROJECT` and optionally `TWL_BINARY`:

```bash
TWL_PROJECT=dsh-demo dsh --profile towel
```

Alternatively, override the complete row in the profile's
`cordis.patch.yml` (later layers replace the full `config` value):

```yaml
- id: towel-capabilities
  name: dsh-towel
  config:
    project: dsh-demo
    twlBinary: /trusted/path/to/twl
    maxModelOutputBytes: 65536
    shutdownGraceMs: 1500
```

No token, secret environment name, protected-store path, or credential
fingerprint belongs in this configuration.

The V1 adapter starts eagerly so capability discovery completes before the
plugin becomes active. Starting the profile may therefore trigger Towel's
platform authorization prompt.

## Model-facing contract

The plugin registers one tool:

```text
twl_request
  capability
  method
  path
  query?       (without `?`)
  body?        (UTF-8)
  content_type?
```

The schema and description enumerate configured capability names,
descriptions, methods, and path prefixes. They do not disclose route
credentials, fingerprints, or an arbitrary host field. Towel remains the
authority boundary: plugin-side schema validation is only user experience, and
the broker rejects any method or path outside stored policy before an upstream
request.

Text and JSON results are decoded and capped by `maxModelOutputBytes`. Binary
responses are replaced with a byte-count placeholder. Authentication headers
and other upstream response headers are never returned.

## Lifecycle and descriptor isolation

The plugin creates the child with:

```text
twl capability serve --project <name> --stdio
stdio: [pipe, pipe, pipe]
shell: false
detached: false
```

The child process is acquired inside `ctx.effect()`. On unload, HMR, config
replacement, cancellation, or startup failure, the adapter stops accepting
calls, rejects pending requests, closes stdin, waits for Towel to exit, sends
SIGTERM if needed, and finally escalates to SIGKILL. Node's dedicated child
pipes are not passed to unrelated subprocesses launched by other Harness
tools.

The adapter buffers at most one bounded protocol frame and never logs raw
frames or request bodies. Towel stderr is consumed into a small private
diagnostic tail so the child cannot block, but that tail is not sent to the
model.

## Credential-free demo

The core protocol can be exercised without Harness, protected storage, or a
provider account:

```bash
cargo build
printf '%s\n' \
  '{"op":"hello","protocol":1}' \
  '{"id":"1","op":"list"}' \
  '{"id":"2","op":"invoke","capability":"demo-read","method":"GET","path":"/allowed/example"}' \
  '{"id":"3","op":"invoke","capability":"demo-read","method":"DELETE","path":"/allowed/example"}' \
  | ./target/debug/twl capability demo --stdio
```

Automated Rust tests additionally prove path denial, arbitrary-origin denial,
query confinement, response bounds, Bearer injection, plaintext/common-Base64
reflection blocking, malformed/oversized protocol recovery, EOF shutdown, and
absence of the generated canary from stdout/stderr. Adapter tests cover
protocol correlation, tool rendering, explicit pipe creation, pending-call
failure, and EOF/SIGTERM process disposal.

The V1 validation also boots the published `@deepseek-ai/dsh` `0.1.0-rc.6`
headless profile against `tests/mock-deepseek.mjs`. The mock model calls the
discovered `github-read` capability for `/repos/luciobaiocchi/twl`; the adapter
uses `tests/twl-demo-wrapper` to connect that call to Towel's real canary broker.
The second model request receives the tool result and returns `Towel capability
result received.`. This exercises the real Harness loader, tool loop, adapter,
stdio protocol, broker, mock upstream, and plugin disposal without a provider
credential.

## V1 limitations

- Only credential-backed HTTP requests are supported.
- Authentication is static Bearer, inherited from Towel's existing route model.
- Requests and responses are buffered; there is no streaming.
- The adapter owns one local Towel process per plugin instance; there is no
  daemon, remote transport, delegation, or multi-user grant model.
- Stored capabilities are pre-authorized for the session. DeepSeek approval
  integration and per-request grants are intentionally outside V1.
- A compromised Harness process can exercise its live capability pipe. Full
  host control, `ptrace`, privileged Docker, and comparable attacks remain
  outside Towel's security boundary.
