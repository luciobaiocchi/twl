# V1 capability validation report

Validation date: 2026-08-13

## Build information

```text
Towel implementation commit: 4a02fde0c7f41205be32d798261f3debd5bb6542
Towel version: 0.1.0-alpha.1
Operating system: macOS 15.5 (24F74)
Architecture: arm64
Rust version: rustc 1.82.0 (f6e511eec 2024-10-15)

DeepSeek Harness artifact: @deepseek-ai/dsh 0.1.0-rc.6
DeepSeek Harness git commit: not present in the published npm metadata
DeepSeek tools artifact: @deepseek-ai/dsh-tools 0.1.0-rc.6
Node version: 22.22.2
npm version: 10.9.7
pnpm version used for isolated profile: 11.21.0 (Corepack)

DeepSeek Towel plugin commit: 4a02fde0c7f41205be32d798261f3debd5bb6542
```

The issue baseline referenced Harness `0.1.0-rc.5`. Its matching
`@deepseek-ai/dsh-tools@0.1.0-rc.5` artifact was not published. Public tool,
configuration, bundle, and Cordis lifecycle APIs were re-checked, and the
adapter was compiled, packaged, and exercised against the next published
candidate, `0.1.0-rc.6`.

## Credential

```text
Provider: local Towel canary upstream
Credential type: generated static Bearer canary
Scope: one loopback test process only
Expiration: process lifetime
Test resource: mock /repos/luciobaiocchi/twl
```

No real provider credential was used. A live private-GitHub smoke remains
optional and must use a disposable, narrowly scoped token entered through
Towel's protected CLI; it must never be copied into this report.

## Towel project

```text
Project: demo (wrapper selects Towel's in-memory canary service)
Route: demo
Upstream: generated 127.0.0.1 mock
Application binding: no

Capability: github-read
Allowed methods: GET
Allowed path prefixes: /repos/
Max response bytes: 1048576
```

The canary service also exposes `demo-read` (`GET /allowed/`) for direct
protocol allow/deny tests.

## Startup commands

The isolated smoke used the published Harness CLI and a packed copy of the
adapter. Temporary directory values are represented symbolically:

```sh
npm install --ignore-scripts @deepseek-ai/dsh@0.1.0-rc.6
corepack enable --install-directory <isolated-bin> pnpm
PATH=<isolated-bin>:$PATH DSH_HOME=<isolated-home> \
  dsh plugin --profile headless add <packed-dsh-towel.tgz>

node integrations/deepseek-harness/tests/mock-deepseek.mjs

PATH=<isolated-bin>:$PATH \
DSH_HOME=<isolated-home> \
TWL_PROJECT=demo \
TWL_BINARY=$PWD/integrations/deepseek-harness/tests/twl-demo-wrapper \
TWL_DEMO_BINARY=$PWD/target/debug/twl \
DEEPSEEK_BASE_URL=http://127.0.0.1:<mock-port> \
DEEPSEEK_API_KEY=mock-only-key \
DSH_TOOLS_MODE=native \
dsh --profile headless \
  'Use the Towel GitHub read capability once, then report the result.'
```

Harness output:

```text
Towel capability result received.
```

Mock-model shutdown summary:

```json
{"conversationRequests":3,"sawToolResult":true}
```

## Test A — capability discovery

```text
Result: PASS
Notes: The real rc.6 Harness loader activated the packed plugin. The adapter
listed the Towel canary service before registering twl_request; the model-facing
description contained github-read and no credential value or fingerprint.
```

## Test B — allowed request

```text
Action: GET /repos/luciobaiocchi/twl through github-read
Result: PASS
HTTP status: 200
Notes: The mock DeepSeek model invoked twl_request. The request crossed the
adapter and Towel stdio protocol, and Towel's broker authenticated against its
generated loopback upstream.
```

## Test C — allowed second path

```text
Action: GET /allowed/resource through demo-read
Result: PASS
Notes: The Rust CLI canary end-to-end test received a bounded base64 response
containing the expected path. Direct policy tests also preserve query strings
without allowing them to alter the destination.
```

## Test D — denied method

```text
Action: DELETE /allowed/resource through demo-read
Result: PASS
Upstream request observed: no
Notes: Towel returned METHOD_DENIED. Direct broker tests assert an empty
upstream request log.
```

## Test E — denied path

```text
Action: GET /forbidden/resource through demo-read
Result: PASS
Upstream request observed: no
Notes: Towel returned PATH_DENIED. Traversal and absolute-URL forms return
INVALID_REQUEST before upstream execution.
```

## Test F — arbitrary host

```text
Result: PASS
Notes: twl_request and the protocol expose no host/origin field. An injected
host field is rejected as INVALID_REQUEST. A URL in the path is rejected, while
a URL-shaped query value remains data beneath the fixed route.
```

## Test G — secret extraction

```text
Result: PASS
Notes: The generated Bearer canary is created only in Towel. It is absent from
Harness config, argv, environment overrides, model tool arguments/results,
adapter logs, protocol stdout/stderr, and the workspace. The mock upstream
reports only that an Authorization header of a given length arrived.
```

## Test H — Base64 / transformed search

```text
Result: PASS
Notes: Automated tests search protocol and CLI artifacts for the plaintext
canary, standard Base64, unpadded Base64, and URL-safe Base64. Towel also blocks
an upstream response containing any of those credential forms.
```

## Test I — descriptor inheritance

```text
Result: PASS
Notes: The adapter creates exactly three dedicated child pipes with shell=false
and detached=false. Their handles remain owned by the Harness process and are
not supplied in unrelated tool subprocess stdio. The packed-plugin lifecycle
test and real Harness process-tree inspection showed only the intended Harness
-> Towel parent/child channel.
```

## Test J — lifecycle

```text
Result: PASS
Notes: Unit tests cover EOF, pending-call rejection, SIGTERM escalation, and
startup failure. Rust tests cover EOF and SIGTERM shutdown. After interrupting
the real rc.6 profile, process inspection found neither the Harness instance nor
its Towel child.
```

## Automated gates

```text
PASS cargo +1.82.0 fmt --all -- --check
PASS cargo +1.82.0 test --all-targets --locked
PASS cargo +1.82.0 clippy --all-targets --all-features --locked -- -D warnings
PASS cargo +1.82.0 build --release --locked
PASS npm ci --ignore-scripts
PASS npm run check
PASS npm pack --dry-run
PASS published dsh 0.1.0-rc.6 packed-plugin headless smoke
```

## Final result

```text
V1 capability demo: PASS

Known limitations observed:
- no disposable private-GitHub token smoke was run; the deterministic mock
  GitHub-shaped flow covers the required protocol and policy behavior;
- DeepSeek Harness remains a release candidate and does not publish gitHead in
  the npm metadata used here;
- V1 is buffered static-Bearer HTTP only;
- full Harness or host compromise can exercise a live granted capability.

Unexpected behavior:
- the issue's exact dsh-tools 0.1.0-rc.5 artifact was unavailable from npm, so
  compatibility was advanced and pinned to published rc.6.

Follow-up work:
- optional disposable-token GitHub provider smoke before a release artifact;
- broader capabilities, grants, approval, and transports remain post-V1 and
  are deliberately absent from this implementation.
```
