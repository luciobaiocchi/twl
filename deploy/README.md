# Container deployment

Towel must remain outside the coding agent's process and filesystem boundary.
The templates here create one broker session per agent runtime and share only a
network namespace plus an agent-visible session manifest. The manifest contains
local URLs, fake credentials, and an expiring capability token; protect it from
unrelated workloads, but it does not contain provider credentials or upstream
destinations.

## Docker Compose

Build the Towel image, provide the encrypted vault and its password as secrets,
then start the companion topology:

```bash
export TWL_VAULT_PATH=/secure/towel/towel.vault
export TWL_PASSWORD_PATH=/secure/towel/unlock-password
docker compose -f deploy/docker-compose.yaml up --build
```

Replace the example `agent` image and command with the coding-agent runtime.
Keep both containers unprivileged. They intentionally use the same numeric UID
so the Towel-owned `0640` session manifest is readable through the named volume;
prepare any workspace mount for that UID or use a dedicated shared group.

The agent uses Docker Compose `network_mode: service:towel`, so its loopback is
the Towel container's network namespace. No broker port is published. PID and
root filesystems remain separate; do not add `pid: service:towel`, privileged
mode, `CAP_SYS_PTRACE`, or a mount of either Docker secret to the agent.

The checked-in agent command only proves that the session was installed. The
[session entrypoint](session-entrypoint.py) waits for the manifest, exports the
fake per-route variables, and then replaces itself with the configured agent.

## Kubernetes

The Pod template uses a Kubernetes-native sidecar (`initContainers` with
`restartPolicy: Always`) so Towel starts before the application and stays alive
for the Pod lifetime. This form is enabled by default from Kubernetes 1.29 and
is stable from 1.33. See the official
[sidecar documentation](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/).

Create the inputs from a trusted control plane; never place plaintext values in
the manifest or repository:

```bash
kubectl create secret generic towel-encrypted-vault \
  --from-file=towel.vault=/secure/towel/towel.vault
kubectl create secret generic towel-vault-unlock \
  --from-file=password=/secure/towel/unlock-password
kubectl create configmap towel-session-entrypoint \
  --from-file=session-entrypoint.py=deploy/session-entrypoint.py
kubectl apply -f deploy/kubernetes-pod.yaml
```

Before applying, replace both image placeholders with pinned images and replace
the example `codex` command with the desired agent entrypoint. In production,
use a control-plane-owned encrypted-vault Secret, a short-lived unlock source,
and a persistent workspace volume appropriate for the runtime.

The Pod explicitly keeps `shareProcessNamespace: false`, runs as a non-root UID,
sets `allowPrivilegeEscalation: false`, uses the runtime-default seccomp profile,
drops all Linux capabilities, and mounts the vault/password only in Towel. These
settings follow the Kubernetes Restricted Pod Security expectations documented
in the official [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

All containers in a Pod share one network namespace and can communicate over
loopback. Standard NetworkPolicy therefore cannot distinguish the agent's
traffic from Towel's traffic. The example policy is deliberately fail-closed
with documentation-only CIDRs: replace them with the authorized provider ranges
and verify that the cluster CNI enforces NetworkPolicy. Where exact provider
CIDRs are unavailable, an egress gateway or CNI with FQDN policy can provide a
stronger destination boundary. Towel still protects the credential when the
agent can make independent unauthenticated network requests.

## Isolation checklist

- One Towel session per agent runtime or conversation.
- Vault, unlock input, and trusted grant inputs mounted only in Towel.
- Session manifest mounted only in Towel and its paired agent.
- Separate PID and root filesystem namespaces.
- Agent non-root, no privilege escalation, no `CAP_SYS_PTRACE` (prefer dropping
  all capabilities), and no host PID/network/filesystem mounts.
- Broker not published outside the shared native/container loopback.
- Egress constrained to DNS and authorized HTTPS destinations where the
  platform supports it.
- Narrow provider credential scope, low request budget, short expiry, and
  rotation/revocation owned by the surrounding control plane.
