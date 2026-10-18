# Credential isolation from VM root

Each SAW namespace runs a credential proxy beside its VM. Provider API keys stay
in Kubernetes Secrets mounted only into that proxy. The VM receives metadata
Secrets, a public proxy CA certificate, and nonsecret markers such as
`saw-cred.inference.api_key`. The gateway, supervisor, NemoClaw, and agents may
store a marker; they do not receive the provider's key.

This boundary addresses an attacker with root in a user's VM. It is distinct
from the sandbox policy boundary. VM root can still **use** a key while it
controls the VM by sending a marker to an endpoint bound to that key. It cannot
read the key from VM disks or the gateway database. Cluster administrators and
anyone who can read the namespace's provider Secret remain trusted.

```text
sandbox -- placeholder --> supervisor -- marker over CONNECT --> proxy pod
                                                           |        |
                                           bound HTTPS host |        +-- Secret API key
                                                           v
                                                   provider endpoint
```

## How a request is handled

The sandbox driver sends HTTPS traffic to the namespace proxy using
`https_proxy` and trusts its public CA using `proxy_ca_bundle`. The proxy
accepts CONNECT only for an allowlisted DNS hostname on port 443. It reads the
TLS SNI, refuses a mismatch with the CONNECT host, and splices traffic to
allowlisted hosts that have no credential binding. For a bound host it
terminates TLS, verifies that the HTTP Host matches SNI, replaces bound markers
in headers, decoded Basic authorization, path, and query, then verifies the
upstream's TLS certificate against the system roots. An unknown marker, marker
on the wrong host, missing Secret, or surviving marker gets a 502; the request
does not reach the provider. Logs contain method, host, redacted path, binding,
and status. They do not contain headers, query strings, bodies, or keys.

Bindings come from `credentialProxy.secrets` and the keyed provider profile
catalog. The Secret's `provider` metadata selects a permitted profile type;
its `url` adds a custom HTTPS host on port 443. A custom `http://` URL bypasses
the TLS proxy and would expose the marker to that endpoint. Use HTTPS for
keyed custom endpoints. The installer warns about HTTP URLs and refuses
custom HTTPS ports other than 443.

Provider key rotation changes the projected Secret file in the proxy pod. The
proxy reads it for each request, so no VM or proxy restart is needed. The
actual delay is the Vault/External Secrets sync and kubelet projection delay.

## Admin authority during apply

The gateway's CA key is generated in the runtime user's `/run/user/<uid>`
tmpfs. The first boot PKI script signs the server, a shared user client, and a
`CN=saw-relay, OU=openshell-user` certificate, then deletes the CA key before
the gateway starts. Only public certificates and nonadmin private keys remain
under `~/.local/state/openshell/tls`.

Each installer apply creates a separate admin CA in tmpfs and a one-day
`OU=openshell-admin` client certificate (trust ends earlier, when the run
removes the CA from the bundle). It temporarily appends that CA's
public certificate to `client-ca.pem`, waits for gateway TLS reload, runs the
CLI with a tmpfs `XDG_CONFIG_HOME`, and removes the CA from the bundle and the
tmpfs directory in `finally`. Forward and keepalive units use `saw-relay`,
which is a user member of each managed workspace. At boot and on install, the
installer resets `client-ca.pem` to the gateway CA to discard any stale admin
CA left by a crashed apply.

The admin private key does exist in tmpfs during an apply. Root in the VM
during that window can read or use it. The persistent shared client and relay
keys, gateway JWT signing key, and Podman supervisor secrets are also in VM
scope, but none carries platform admin mTLS authority. VM root can also edit
the gateway's trust bundle or processes and grant itself admin access while it
controls the VM. This design removes reusable admin signing material from
persistent storage; it does not make a compromised gateway trustworthy. Root
present during the brief first-boot PKI generation could observe the CA key
while it exists in tmpfs.

## Deployment and migration

Build and publish `credential-proxy/Containerfile`, then set
`credentialProxy.image` to the resulting **digest reference** (`...@sha256:...`).
The chart refuses an empty or tag-only image. `make saw-create` accepts
`CREDENTIAL_PROXY_IMAGE` or `SAW_VALUES_FILE` with that value. The proxy CA
hook creates a namespace CA Secret and its public ConfigMap before the VM and
proxy Deployment. The CA ConfigMap is a required VM disk.

Before a production rollout, verify the deployed OpenShell gateway accepts
`https_proxy`, `proxy_ca_bundle`, and `proxy_connect_by_hostname`; that the
supervisor accepts proxy-signed HTTP/1.1 TLS; and that OpenClaw and NemoClaw
accept and retain the marker. Also check client-CA reload, `saw-relay` workspace
access, and sandbox wiring labels against the cluster's exact OpenShell build.
The local test suite cannot establish these runtime compatibility facts.

Every provider Secret attached to an existing VM needs a metadata companion
named `<secret>-meta`. It must contain only nonsecret keys such as `provider`,
`model`, and `url`. The built-in `inference-meta` and `web-search-meta`
ExternalSecrets and quickstart path create these. For a custom Secret in
`additionalProviderSecrets`, create its companion and add its `{name,key,providers}`
binding to `credentialProxy.secrets`. The installer refuses a credential key
file found on a VM input disk or a provider without a binding.

An upgrade from the old layout rotates gateway PKI, removes persistent
`saw-installer` admin material, updates provider credentials to markers, and
recreates sandboxes whose egress wiring label changed. **Recreation wipes
`/sandbox`**. Users must fetch the new gateway CA (`make saw-configure` or
`scripts/extract-gateway-ca.sh`). Rotate every provider key that previously
reached a VM; old copies on copy-on-write storage cannot be reliably scrubbed.
Increasing `gatewayPki.generation` or changing the route host rotates the
gateway PKI and causes the same sandbox recreation.

## Rotation operations

- **Provider key:** update its Vault value or namespace Secret, wait for the
  ExternalSecret and projected volume to sync, then check proxy readiness and
  make an inference or search request. Revoke the old provider key after the
  new one works. The VM does not need a restart.
- **Proxy CA:** schedule a maintenance window. Remove the namespace
  `saw-credential-proxy-ca` Secret, then run a Helm upgrade or Argo sync so the
  `init-ca` hook creates a new Secret and refreshes `saw-proxy-ca`. Restart the
  proxy Deployment if its mounted CA does not update. Restart the VM so its
  required CA disk changes, then run install and apply; existing sandboxes are
  recreated because their egress wiring fingerprint changed. Verify the
  Deployment is ready and a provider request succeeds before ending the
  maintenance window. An ordinary upgrade keeps the existing proxy CA.
- **Gateway PKI:** increment `gatewayPki.generation` in values and upgrade
  the SAW. The installer rotates the gateway CA, server and relay identities,
  and recreates sandboxes. Users then fetch the new gateway CA with
  `make saw-configure` or `scripts/extract-gateway-ca.sh`.

## Failure modes and checks

| Event | Result |
| --- | --- |
| Proxy down or not ready | Provider calls fail; no VM key fallback exists. Calls recover when the proxy is ready. |
| Proxy CA Secret or ConfigMap missing | The required VM disk or installer check fails closed. |
| Vault or External Secrets unavailable | The last synced key remains usable; a missing mounted key makes the proxy unhealthy. |
| Key rotated | The projected key is read on the next request after sync. |
| Admin CA reload timeout | Apply fails and systemd can retry. |
| Crash during apply | The admin key disappears with tmpfs; the stale public CA is pruned on the next install or boot. |
| Route host or PKI generation changes | Gateway PKI rotates; sandboxes are recreated. |

Run `make test-credential-proxy` locally and
`make test-credential-isolation OPENSHELL_SAW_NAME=<name> SAW_NS=saw-<name>`
on a test SAW. For a live check, inspect `/var/lib/saw/status.json` for matching
proxy and PKI fingerprints, confirm the proxy `/healthz` endpoint, and run an
inference request from a sandbox. `SKIP_LIVE=1 tests/test-credential-isolation.sh`
runs only the offline render checks. The live script uses an SSH key already
authorized for the VM and restarts `saw-apply` to observe the temporary CA;
set `SKIP_APPLY=1` for read-only checks. Set `OLD_ADMIN_CERT` to a saved public
admin certificate to check that the old issuer is no longer trusted.
