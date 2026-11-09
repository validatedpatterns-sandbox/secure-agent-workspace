# Credential isolation from VM root

## Credential modes

`credentialProxy.enabled: true` is the default. Provider keys and Gmail OAuth
material stay in the namespace proxy, outside the VM. The VM receives only
metadata, markers and the public proxy CA. The proxy boundary described below
applies to this mode.

`credentialProxy.enabled: false` selects **direct mode**. Full provider Secrets
are mounted into the VM and OpenShell receives real keys. VM root can read
those keys and Gmail refresh material. No proxy Deployment, Service, policy,
metadata Secret or proxy CA is needed. Custom HTTP and HTTPS endpoints on
other ports are accepted by the installer; their ports and destinations must
also be allowed by the deployment's egress policies.

Both modes keep the tmpfs gateway CA, per-apply temporary admin identity,
nonadmin `saw-relay`, and gateway-CA sandbox recovery. Optional web search,
named credentials, official OpenAI/Anthropic providers, sandbox recovery,
ingress-CA trust and daily-briefing thread replies work in both modes.

Set the default in `overrides/saw-users.yaml`:

```yaml
defaults:
  openshellSaw:
    credentialProxy:
      enabled: false
```

A user's `values.credentialProxy.enabled` overrides that default. The portal
inherits the same defaults. The chart pins the published proxy image; an image
override is optional.
Quickstart accepts `CREDENTIAL_PROXY_ENABLED=false` or the same setting in
`SAW_VALUES_FILE`; the environment variable takes precedence.

The NVIDIA [Security and Governance Model](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)
requires credential mediation outside the agent process, and outside the guest
where controls must survive guest compromise. Proxy mode provides that external
placement. Direct mode provides agent-process isolation only; use proxy mode
where the guest-compromise threat model applies. See the
[per-mode reference mapping](architecture-alignment.md#6-secret-management)
for provider scope, lifetime, audit, revocation and residual guest-root access.

## Switching modes

1. Change the value and sync Argo CD (or rerun quickstart).
2. Run `make saw-restart-pending` to review the VMs, then
   `make saw-restart-pending CONFIRM=yes`. A live config update alone does not
   swap the booted volume sources. Until restart, install/apply/validate refuse
   with a configured/booted credential-mode mismatch before changing the gateway.
3. Watch `make saw-logs OPENSHELL_SAW_NAME=<user>` and
   `make saw-status OPENSHELL_SAW_NAME=<user>`. Wait for `apply: Done` and the
   expected `credentialMode.applied`.

Mode migrations archive `/sandbox` from the workload volume before provider
updates, then recreate managed sandboxes and restore and verify their files.
They preserve the daily briefing store too. Failed archives leave the original
sandbox intact; failed provider updates stop the migration. A pending restore
keeps the old proxy CA files until all managed sandboxes have migrated.
User-created, unmanaged sandboxes must be recreated by their owners.

The VM keeps its `saw-proxy-ca` disk/virtiofs slot in direct mode, backed by
`<release>-credential-mode`, whose only data is `mode: direct`. This compatibility
shim has no CA or Service URL: cloud-init mount helpers baked into existing
VM root disks require the slot and are never refreshed by a chart upgrade.

**Proxy to direct:** the gateway config drops all proxy settings. The installer
archives sandboxes, replaces markers with real keys, configures gateway Gmail
refresh, and restores the sandboxes. Only after a clean apply does root delete
both proxy CA files. Per-user Argo apps self-heal but never prune; after the VM
reports direct mode as Done, delete the GitOps leftovers:

```bash
oc -n saw-<u> delete deploy/<u>-credential-proxy svc/<u>-credential-proxy cm/<u>-credential-proxy-config \
  sa/<u>-credential-proxy networkpolicy/saw-credential-proxy secret/saw-credential-proxy-ca cm/saw-proxy-ca \
  --ignore-not-found
# data-science:
oc -n saw-<u> delete externalsecret,secret inference-meta web-search-meta --ignore-not-found
# personal-assistant:
oc -n saw-<u> delete externalsecret,secret inference-meta slack-meta gmail-meta --ignore-not-found
# Remove any remaining CA hook resources as well:
oc -n saw-<u> delete sa,role,rolebinding,networkpolicy saw-credential-proxy-ca-hook --ignore-not-found
```

Quickstart deletes stale metadata Secrets and CA objects after Helm upgrades;
Helm prunes the other resources. Check the direct isolation test after the
migration. When using Helm alone with `cleanupOnDelete=false`, a direct to
proxy flip may need the EgressFirewall API exception applied first: Helm's
pre-upgrade CA hook runs before the firewall update. Argo CD applies the
firewall at wave -30 before its Sync hook.

**Direct to proxy:** proxy health is a migration precondition. Root deletes
`~/.nemoclaw/credentials.json`; managed sandboxes are archived, gateway Gmail
refresh metadata is deleted, and provider keys become markers. After restore
and the final health check the applied mode becomes proxy. The old
`<release>-credential-mode` ConfigMap may remain; it is harmless and can be deleted.

**Key rotation is required after direct to proxy.** The root-owned
`/var/lib/saw/credential-mode.json` records exposed Secret/key names, never
values. Every apply logs a WARN and reports `rotationRequired` until
`credentialProxy.keyGeneration` exceeds the generation recorded at transition.
Revoke the exposed credentials at Google, Slack and NVIDIA, update their Vault
entries and load/sync Secrets, then bump `keyGeneration` (default 1). The
counter is an operator acknowledgement of rotation, not proof of revocation.


In proxy mode, each SAW namespace runs a credential proxy beside its VM. Provider API keys stay
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
does not reach the provider. Both intercepted and spliced connections resolve
the destination once per dial, reject private, loopback, link-local, special-use
and configured cluster CIDRs, then dial the checked IP. Configure the live
cluster/service CIDRs even when VM-wide NetworkPolicy is staged off, especially
on clusters using publicly numbered internal ranges.

The proxy removes `Forwarded` and `X-Forwarded-*`, and inspects upstream status,
headers and response bytes for bound static keys and access tokens minted for
that request, including common URL, JSON and base64 representations. It rejects
compressed responses and protocol upgrades on bound hosts, suppresses
informational responses, strips trailers, and replaces upstream error bodies.
An initial reflection produces a sanitized 502. A later streaming reflection
terminates the response; HTTP status may already have been sent. A streaming
filter retains possible token prefixes across reads without buffering the
whole response. This is regression-tested byte-pattern enforcement, not a
formal proof against arbitrary upstream transformations or partial disclosure.
Logs contain the trusted host, binding and status. Request methods, paths,
headers, query strings and bodies are omitted.

Proxy ingress always has a NetworkPolicy permitting port 3128 only from gateway
pods in the same namespace, including when `networkPolicy.enabled: false`.
VM-wide segmentation and proxy egress rules still follow that switch. Health
listens on pod loopback only and is checked by an exec readiness probe; neither
the Service nor VM policy exposes 8081. Installer preflight checks readiness
through a rejected reserved CONNECT target on 3128.

The namespace-wide EgressFirewall permits direct VM connections to allowlisted
provider hosts. It does not force every provider connection through the proxy.
Those direct connections have no provider key in proxy mode. VM root retains
authority to use a bound key through the proxy; credential custody does not
provide per-task authorization or revoke previously accepted provider actions.

Bindings come from `credentialProxy.secrets` and the keyed provider profile
catalog. The Secret's `provider` metadata selects a permitted profile type;
its `url` adds a custom HTTPS host on port 443. A custom `http://` URL bypasses
the TLS proxy and would expose the marker to that endpoint. Use HTTPS for
keyed custom endpoints. The installer warns about HTTP URLs and refuses
custom HTTPS ports other than 443.

Provider key rotation changes the projected Secret file in the proxy pod. The
proxy reads it for each request, so no VM or proxy restart is needed. The
actual delay is the Vault/External Secrets sync and kubelet projection delay.
The 15-second ESO refresh interval is not an end-to-end revocation bound.
Measure propagation on the deployed cluster, including existing tunnels and
OAuth caches. Provider-side revocation is a separate operation.

New proxy CAs expire after one year, cannot issue intermediate CAs, and carry
critical DNS constraints derived from configured egress hosts (wildcards use
their parent DNS suffix). IP certificates are excluded. The public CA is copied
to the gateway driver's explicit bundle, not installed in the system trust
store. Existing CAs are preserved on upgrade: rotate them during the documented
maintenance procedure to adopt new constraints or changed allowed suffixes.

## Admin authority during apply

The gateway's CA key is generated in the runtime user's `/run/user/<uid>`
tmpfs. The first boot PKI script signs the server, a shared user client, and a
`CN=saw-relay, OU=openshell-user` certificate, then deletes the CA key before
the gateway starts. Only public certificates and nonadmin private keys remain
under `~/.local/state/openshell/tls`.
The separate `jwt/` Ed25519 signing bundle generated by `rhaiv.6` remains
there for sandbox launch authentication, with its private key restricted to
mode `0600`. It does not sign mTLS client certificates.

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

The chart ships the published multi-architecture image digest built by
`.github/workflows/credential-proxy.yml` from `credential-proxy/`. Proxy mode
needs no image override. For a mirror or custom build, set
`defaults.openshellSaw.credentialProxy.image` in `overrides/saw-users.yaml`;
the override must be `repo@sha256:<index digest>` for a multi-arch image.
Explicit empty and tag-only chart values are refused. `make saw-create`
optionally accepts `CREDENTIAL_PROXY_IMAGE` or `credentialProxy.image` in
`SAW_VALUES_FILE`; with neither override supplied, quickstart uses the
chart default. An explicit empty image in the values file still fails Helm. See [Container images](container-images.md#releasing-a-credential-proxy-change)
for the release and mirror commands. The proxy CA hook creates a namespace
CA Secret and its public ConfigMap before the VM and proxy Deployment. The
CA ConfigMap is a required VM disk in proxy mode.

Before a production rollout, verify the deployed OpenShell gateway accepts
`https_proxy`, `proxy_ca_bundle`, and `proxy_connect_by_hostname`; that the
supervisor accepts proxy-signed HTTP/1.1 TLS; and that OpenClaw and NemoClaw
accept and retain the marker. Also check client-CA reload, `saw-relay` workspace
access, and sandbox wiring labels against the cluster's exact OpenShell build.
The local test suite cannot establish these runtime compatibility facts.

Every provider Secret attached to an existing VM needs a metadata companion
named `<secret>-meta`. It must contain only nonsecret keys such as `provider`,
`model`, `cuda_model`, and `url`. The pattern-secrets ExternalSecrets and
quickstart path create these. For a custom Secret in
`additionalProviderSecrets`, add its `{name,key,providers}`
binding to `credentialProxy.secrets`. The installer refuses a credential key
file found on a VM input disk or a provider without a binding.

An upgrade from the old layout rotates gateway PKI, removes persistent
`saw-installer` admin material, updates provider credentials to markers, and
recreates sandboxes whose gateway CA changed. Before deletion, the installer
archives `/sandbox` from the workload's podman volume and verifies the archive,
then restores the files into the replacement. An unavailable or failed archive
stops migration without deleting the sandbox. Interrupted migrations resume
from the volume even when the old supervisor cannot reach the rotated gateway.
Argo applies the API firewall exception before running the CA bootstrap hook.
The installer also mounts the newly attached public CA input when an existing
VM still has the old cloud-init mount helper.
Users must fetch the new gateway CA (`make saw-configure` or
`scripts/extract-gateway-ca.sh`). Rotate every provider key that previously
reached a VM; old copies on copy-on-write storage cannot be reliably scrubbed.
Increasing `gatewayPki.generation` or changing the route host rotates the
gateway PKI and causes the same sandbox recreation.

## Typed provider config (#135)

- Every named credential maps to a distinct `saw-cred.<secret>.<key>` marker
  and requires its own `credentialProxy.secrets` binding. Any credential key
  found on a VM input disk, including a named key or symlink, is refused.
- `saw-users` derives `metaKeys` from every selected catalog field whose kind
  is not `secret`, plus optional `provider`. The metadata projection therefore
  retains fields such as `cuda_model` while excluding credential keys.
  Quickstart uses the same allowlist: `provider` plus selected profiles'
  nonsecret catalog fields, or `provider`, `model`, `url` for an unlisted
  Secret. Bound keys and `api_key` are excluded in every case.
- A shared Secret can omit `provider`. Its cluster-owned binding then permits
  the union of the listed types' hosts, plus the Secret's HTTPS `url` host.
  Setting `provider` narrows that union to the selected type's hosts.
- Deployment-owned profiles are not yet in the proxy's shipped host map.
  Their keyed sandbox endpoint must reference the credential Secret's `url`
  key; the proxy binds only that URL's host. Keyed endpoints require HTTPS
  port 443 and publicly trusted TLS. Other ports and service-CA trust remain
  follow-up work. Plain HTTP bypasses key injection and sends a marker, so
  it is suitable only for keyless endpoints.
- `saw.redhat.com/egress-wiring` tracks the proxy URL/CA. Changes use #135's
  archive/restore migration to preserve `/sandbox`, as environment changes do.
  Restore preserves file contents and modes. Ownership follows the new
  sandbox user (the archive is normalized before upload). Read-only image
  files are kept in place and verified.
  `saw.redhat.com/gateway-ca` separately tracks gateway trust: missing or
  changed gateway trust archives `/sandbox` from the workload volume before
  recreation, because the old supervisor cannot connect to serve an archive.
  Archive failures leave the original sandbox and files intact.
- In direct mode Gmail uses `openshell provider refresh configure` followed by
  `rotate` on the gateway. Material is passed through environment variables,
  never argv; only a digest is saved in mode-0600 `user/refresh.json`. A static
  access token without complete material is accepted with a WARN. Missing both
  is refused. Configure failures stop apply; failed initial rotation is retried
  on the next apply. `oauth2.googleapis.com` must remain in `egress.allow`.
- In proxy mode Gmail OAuth2 refresh runs in the namespace credential proxy. A binding
  with `refresh: true` gets its token URL only from the shipped provider
  profile, never from a Secret, Vault or the VM: a tenant-controlled URL
  could redirect the client secret. The proxy reads `client_id`,
  `client_secret`, and `refresh_token`, caches access tokens in memory, and
  refreshes five minutes before expiry. Material keys never get their own
  marker or binding. The VM receives only `saw-cred.gmail.access_token`.
  Readiness checks material presence without making token requests. A transient
  failure (network error, timeout, HTTP 429/5xx, `temporarily_unavailable`, or
  `server_error`) during early refresh keeps serving the cached token until it
  actually expires and retries every 60 seconds. An authorization failure
  (`invalid_grant`, `invalid_client`, and related permanent errors) drops the
  token at once and returns a sanitized 502. Static Slack and inference
  bindings continue working either way.
- Slack uses a static bot token. Slack rotating refresh tokens are unsupported:
  persisting their rotation back to Vault requires a separate implementation.
- Google OAuth clients in **Testing** issue refresh tokens that expire after
  seven days for Gmail scopes. Use an **In production** client (internal
  where appropriate) for longer deployments. See [Google's token expiration
  rules](https://developers.google.com/identity/protocols/oauth2#expiration).

Pattern E2E mounts `registry.authSecret` unchanged: a four-hour
`registry-viewer` token for `openshell-agents`, readable by VM root. This
CI-only pull token is outside the guarantee for provider API keys and
platform-admin mTLS authority. It must use a dedicated Secret.

The Pattern passes `overrides/saw-users.yaml` to both `saw-users` and the
portal chart. Its `defaults` (including the proxy image pin) apply to portal
workspaces as well as Git-listed users. Explicit `sawUsers.defaults` in the
portal chart takes precedence when a separate portal override is needed.

## Rotation operations

- **Provider key:** update its Vault value or namespace Secret, wait for the
  ExternalSecret and projected volume to sync, then check proxy readiness and
  make an inference or search request. Revoke the old provider key after the
  new one works. The VM does not need a restart.
- **Gmail OAuth material:** revoke access at Google, or change the user's
  Vault entry. ESO updates the mounted Secret and the broker discards its
  cached token and any in-memory rotated refresh token when material changes.
  Tokens remain only in memory; a proxy restart mints a fresh access token.
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

A configured/booted mode mismatch means a restart is pending; use
`make saw-restart-pending CONFIRM=yes`. A direct-mode missing key in a metadata
directory has the same hint. `rotationRequired` means exposed credentials must
be revoked and replaced before increasing `credentialProxy.keyGeneration`.
A direct-mode Gmail configure failure requires checking the gateway refresh
interface and governance engine; direct-mode APF refresh is refused in
preflight when the live profile lacks gateway refresh metadata.


| Event | Result |
| --- | --- |
| Proxy down or not ready | Provider calls fail; no VM key fallback exists. Calls recover when the proxy is ready. |
| Proxy CA Secret or ConfigMap missing | The required VM disk or installer check fails closed. |
| Vault or External Secrets unavailable | The last synced key remains usable; a missing mounted key makes the proxy unhealthy. |
| Key rotated | The projected key is read on the next request after sync. |
| Admin CA reload timeout | Apply fails and systemd can retry. |
| Crash during apply | The admin key disappears with tmpfs; the stale public CA is pruned on the next install or boot. |
| Route host or PKI generation changes | Gateway PKI rotates; sandboxes are recreated after a verified `/sandbox` volume archive. |

Run `make test-credential-proxy` locally and
`make test-credential-isolation OPENSHELL_SAW_NAME=<name> SAW_NS=saw-<name>`
on a test SAW. For a live check, inspect `/var/lib/saw/status.json` for matching
proxy and PKI fingerprints, confirm the proxy `/healthz` endpoint, and run an
inference request from a sandbox. `SKIP_LIVE=1 tests/test-credential-isolation.sh`
runs only the offline render checks. The live script uses an SSH key already
authorized for the VM and restarts `saw-apply` to observe the temporary CA;
set `SKIP_APPLY=1` for read-only checks. Set `OLD_ADMIN_CERT` to a saved public
admin certificate to check that the old issuer is no longer trusted.
