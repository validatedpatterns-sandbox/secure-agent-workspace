# Secure Agent Workspace — End-to-End Deployment Guide

## Overview

The Secure Agent Workspace (SAW) deploys a per-user AI agent sandbox running inside a KubeVirt virtual machine on OpenShift. The deployment is fully GitOps-driven via Red Hat Validated Patterns and ArgoCD.

Each sandbox provides an OpenShell gateway with OIDC authentication, governance policy enforcement, and a web-based agent interface — all managed declaratively from Git.

## Architecture

```text
                         +-----------------------+
                         |  OpenShift Cluster     |
                         |                        |
   User (CLI/Browser)    |  +------------------+  |
         |               |  | Keycloak (OIDC)  |  |
         | OIDC login    |  +--------+---------+  |
         v               |           |             |
   +-----+------+        |  +--------v---------+  |
   | TLS Route  +------->|  | KubeVirt VM      |  |
   | (passthru) |        |  |  openshell-saw   |  |
   +------------+        |  |                  |  |
                         |  |  Gateway :17670  |  |
                         |  |  Dashboard :8080 |  |
                         |  |  Agent :18789    |  |
                         |  |  Docker sandboxes|  |
                         |  +--------+---------+  |
                         |           |             |
                         |  +--------v---------+  |
                         |  | Governance        |  |
                         |  | Interceptor :18081|  |
                         |  +------------------+  |
                         |                        |
                         |  +------------------+  |
                         |  | Vault + ESO      |  |
                         |  | (secrets)        |  |
                         |  +------------------+  |
                         +-----------------------+
```

## ArgoCD Applications

All applications are defined in `values-prod.yaml` and deployed by the Validated Patterns framework. ArgoCD syncs them automatically — dependencies are resolved at runtime via init containers and wait loops, not explicit ordering.

| Application | Namespace | Purpose |
| --- | --- | --- |
| `openshift-cnv` | `openshift-cnv` | KubeVirt operator for VM lifecycle |
| `vault` | `vault` | HashiCorp Vault for secret storage |
| `openshift-external-secrets` | `external-secrets` | External Secrets Operator |
| `saw-users` | `openshell-agents` | One namespace and three apps per user, from `overrides/saw-users.yaml` |
| `openshell-keycloak` | `saw-keycloak` | Keycloak OIDC provider + realm |
| `governance-policy` | `openshell-agents` | Policy ConfigMaps (profiles + sandbox policy) |
| `governance-interceptor` | `openshell-agents` | gRPC interceptor deployment |

**Operator Subscriptions:** OpenShift Virtualization, RHBK (Keycloak), External Secrets Operator, RHDH, OpenShift AI.

## Deployment Phases

### Phase 1: Golden VM Image

The `openshell-gateway-image` BuildConfig creates a Fedora 44 qcow2 image with:

- Podman by default (`containerRuntime: podman`), or Docker CE with `containerRuntime: docker`; plus Node.js, Python3, cloud-init, openssh, qemu-guest-agent. See [Container runtime support](container-runtime.md).
- `cloud-user` with sudo access (and the `docker` group only in the Docker variant)
- Systemd user service for the OpenShell gateway (`openshell-gateway.service`)
- First-boot setup service (`openshell-gateway-setup.service`) that starts the container runtime, enables the gateway, and configures mTLS certs

The image is pushed to an internal ImageStream (`openshell-gateway:latest`) and used as a DataSource for cloning VM disks.

Build trigger: `make build-gateway-docker` (Docker variant) or `make build-gateway-podman` (Podman variant), or automatically via ArgoCD.

### Phase 2: Keycloak + OIDC

RHBK operator deploys Keycloak. A `KeycloakRealmImport` creates the `openshell` realm with:

- **Clients:**
  - `openshell-cli` — public client, PKCE with S256, device code flow, 24h token lifetime
    (effective lifetime capped to 10h by the realm's SSO Session Max)
  - `openshell-dashboard` — public client, PKCE, redirect URIs registered by the redirect registrar or an administrator (below)
- **Users:** developer, admin, alice, bob (test accounts)
- **Roles:** `openshell-user`, `openshell-admin`
- **Token mappers:** realm roles in access tokens, audience mapper so dashboard tokens are accepted by the gateway

#### Web UI redirect URIs

Every web UI has its own route host (each VM's dashboard, and each sandbox UI route), and Keycloak matches redirect URIs exactly apart from a trailing wildcard, so each host has to be registered on `openshell-dashboard`. The routes to register are labelled `saw.redhat.com/oidc-redirect=true` in namespaces labelled `openshell.pattern/saw=true`; their redirect URI is `https://<host>/oauth2/callback` and their web origin `https://<host>`. No pod in a SAW namespace holds Keycloak credentials for it.

By default the redirect registrar registers them (`redirectRegistrar` in `openshell-keycloak`): one Deployment, `saw-redirect-registrar` in Keycloak's namespace, every 15 seconds adds the entries of routes it finds and removes those it added for routes that are gone from every SAW namespace. It keeps an entry while its route still exists (labelled or not), keeps entries it did not add (recorded in the client attribute `saw.redhat.com/managed-redirects`), and on its first run adopts the per-VM entries the prepare Jobs used to add. A failed route list removes nothing. It signs in as its own confidential client, `saw-redirect-registrar`, whose service account has only `manage-clients` in the OpenShell realm; its init container sets that client up with the operator's `<keycloak>-initial-admin` Secret and hands the client secret over in memory, so the registrar container never sees the master admin. It reads routes, namespaces and the ingress domain only, and reaches Keycloak in-cluster (`http://<keycloak>-service.<namespace>.svc:8080`; set `redirectRegistrar.keycloakUrl` for an existing Keycloak without HTTP, and `redirectRegistrar.adminSecret` for another admin Secret name). `manage-clients` still covers every client of the realm; Keycloak's fine-grained admin permissions could narrow it to `openshell-dashboard`.

With `redirectRegistrar.enabled: false`, nothing in the cluster holds Keycloak admin access for this: an administrator runs `make -f Makefile-quickstart keycloak-register KC_USER=<user>` once the workspace exists (it also creates the Keycloak account if it is new) and `keycloak-redirects-sync` after deleting workspaces (`scripts/keycloak-redirects.py`, with the administrator's `oc` session and Keycloak's admin Secret, like `scripts/keycloak-users.sh`). The script applies the registrar's rules. See the README's [Web UI sign-in](../README.md#web-ui-sign-in-redirect-uris).

### Phase 3: Secrets

ExternalSecret CRs pull from Vault:

| Secret | Vault Path | Content |
| --- | --- | --- |
| `openshell-aap-ssh` | `<prefix>/ssh` | SSH private key + public key |
| `openshell-ssh-pubkey` | `<prefix>/ssh` | SSH public key (for cloud-init) |
| `inference` | `<prefix>/inference` | Provider type, model, API key |
| `web-search` | `<prefix>/web-search` | Brave provider and API key |

`<prefix>` is `secret/data/hub` unless a user sets `vaultPrefix`. One shared hub key then serves every workspace. To give one person their own keys, put them in Vault at `secret/data/hub/saw-<user>/...` and set that user's `vaultPrefix` to `secret/data/hub/saw-<user>`. The `saw-users` chart reads the prefix; it does not create Vault entries. See the commented example in `values-secret.yaml.template`.

### Phase 4: Governance Policy

The `governance-policy` chart creates two ConfigMaps from files in the chart:

- `governance-interceptor-policy` — sandbox filesystem/process policy from `policy.yaml`
- `governance-interceptor-profiles` — all `profiles/*.yaml` auto-discovered via Helm glob

The `governance-interceptor` chart deploys the interceptor pod, which mounts both ConfigMaps and serves them over gRPC. See [governance-interceptor.md](governance-interceptor.md) for the full enforcement flow.

### Phase 5: VM Boot + In-guest installer

The VM boots from a clone of the golden image. Nothing logs in over SSH to install it. See [Versioned BOM installer](versioned-bom-installer.md).

#### Cloud-init

Cloud-init runs once and writes the static files: the mount script, the `saw-install` and `saw-apply` units, first-boot copies of `gateway.env` and `gateway.toml`, and (only when `vm.liveInputs` is true) the reconcile units. SSH keys are not in this Secret. KubeVirt `accessCredentials` writes `cloud-user`'s `authorized_keys` from the `<name>-ssh-pubkey` Secret.

#### Root disk

There is no prepare Job: nothing runs in the SAW's namespace but the VM. The VM's disk template makes its root disk once, when it does not exist: by default CDI imports the golden image from the internal registry (`<source.dataSourceNamespace>/openshell-gateway:latest`, from `make copy-images` or the image build) with `pullMethod: node`, so each node pulls the image once and caches it. Set `source.registryURL` to import another image (pin it by digest), `source.httpURL` (or the older `source.goldenImageURL`) to download a qcow2 over HTTP, or `source.dataSource` to clone a golden image DataSource that already exists. An `http://` or `https://` disk URL is added to the namespace egress firewall on its own host and port; a host already allowed on that port is not listed twice. Changing the source later does not change an existing VM's disk. Keycloak redirect URIs are registered by the redirect registrar in Keycloak's namespace, or by an administrator ([Web UI redirect URIs](#web-ui-redirect-uris)).

#### Guest

`saw-install` pulls each BOM component by digest and starts the gateway. `saw-apply` reads the mounted profiles and provider Secrets and creates workspaces, providers, and sandboxes, and attaches each sandbox's providers (OpenShell 0.1.x has no inference routes: agents call their provider's own endpoint). The default signature mode is `warn`. The default prune mode is `report` (log `would delete`, delete nothing). Inputs are iso9660 disks unless `vm.liveInputs` is true, in which case virtiofs updates them without a restart.

A workspace that stays Starting is usually waiting on a provider Secret. The virt-launcher pod is scheduled and sits in ContainerCreating; the kubelet retries the mount, so the VM boots within about 2 minutes of the Secret appearing.

```bash
oc get events -n saw-<user> | grep FailedMount
```

## Upgrading from the single-user layout

Before the `saw-users` chart, `values-prod.yaml` defined Alice's SAW directly:
the `saw-alice` namespace and the `openshell-saw`, `saw-bom` and
`pattern-secrets` applications (VM `openshell-saw`). Upgrading an existing
install does not remove them: the pattern's top-level application syncs
without pruning, so the old applications keep running next to the new
`saw-alice*` ones and both manage the same ExternalSecrets and ConfigMap in
`saw-alice`.

Remove the old applications **without cascading**. Every pattern application
carries the `resources-finalizer.argocd.argoproj.io/foreground` finalizer, so
a plain `oc delete application` would also delete the ExternalSecrets and the
`saw-bom-profiles` ConfigMap that the new applications now use.

```bash
ARGO_NS=vp-gitops   # the pattern's Argo CD namespace (global.vpArgoNamespace)
for app in openshell-saw saw-bom pattern-secrets; do
  oc -n "$ARGO_NS" patch application "$app" --type json \
    -p '[{"op":"remove","path":"/metadata/finalizers"}]'
  oc -n "$ARGO_NS" delete application "$app"
done
# The old VM and its disk are no longer managed; delete them.
oc -n saw-alice delete vm openshell-saw
oc -n saw-alice delete datavolume openshell-saw-root --ignore-not-found
```

The `saw-alice*` applications keep the shared objects in place (they self-heal
anything removed). Alice's new VM is `alice` in `saw-alice`: use
`OPENSHELL_SAW_NAME=alice`. Sandboxes and files inside the
old VM are not migrated; the new VM recreates the profile's workspaces and
sandboxes.

## Network Architecture

### Routes

| Route | Target Port | TLS | Purpose |
| --- | --- | --- | --- |
| `<name>-gateway` | 17670 | Passthrough | gRPC gateway (CLI + API) |
| `<name>-dashboard` | 18789 | Edge | OpenClaw agent web UI; the dashboard Route does not reach the OpenClaw UI on OpenShell 0.1.x, see [OpenClaw UI and the dashboard Route](#openclaw-ui-and-the-dashboard-route) |
| `<name>-webui` | 8080 | Edge | OpenShell Dashboard (via oauth2-proxy) |

### Egress from the VM

Each sandbox namespace has an `EgressFirewall` (`k8s.ovn.org/v1`, name `default`) rendered by the `openshell-saw` chart. It needs OVN-Kubernetes. On another network plugin the kind is unknown and the Argo CD sync fails. It is independent of OpenShell's sandbox allowlist: a process on the VM that skips the sandbox proxy still cannot open a connection to a host that is not listed.

The source of truth is `egress.allow` in [`charts/openshell-saw/values.yaml`](../charts/openshell-saw/values.yaml). That list includes the registries the VM pulls from and every exact host in [`charts/governance-policy/profiles/`](../charts/governance-policy/profiles/). A chart test fails if a shipped profile adds a host that is not on the firewall. The chart also allows the Keycloak route host taken from the OIDC issuer URL, using the URL's port (443 when the URL has none).

Node addresses are allowed only on TCP 6443, 443, and 80 (the API and the ingress router). Kubelet, SSH, and NodePorts are not. If the API or the ingress is a load balancer address rather than a node IP, this rule does not cover it. The Keycloak host is what the VM uses for login.

Everything else on the public internet is denied, for IPv4 and IPv6. Pods and services inside the cluster, including DNS, the governance interceptor, and the internal registry, are not filtered by this object.

Hostnames are exact. A name such as `*.quay.io` is rejected at render time, because matching a wildcard needs the `DNSNameResolver` feature gate. Gemini's `*-aiplatform.googleapis.com` cannot be written as a `dnsName` rule. Add the regional host you use under `extraAllow` (for example `us-central1-aiplatform.googleapis.com`).

Quay serves image layers from `cdn01.quay.io` through `cdn06.quay.io`. Those names are on the list. Their addresses change often, and OVN resolves them itself, which can disagree with the VM's own resolver. On cluster-mx8z2, `podman pull quay.io/quay/busybox` succeeded three times in a row and `https://cdn01.quay.io/` returned HTTP 403 (the name is reachable; Quay refuses a bare GET). `registry.npmjs.org` is on the list too, and from that same VM it still timed out: the guest resolved Cloudflare addresses that OVN had not installed for the name. Public NTP (UDP 123) is denied. The guest clock stays on kvm-clock; chrony will not see public pool servers. Harness images from ghcr.io and Sigstore (follow-up #53) are not on this list yet.

An external disk download (`source.httpURL`, or `source.goldenImageURL` / `source.registryURL` when it is `http://` or `https://`) is allowed automatically. A `docker://` image and the internal registry are not added. Any other host outside the cluster, including a custom inference endpoint, still has to be listed.

To let one deployment reach another host (an enterprise system, or a custom inference endpoint outside the cluster), add it in Git under `egress.extraAllow`. On the pattern path, set that under `defaults.openshellSaw` in [`charts/saw-users/values.yaml`](../charts/saw-users/values.yaml), or on one user. A host inside the cluster (`*.svc`) needs no entry.

```yaml
egress:
  extraAllow:
    - vllm.example.net
```

`egress.enabled: false` removes the firewall. Leave it on.

**Upgrading an existing sandbox.** The next sync turns this firewall on. A custom-inference URL that is outside the cluster lives only in Vault, so the chart cannot see it. Before upgrading, put that host in `egress.extraAllow`, or set `egress.enabled: false` on that user until you do. Calls to that URL time out. OpenShell does not report a policy denial.

### Internal Connectivity

| From | To | Protocol | Purpose |
| --- | --- | --- | --- |
| Gateway (VM) | Governance interceptor (pod) | gRPC over HTTP | Policy enforcement |
| Gateway (VM) | Keycloak (pod) | HTTPS | OIDC token validation |
| In-guest installer | mounted ConfigMaps and Secrets | virtiofs or iso9660 | Install binaries and apply profiles |
| Dashboard (VM) | Gateway (VM) | gRPC over TLS | Agent operations |

### Authentication Flows

- **CLI:** `openshell gateway login` uses the browser flow by default, or the OIDC device-code flow when `OPENSHELL_NO_BROWSER=1` is set, authenticating against Keycloak. The token is cached locally and sent as a bearer token on gRPC calls.
- **Dashboard:** OAuth2 proxy handles browser-based OIDC login, proxies authenticated requests to the dashboard backend, which connects to the gateway.
- **In-guest installer:** its own mTLS client certificate, `CN=saw-installer` and `OU=openshell-admin`, registered as the `saw-installer` gateway entry. Users still use OIDC.

## Operator Quick Reference

### Prerequisites

```bash
make check-prereqs          # Verify operators and CLI tools
```

### Initial Setup

```bash
make generate-keys           # Create SSH keypair
make ssh-secret              # Create Kubernetes secrets from keys
make build-gateway-docker    # Build Docker golden VM image (or: make copy-images)
make keycloak                # Deploy Keycloak (if not via ArgoCD)
```

### Sandbox Lifecycle

```bash
# Create
make openshell-saw-create OPENSHELL_SAW_NAME=my-saw

# Access — NemoClaw sandbox
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=cuda-sandbox make nemoclaw-tui
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=cuda-sandbox GUI_PORT=18789 make nemoclaw-gui

# Access — OpenClaw sandbox
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=notebook make openclaw-tui
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=notebook GUI_PORT=18790 make openclaw-gui

# SSH into a sandbox
make openshell-saw-ssh OPENSHELL_SAW_NAME=my-saw
make login OPENSHELL_SAW_NAME=my-saw

# Monitor
make openshell-saw-list
make openshell-saw-logs OPENSHELL_SAW_NAME=my-saw
make status

# Delete
make openshell-saw-delete OPENSHELL_SAW_NAME=my-saw
make delete-all              # Remove everything
```

### Governance

```bash
make governance-demo OPENSHELL_SAW_NAME=my-saw
make governance-list-profiles OPENSHELL_SAW_NAME=my-saw
make governance-add-profile OPENSHELL_SAW_NAME=my-saw PROFILE_NAME=github
make governance-remove-profile OPENSHELL_SAW_NAME=my-saw PROFILE_NAME=github
make governance-create-profile OPENSHELL_SAW_NAME=my-saw \
  PROFILE_NAME=jira PROFILE_FILE=/path/to/jira.yaml
```

The `add`, `remove`, and `create` targets edit `charts/governance-policy/profiles/`, commit, and run `git push origin HEAD`, then wait for Argo CD to sync the `governance-policy` application. On the quickstart path, where governance-policy is installed with Helm rather than Argo CD, edit the profiles and re-run `helm upgrade --install governance-policy charts/governance-policy --namespace openshell-agents` instead. `OPENSHELL_SAW_NAME` selects the gateway that `governance-list-profiles` queries (default `openshell-saw`). See [governance-interceptor.md](governance-interceptor.md#applying-profile-changes).

### Testing

```bash
make test                    # Headless E2E test
```

## Quickstart notes

### Operators for the quickstart

The quickstart installs operators from OperatorHub. OpenShift Virtualization needs one extra resource: after its operator is running, create a `HyperConverged` so the operator deploys the virtualization components and a node can run VMs. Option A (the validated pattern) creates this for you; the quickstart does not.

```yaml
apiVersion: hco.kubevirt.io/v1beta1
kind: HyperConverged
metadata:
  name: kubevirt-hyperconverged
  namespace: openshift-cnv
spec: {}
```

External Secrets is only required for Option A, which syncs the pattern's secrets from Vault; the quickstart sets its secrets directly and does not use it.

### Golden image tag

`make copy-images` mirrors the prebuilt images into the cluster. For each image it tries the `OPENSHELL_VERSION` tag first, then `v<version>`, and finally falls back to the `latest` tag, using the first that exists and storing it under the requested version (it also tags the result `latest`). If the golden image predates bundle signing, as the prebuilt images do, it ships no `verify-bundle`, so `saw-stage-installer` stages the installer tree without verification; the default signing mode `warn` still boots the VM, while `enforce` would refuse.

### OpenClaw UI and the dashboard Route

The `<name>-dashboard` Route forwards to the gateway Service on VM port 18789, but OpenClaw listens inside the sandbox container, which on OpenShell 0.1.x runs in its own network namespace with only loopback (network mode `none`, no port mappings). The Route therefore does not reach the OpenClaw UI and answers 503. Each sandbox has its own namespace, so several OpenClaw sandboxes all listen on 18789 without conflict.

On the pattern path (Option A, including workspaces created in the self-service portal), a sandbox whose profile sets `ui: {route: true}` gets its own Route instead, `<user>-<workspace>-<sandbox>-ui.apps.<domain>`, signed in through Keycloak and open only to the workspace owner. It reaches OpenClaw through `openshell forward`, so it works on 0.1.x; see [Opening a sandbox UI](rhdh-architecture.md#opening-a-sandbox-ui). On the quickstart path (Option B) no such Routes are created: use `make openclaw-gui` (or `make nemoclaw-gui`), which port-forwards to the sandbox UI.

### Web search in the default sandbox

The `notebook` sandbox attaches only the NVIDIA provider, and its policy allows only that provider's endpoints, so the agent's web search and web fetch calls fail. Attaching the `brave` provider to the sandbox in the BOM profile (`charts/saw-bom/profiles/data-science/default/sandbox.yaml`) opens its endpoints; note that the default profile already creates a `brave` provider but attaches it to no sandbox, which is why step 11 still needs `WEB_SEARCH_API_KEY`. A live walkthrough also saw OpenClaw's own SSRF guard reject the sandbox's synthetic DNS answers, so enabling web search may take more than the provider change.

### Shell access

`openshell sandbox connect` attaches to the sandbox's main process. In SAW sandboxes that process is `sleep infinity`, started without a terminal, so `connect` shows nothing. To get an interactive shell, use `openshell sandbox exec`:

```bash
openshell sandbox exec -n notebook -- sh
openshell sandbox exec -n cuda-sandbox --workspace cuda-dev -- sh
```
