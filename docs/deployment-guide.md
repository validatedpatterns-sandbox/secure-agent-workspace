# Secure Agent Workspace — End-to-End Deployment Guide

## Overview

The Secure Agent Workspace (SAW) deploys a per-user AI agent sandbox running inside a KubeVirt virtual machine on OpenShift. The deployment is fully GitOps-driven via Red Hat Validated Patterns and ArgoCD. For Alice and Bob test account passwords and separate browser sign-in steps, see [Keycloak test users](../README.md#keycloak-test-users).

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

The image is pushed to an internal ImageStream (`openshell-gateway:latest`). CDI imports it into each VM disk by default. A DataSource can be used for cloning instead.

Build trigger: `make gateway-build-docker` (Docker variant) or `make gateway-build-podman` (Podman variant), or automatically via ArgoCD.

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

The VM boots from a disk imported from the golden image. Nothing logs in over SSH to install it. See [Versioned BOM installer](versioned-bom-installer.md).

#### Cloud-init

Cloud-init runs once and writes the static files: the mount script, the `saw-install` and `saw-apply` units, first-boot copies of `gateway.env` and `gateway.toml`, and (only when `vm.liveInputs` is true) the reconcile units. SSH keys are not in this Secret. KubeVirt `accessCredentials` writes `cloud-user`'s `authorized_keys` from the `<name>-ssh-pubkey` Secret.

#### Root disk

There is no prepare Job: nothing runs in the SAW's namespace but the VM. The VM's disk template makes its root disk once, when it does not exist: by default CDI imports the golden image from the internal registry (`<source.dataSourceNamespace>/openshell-gateway:latest`, from `make images-mirror` or the image build) with `pullMethod: node`, so each node pulls the image once and caches it. Set `source.registryURL` to import another image (pin it by digest), or `source.dataSource` to clone a golden image DataSource that already exists. Changing the source later does not change an existing VM's disk. Keycloak redirect URIs are registered by the redirect registrar in Keycloak's namespace, or by an administrator ([Web UI redirect URIs](#web-ui-redirect-uris)).

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
make quickstart-prereqs-check # Verify operators and the CLI version against the gateway BOM
```

### Initial Setup

```bash
make ssh-key-generate           # Create SSH keypair
make images-mirror               # Mirror the prebuilt golden image
make gateway-build               # Or build with CONTAINER_RUNTIME=podman|docker
make keycloak-deploy             # Deploy Keycloak (if not via Argo CD)
make governance-deploy           # Deploy governance policy and interceptor
```

### Sandbox Lifecycle

```bash
# Create
make saw-create OPENSHELL_SAW_NAME=my-saw

# Access — NemoClaw sandbox
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=cuda-sandbox make nemoclaw-tui
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=cuda-sandbox GUI_PORT=18789 make nemoclaw-gui

# Access — OpenClaw sandbox
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=notebook make openclaw-tui
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=notebook GUI_PORT=18790 make openclaw-gui

# SSH into a sandbox
make saw-ssh OPENSHELL_SAW_NAME=my-saw
make login OPENSHELL_SAW_NAME=my-saw

# Monitor
make saw-list
make saw-logs OPENSHELL_SAW_NAME=my-saw
make status

# Delete
make saw-delete OPENSHELL_SAW_NAME=my-saw
make quickstart-delete              # Remove Keycloak and image releases after SAWs
```

### Governance

```bash
make governance-demo OPENSHELL_SAW_NAME=my-saw
make governance-profile-list OPENSHELL_SAW_NAME=my-saw
make governance-profile-add OPENSHELL_SAW_NAME=my-saw PROFILE_NAME=github
make governance-profile-remove OPENSHELL_SAW_NAME=my-saw PROFILE_NAME=github
make governance-profile-create OPENSHELL_SAW_NAME=my-saw \
  PROFILE_NAME=jira PROFILE_FILE=/path/to/jira.yaml
```

The `add`, `remove`, and `create` targets edit `charts/governance-policy/profiles/`, commit, and run `git push origin HEAD`, then wait for Argo CD to sync the `governance-policy` application. On the quickstart path, where governance-policy is installed with Helm rather than Argo CD, edit the profiles and re-run `make governance-deploy` instead. `governance-profile-list` lists repository profiles when no SAW name is set. Set `OPENSHELL_SAW_NAME` to query a gateway or to change a profile. See [governance-interceptor.md](governance-interceptor.md#applying-profile-changes).

### Testing

```bash
make lint                   # Lint all 13 charts
make test                   # Run local Python tests through uv
make test-deployment        # Run the dedicated live-cluster test
```

### Live deployment test

Run this test only after the file changes are reviewed and the exact tested
commit is pushed. Use a dedicated OpenShift cluster. The runner checks the
current `oc` context and the pushed commit before it changes cluster state.
It requires a new manual SAW name and a separate token directory for a
second user. The pattern SAW name must match a user in
`overrides/saw-users.yaml`. Do not use a production namespace.

Set `TEST_CLUSTER_CONTEXT` to the result of `oc config current-context`.
Set `TEST_OWNER_SUBJECT` to the test owner's OIDC subject. Set
`TEST_SECOND_TOKEN_DIR` to a different local directory that already has a
second user's `token.json`. Keep credentials in files or environment
variables; do not add them to a command line. The data-science profile
needs `WEB_SEARCH_API_KEY`. The pattern also needs its inference and
web-search keys in Vault before the test. For example:

```bash
export TEST_CLUSTER_CONTEXT=<dedicated-oc-context>
export TEST_SAW_NAME=review-01
export TEST_PATTERN_SAW_NAME=alice
export TEST_OWNER=alice
export TEST_OWNER_SUBJECT=<alice-oidc-subject>
export TEST_SECOND_TOKEN_DIR=<second-user-token-directory>
export TARGET_BRANCH=<pushed-test-branch>
export TARGET_ORIGIN=origin
export PROVIDER=build
export MODEL=nvidia/nemotron-3-super-120b-a12b
read -r API_KEY < "$HOME/.nvidia-api-key"
export API_KEY
read -r WEB_SEARCH_API_KEY < "$HOME/.web-search-api-key"
export WEB_SEARCH_API_KEY
export TEST_INFERENCE_CHECK=/absolute/path/check-inference.sh
export TEST_OWNER_ACCESS_CHECK=/absolute/path/check-owner-access.sh
export TEST_SECOND_USER_DENIED_CHECK=/absolute/path/check-second-user-denied.sh
make test-deployment
unset API_KEY WEB_SEARCH_API_KEY
```

Each check must be an executable script that sends a real request and
verifies the response. The runner sets `TEST_ACTIVE_SAW_NAME` and
`TEST_ACTIVE_SAW_NS` for each manual or pattern SAW. It also passes the
owner's `OIDC_TOKEN_DIR` and `TEST_SECOND_TOKEN_DIR`. The inference check
must return a JSON object such as `{"result":"accepted","status_code":200}`.
The owner check must return `{"result":"allowed","status_code":200}`.
The second-user check must return `{"result":"denied","status_code":403}`.
Return a nonzero exit code when a request fails. Do not print tokens or
response bodies. The runner records the status code and a SHA-256 hash of
the output. These checks are required; a typed confirmation cannot replace
them.

The runner checks prerequisites, creates or recovers keys, mirrors the
gateway image, deploys Keycloak and governance, signs in, creates a SAW,
and waits up to 2400 seconds for both installer phases to be `Done`.
It exercises `saw-list`, `saw-status`, `saw-configure`, VM SSH, and a
deprecated alias. A person verifies logs, sandbox SSH, TUI, and GUI.
Enter `yes` after each interactive check passes. The three executable
checks send an inference request, verify owner access, and verify denial
for the second user. Each must return the expected status code. A failed
check stops the runner with a nonzero exit code.

The runner repeats setup and checks that credentials and Helm release
counts stay stable. It deletes the manual SAW twice, then installs the
Validated Pattern through `pattern.sh`, checks Argo CD health and installer
status, uninstalls twice, and reinstalls. Argo CD must report the tested
commit as the synced revision for all three user applications. The default
`pruneOnRemove: false` leaves the user namespace after pattern uninstall.
The runner verifies the pattern ownership labels, checks that the VM is
gone, then deletes only that test namespace. It mirrors the gateway image
again before reinstall because Pattern uninstall removes the managed image
stream. It performs a final uninstall
and cleanup after the reinstall. It records ISO 8601 timestamps,
commit SHA, cluster context, component versions, initial resource state,
check names, and exit codes in a local TSV
file under `local-docs/`. The runner creates this directory when needed.
If a check fails, it attempts cleanup of resources that it created and
records cleanup results.

If a step fails, keep the evidence file and inspect the reported resource.
Fix the fault, use a new manual SAW name when needed, and rerun the affected
checks. A mock or local test result does not replace this live test.

## Quickstart notes

### Operators for the quickstart

The quickstart installs operators from OperatorHub. OpenShift Virtualization needs one extra resource: after its operator is running, create a `HyperConverged` so the operator deploys the virtualization components and a node can run VMs. Option A (the validated pattern) creates this for you; the quickstart does not.

With local Keycloak, `make saw-create` reads the selected SAW-BOM profiles
and creates an owner-restricted Route for each enabled sandbox with
`ui.route: true`. It sets the cluster domain from OpenShift ingress so the
VM's proxy can use the assigned host. Run `make sandbox-ui` after the
installer reaches `Done` to list these routes. An external OIDC issuer needs
its own redirect registration, so the quickstart does not create these
routes for that mode.

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

`make images-mirror` mirrors the prebuilt images into the cluster. For each image it tries the `OPENSHELL_VERSION` tag first, then `v<version>`, and finally falls back to the `latest` tag, using the first that exists and storing it under the requested version (it also tags the result `latest`). If the golden image predates bundle signing, as the prebuilt images do, it ships no `verify-bundle`, so `saw-stage-installer` stages the installer tree without verification; the default signing mode `warn` still boots the VM, while `enforce` would refuse.

`OPENSHELL_VERSION` defaults to `0.0.116` and selects a prebuilt gateway
disk image tag. The `openshell-saw` chart has a separate in-VM BOM that
pins OpenShell `0.1.2-rhaiv.0` images by digest. Changing a mirror tag does
not upgrade the in-VM runtime. See [Versioned BOM installer](versioned-bom-installer.md).

The default VM disk source is the `openshell-gateway:latest` image in the
internal registry. To use another registry image, a DataSource, or an HTTP
source, set one of these values in an override file for `charts/openshell-saw`:

```yaml
source:
  registryURL: docker://quay.io/example/openshell-gateway:tag
```

```yaml
source:
  dataSource: openshell-gateway
  dataSourceNamespace: openshell-agents
```

```yaml
source:
  httpURL: https://example.com/openshell-gateway.qcow2
```

Set only one source mode. Keep `source.dataSourceNamespace` at
`openshell-agents` when using the shared golden image.

### OpenClaw UI and the dashboard Route

The `<name>-dashboard` Route forwards to the gateway Service on VM port 18789, but OpenClaw listens inside the sandbox container, which on OpenShell 0.1.x runs in its own network namespace with only loopback (network mode `none`, no port mappings). The Route therefore does not reach the OpenClaw UI and answers 503. Each sandbox has its own namespace, so several OpenClaw sandboxes all listen on 18789 without conflict.

On the pattern path (Option A, including workspaces created in the self-service portal), a sandbox whose profile sets `ui: {route: true}` gets its own Route, `<user>-<workspace>-<sandbox>-ui.apps.<domain>`, signed in through Keycloak and open only to the workspace owner. The local-Keycloak quickstart path (Option B) also creates these Routes for enabled profile UIs. They reach OpenClaw through `openshell forward`, so they work on 0.1.x; see [Opening a sandbox UI](rhdh-architecture.md#opening-a-sandbox-ui). Use `make sandbox-ui` to list them. `make openclaw-gui` and `make nemoclaw-gui` port-forward to the sandbox UI as another access method.

### Web search in the default sandbox

The `notebook` sandbox attaches only the NVIDIA provider, and its policy allows only that provider's endpoints, so the agent's web search and web fetch calls fail. Attaching the `brave` provider to the sandbox in the BOM profile (`charts/saw-bom/profiles/data-science/default/sandbox.yaml`) opens its endpoints; note that the default profile already creates a `brave` provider but attaches it to no sandbox, which is why step 11 still needs `WEB_SEARCH_API_KEY`. A live walkthrough also saw OpenClaw's own SSRF guard reject the sandbox's synthetic DNS answers, so enabling web search may take more than the provider change.

### Shell access

`openshell sandbox connect` attaches to the sandbox's main process. In SAW sandboxes that process is `sleep infinity`, started without a terminal, so `connect` shows nothing. To get an interactive shell, use `openshell sandbox exec`:

```bash
openshell sandbox exec -n notebook -- sh
openshell sandbox exec -n cuda-sandbox --workspace cuda-dev -- sh
```
