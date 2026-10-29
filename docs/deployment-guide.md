# Secure Agent Workspace — End-to-End Deployment Guide

## Overview

The Secure Agent Workspace (SAW) deploys a per-user AI agent sandbox running inside a KubeVirt virtual machine on OpenShift. The deployment is fully GitOps-driven via Red Hat Validated Patterns and ArgoCD. Production has no demo users. For an explicit demo and separate browser sign-in steps, see [Keycloak production and demo users](../README.md#keycloak-production-and-demo-users).

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
| `governance-interceptor` | `openshell-agents` | gRPC interceptor deployment; with `global.governance.engine: apf`, the APF inputs and an Argo CD app for the APF chart ([apf.md](apf.md)) |

**Operator Subscriptions:** OpenShift Virtualization, RHBK (Keycloak), External Secrets Operator, RHDH, OpenShift AI.

## Deployment Phases

### Phase 1: Golden VM Image

The `openshell-gateway-image` BuildConfig creates a Fedora 44 qcow2 image with:

- Podman by default (`containerRuntime: podman`), or Docker CE with `containerRuntime: docker`; plus Node.js, Python3, cloud-init, openssh, qemu-guest-agent. See [Container runtime support](container-runtime.md).
- `cloud-user` with sudo access (and the `docker` group only in the Docker variant)
- Systemd user service for the OpenShell gateway (`openshell-gateway.service`)
- First-boot setup service (`openshell-gateway-setup.service`) that starts the container runtime and enables the gateway; `saw-gateway-pki` generates gateway PKI in tmpfs through its systemd `ExecStartPre` drop-in

The image is pushed to an internal ImageStream (`openshell-gateway:latest`). CDI imports it into each VM disk by default. A DataSource can be used for cloning instead.

Build trigger: `make gateway-build-docker` (Docker variant) or `make gateway-build-podman` (Podman variant), or automatically via ArgoCD.

### Phase 2: Keycloak + OIDC

RHBK operator deploys Keycloak. A `KeycloakRealmImport` creates the `openshell` realm with:

- **Clients:**
  - `openshell-cli` — public client, PKCE with S256, device code flow, 24h token lifetime
    (effective lifetime capped to 10h by the realm's SSO Session Max)
  - `openshell-dashboard` — public client, PKCE, redirect URIs registered by the redirect registrar or an administrator (below)
- **Users:** none by default; create real accounts before adding their workspace entries
- **Roles:** `openshell-user`, `openshell-admin`
- **Token mappers:** realm roles in access tokens, audience mapper so dashboard tokens are accepted by the gateway

#### Web UI redirect URIs

Every web UI has its own route host (each VM's dashboard, and each sandbox UI route), and Keycloak matches redirect URIs exactly apart from a trailing wildcard, so each host has to be registered on `openshell-dashboard`. The routes to register are labelled `saw.redhat.com/oidc-redirect=true` in namespaces labelled `openshell.pattern/saw=true`; their redirect URI is `https://<host>/oauth2/callback` and their web origin `https://<host>`. No pod in a SAW namespace holds Keycloak credentials for it.

By default the redirect registrar registers them (`redirectRegistrar` in `openshell-keycloak`): one Deployment, `saw-redirect-registrar` in Keycloak's namespace, every 15 seconds adds the entries of routes it finds and removes those it added for routes that are gone from every SAW namespace. It keeps an entry while its route still exists (labelled or not), keeps entries it did not add (recorded in the client attribute `saw.redhat.com/managed-redirects`), and on its first run adopts the per-VM entries the prepare Jobs used to add. A failed route list removes nothing. It signs in as its own confidential client, `saw-redirect-registrar`, whose service account has only `manage-clients` in the OpenShell realm; its init container sets that client up with the operator's `<keycloak>-initial-admin` Secret and hands the client secret over in memory, so the registrar container never sees the master admin. It reads routes, namespaces and the ingress domain only, and reaches Keycloak in-cluster (`http://<keycloak>-service.<namespace>.svc:8080`; set `redirectRegistrar.keycloakUrl` for an existing Keycloak without HTTP, and `redirectRegistrar.adminSecret` for another admin Secret name). `manage-clients` still covers every client of the realm; Keycloak's fine-grained admin permissions could narrow it to `openshell-dashboard`.

The Pattern also enables `saw-owner-resolver` in the Keycloak namespace. Its
separate client has only `realm-management/view-users` in the OpenShell realm.
It finds each existing account by the exact `users[].name` and writes its
subject to a dedicated ConfigMap in that user's namespace. A namespaced Role
permits only `get` and `patch` on that ConfigMap. No Keycloak admin Secret
reaches a tenant namespace or VM. A missing, disabled, ambiguous, or
mismatched account gets no membership. The resolver records its state in the
ConfigMap annotation `saw.redhat.com/owner-resolution`.

With `redirectRegistrar.enabled: false`, nothing in the cluster holds Keycloak admin access for this: an administrator runs `make -f Makefile-quickstart keycloak-register KC_USER=<user>` once the workspace exists (it also creates the Keycloak account if it is new) and `keycloak-redirects-sync` after deleting workspaces (`scripts/keycloak-redirects.py`, with the administrator's `oc` session and Keycloak's admin Secret, like `scripts/keycloak-users.sh`). The script applies the registrar's rules. See the README's [Web UI sign-in](../README.md#web-ui-sign-in-redirect-uris).

#### The issuer's certificate

The OpenShell gateway in each workspace VM fetches the issuer's OIDC configuration at startup. It verifies the certificate with the public CAs Fedora ships, and exits if it cannot. Then `install` fails with "cannot verify the OIDC issuer's certificate" and `apply` keeps failing with "install has not finished". The dashboard and sandbox-UI oauth2-proxies verify the issuer too. Set `dashboard.insecureSkipIssuerTlsVerify: true` only to debug.

When an issuer CA is configured (below), only the gateway and the oauth2-proxies trust it, never the VM's system trust store. The cluster's ingress CA has no name constraints. In the system store, a certificate it signed for `quay.io` would verify for podman and every other TLS client on the VM. Instead, the installer writes two files to the runtime user's `~/.config/openshell/`, then restarts the gateway:

- `issuer-ca.pem`: the CA certificates alone (leaf certificates are dropped). The oauth2-proxies mount it and use it only for their calls to the issuer (`OAUTH2_PROXY_PROVIDER_CA_FILES`).
- `issuer-trust.pem`: the public CAs plus that CA. The gateway gets it as `SSL_CERT_FILE`, through a systemd drop-in (`openshell-gateway.service.d/issuer-ca.conf`).

A bundle with a private key in it is refused, by the chart and by the installer, and so is a bundle without a CA certificate. Before installing the CA, the installer connects to the issuer and verifies its certificate with the CA alone. If the CA signs it, the CA is installed. If the issuer is publicly trusted anyway (the automatic cluster CA on a cluster whose `*.apps` certificate is public), the CA is not installed, because it would only widen the gateway's trust. If neither verifies it, install fails with the fix. The gateway trusts the issuer CA for all of its HTTPS, not only discovery, because OpenShell has no setting that limits a CA to the issuer.

Most clusters need nothing here. A certificate that is not from a public CA does:

- **The in-cluster Keycloak on a cluster that keeps OpenShift's self-signed `*.apps` certificate** (common on lab, bare-metal and LaunchPad clusters). The pattern handles this one for you. See [The cluster's ingress CA, automatically](#the-clusters-ingress-ca-automatically).
- **An external issuer (`oidc.issuerUrl`) with a private CA, or the quickstart.** Set `oidc.caBundle` yourself. See [Setting oidc.caBundle](#setting-oidccabundle).

Before installing, `make check-oidc-ca` tells you which case you are in. It looks at the default IngressController's certificate and verifies `*.apps` against public CAs only. Run `make check-oidc-ca ISSUER=<url>` for an external issuer. If something was missed, the installer in each VM checks the issuer before starting the gateway and fails with the fix (`install: Failed - cannot verify the OIDC issuer's certificate …; set oidc.caBundle …`).

`make prereqs-check` also runs this CA check as a warning. It does not change
the cluster, but the CA check can save `ingress-ca.pem` in the current directory.

To check from inside a VM (`make saw-vm-ssh` or `virtctl ssh`):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' <issuer>/.well-known/openid-configuration
```

`200` means the issuer is trusted.

##### The cluster's ingress CA, automatically

With the in-cluster Keycloak (`oidc.issuerUrl` empty) and no `oidc.caBundle`, every workspace VM trusts the cluster's own ingress CA:

1. The `saw-ingress-ca` imperative job (`ansible/playbooks/saw-ingress-ca.yaml`, every 10 minutes) copies `openshift-config-managed/default-ingress-cert` to Vault at `secret/data/hub/cluster-ingress-ca`. That ConfigMap is public data, and the job only writes when the CA changed.
2. Each user's `saw-<user>-secrets` app syncs it into their namespace as the Secret `saw-ingress-ca` (pattern-secrets, from saw-users `defaults.clusterCaSecret`).
3. The VM mounts that Secret like a provider metadata Secret (openshell-saw `oidc.clusterCaSecret`). On every boot, the installer trusts its `ca-bundle.crt`.

No workspace needs RBAC on `openshift-config-managed`, and nothing reads a private key. On clusters whose `*.apps` certificate is from a public CA it is harmless.

- **First install.** The VM waits for the Secret, as it does for the provider metadata Secrets, so a VM created before the job's first run starts within about 10 minutes. To skip the wait, run the job once: `oc create job -n imperative --from=cronjob/<the saw-ingress-ca cronjob> saw-ingress-ca-now`.
- **Rotation.** A rotated CA reaches Vault and the Secret on its own, and each VM on its next restart.
- **Turning it off.** Set saw-users `defaults.clusterCaSecret: ""`, for example when the issuer is external or the cluster has a public certificate.

##### Setting oidc.caBundle

1. **Get the CA.** For the cluster's own ingress CA:

   ```bash
   oc get cm default-ingress-cert -n openshift-config-managed -o jsonpath='{.data.ca-bundle\.crt}' > ingress-ca.pem
   ```

   For an external issuer, use your organisation's root CA (and any intermediates).

2. **Set it.** It wins over the cluster CA.
   - Validated pattern, every user: put it under `defaults.openshellSaw.oidc.caBundle` (a literal block, `caBundle: |`) in the saw-users values.
   - Validated pattern, one user: put it under that user's `values.oidc.caBundle` in `overrides/saw-users.yaml`.
     A user's `values` are admin input: whoever can change `overrides/saw-users.yaml` decides which CA that user's gateway and proxies trust, and can also turn off the proxies' verification (`dashboard.insecureSkipIssuerTlsVerify`). Treat write access to that file like admin access to those workspaces. The self-service portal never writes `values`.
   - Quickstart, after `make saw-create`: `helm upgrade <name> charts/openshell-saw -n <namespace> --reuse-values --set-file oidc.caBundle=ingress-ca.pem`.

3. **Restart the VM** so it reads the new config: `virtctl restart <user> -n saw-<user>`. On boot, the installer writes the issuer trust files described above and restarts the gateway. The console log shows `Trusting the issuer CA (N certificate(s)) for the gateway and the oauth2-proxies only`, then `install: Done`. Emptying the setting removes the files again.

A CA you set by hand does not follow rotation. Repeat these steps when the CA changes.

#### Using your own OIDC provider

Set `oidc.issuerUrl` (in saw-users `defaults.openshellSaw`, or per user) to your provider's issuer, for example `https://sso.example.com/realms/corp`. The cluster's ingress CA is then not used, because it has nothing to do with an external issuer. The provider needs:

- a public client `openshell-cli` (`oidc.clientId`) for the CLI's browser and device-code login;
- a public client `openshell-dashboard` (`dashboard.clientId`) with PKCE (S256), whose redirect URIs include `https://<host>/oauth2/callback` for every web UI route (see [Web UI redirect URIs](#web-ui-redirect-uris); the redirect registrar only manages the in-cluster Keycloak);
- a roles claim the gateway reads (`oidc.rolesClaim`, default `realm_access.roles`) with `openshell-admin` / `openshell-user` (`oidc.adminRole`, `oidc.userRole`), and `preferred_username` matching the workspace owner for the sandbox-UI allow-list;
- a certificate the VM trusts: from a public CA, or set `oidc.caBundle` to your private root CA (and intermediates).

### Phase 3: Secrets

ExternalSecret CRs pull from Vault:

| Secret | Vault Path | Content |
| --- | --- | --- |
| `openshell-aap-ssh` | `<prefix>/ssh` | SSH private key + public key |
| `openshell-ssh-pubkey` | `<prefix>/ssh` | SSH public key (for cloud-init) |
| `inference` | `<prefix>/inference` | Provider type, model, API key |
| `web-search` | `<prefix>/web-search` | Brave provider and API key; proxy only, omitted when web search is off |
| `inference-meta` | `<prefix>/inference` | Provider, model and URL only; VM mount |
| `web-search-meta` | `<prefix>/web-search` | Provider only; VM mount, omitted when web search is off |
| `<additional-provider>-meta` | `<prefix>/<additional-provider>` | Provider, model and URL only; VM mount |

`<prefix>` is `secret/data/hub` unless a user sets `vaultPrefix`. One shared hub key then serves every workspace. To give one person their own keys, put them in Vault at `secret/data/hub/saw-<user>/...` and set that user's `vaultPrefix` to `secret/data/hub/saw-<user>`. The `saw-users` chart reads the prefix; it does not create Vault entries. See the commented example in `values-secret.yaml.template`.

### Phase 4: Governance Policy

The `governance-policy` chart creates two ConfigMaps from files in the chart:

- `governance-interceptor-policy` — sandbox filesystem/process policy from `policy.yaml`
- `governance-interceptor-profiles` — all `profiles/*.yaml` auto-discovered via Helm glob

The `governance-interceptor` chart deploys the interceptor pod, which mounts both ConfigMaps and serves them over gRPC. See [governance-interceptor.md](governance-interceptor.md) for the full enforcement flow.

### Phase 5: VM Boot + In-guest installer

The VM boots from a disk imported from the golden image. Nothing logs in over SSH to install it. See [Versioned BOM installer](versioned-bom-installer.md).

#### Cloud-init

Cloud-init runs once and writes the static files: the mount script, the `saw-install` and `saw-apply` units, first-boot copies of `gateway.env` and `gateway.toml`, the PKI systemd drop-in, `server-sans` and `pki-generation`, and (only when `vm.liveInputs` is true) the reconcile units. SSH keys are not in this Secret. KubeVirt `accessCredentials` writes `cloud-user`'s `authorized_keys` from the `<name>-ssh-pubkey` Secret.

#### Root disk

There is no prepare Job. The namespace runs the VM, credential proxy Deployment and a bounded PreSync CA hook. The VM's disk template makes its root disk once, when it does not exist: by default CDI imports the golden image from the internal registry (`<source.dataSourceNamespace>/openshell-gateway:latest`, from `make images-mirror` or the image build) with `pullMethod: node`, so each node pulls the image once and caches it. Set `source.registryURL` to import another image (pin it by digest), `source.httpURL` (or the older `source.goldenImageURL`) to download a qcow2 over HTTP, or `source.dataSource` to clone a golden image DataSource that already exists. An `http://` or `https://` disk URL is added to the namespace egress firewall on its own host and port; a host already allowed on that port is not listed twice. Changing the source later does not change an existing VM's disk. Keycloak redirect URIs are registered by the redirect registrar in Keycloak's namespace, or by an administrator ([Web UI redirect URIs](#web-ui-redirect-uris)).

#### Guest

`saw-install` pulls each BOM component by digest and starts the gateway. `saw-apply` reads the mounted profiles and provider metadata, creates workspaces, providers, and sandboxes, and attaches each sandbox's providers using nonsecret markers. The namespace credential proxy injects keys on bound HTTPS requests. The default signature mode is `warn`. The default prune mode is `report` (log `would delete`, delete nothing). VM inputs are iso9660 disks unless `vm.liveInputs` is true, in which case virtiofs updates them without a restart.

Pattern owner subjects use a separate `saw-owner-subject` ConfigMap mount over
virtiofs, even when other inputs use ISO media. The input watcher and timer
reapply memberships when that subject changes. Account recreation removes
the old subject before adding the new one. Direct quickstart and portal
provisioning keep their explicit verified subject input. An external OIDC
issuer needs `ownerSubject` because the Keycloak resolver cannot query it.

### Existing-install identity migration

A new `KeycloakRealmImport` does not update an existing realm. Use the realm's
admin console and `make keycloak-harden` for existing settings. Do not use a
chart render as proof that existing accounts or registration changed.

1. Record the current realm and accounts. Confirm which accounts are real
   users; do not disable an account only because its name matches a demo
   name. Establish one real operator with `openshell-admin`. Verify its role
   claim and recovery access.
2. Create each real owner account with `make keycloak-add-users` or the realm
   admin console. Give each ordinary owner `openshell-user` only. Add the
   account name to `overrides/saw-users.yaml`. Sync the Pattern and check
   `saw.redhat.com/owner-resolution=resolved` on that owner's
   `saw-owner-subject` ConfigMap. Verify the owner's workspace list and one
   bounded create/delete action through the gateway before removing access.
   For a workspace enrolled before this release, record its previous owner
   subject before the sync. After the new owner passes these checks, remove
   the old grant in the VM with
   `openshell workspace member remove --workspace <workspace> --subject <old-subject>`.
   Repeat for each workspace. The new membership ledger cannot infer grants
   that an older installer created. Do not remove the grant if it is still
   the verified owner's subject.
3. Run `make keycloak-harden` for the configured realm. In the realm admin
   console, also verify **Realm settings > Login > User registration** is
   off. Check password policy and brute-force settings. Do this explicitly:
   reapplying a `KeycloakRealmImport` does not change an existing realm.
4. For each confirmed demo-only account, remove it from
   `accessControl.dashboardSupportUsers` and
   `sandboxUiProxy.allowedUsers` in every SAW where it has support access.
   Apply the updated installer configuration and restart those proxies.
   Then disable the account and revoke its sessions in the realm admin
   console. A valid oauth2-proxy cookie can outlive Keycloak logout: in a
   live migration check, logout alone left an existing cookie at HTTP 200;
   removing the proxy allowance changed it to HTTP 403. Verify that the
   account's old browser session cannot reach the proxy or gateway. Review
   and rotate credentials that the account could access. Keep the real
   operator and owners active.
5. During rollback, preserve the verified real accounts, their memberships,
   and operator recovery access. Do not restore demo accounts as a shortcut.

An existing VM installed before the owner resolver needs the new guest input
watcher. Sync its updated VM specification, then copy the new
`saw-mount-inputs.sh`, `saw-reconcile`, `saw-reconcile.service`,
`saw-inputs.path`, and `saw-inputs.timer` from
`charts/openshell-saw/files/guest/` into that VM with `virtctl scp`.
Install scripts in `/usr/local/sbin` with mode `0755` and units in
`/etc/systemd/system` with mode `0644`. Run `systemctl daemon-reload` and
`systemctl enable --now saw-inputs.path saw-inputs.timer` in the VM. Restart
the VM once with `make saw-restart OPENSHELL_SAW_NAME=<name>` so KubeVirt
attaches the new virtiofs ConfigMap. The root disk is retained. Run
`saw-mount-inputs.sh` and `systemctl start saw-reconcile.service` after the
restart, then verify membership. A new VM gets these files from cloud-init.

Restart an existing VM after an installer ConfigMap update, including a
dashboard proxy fix. Argo CD can report Synced while the running VM still
mounts the old installer script. The restart retains the root disk. After it
finishes, verify that `/var/lib/saw/verified/installer/setup-dashboard.sh`
has the new content and that `saw-apply.service` completed. Check the web UI
route with an owner and a different user before you consider the update done.

A workspace that stays Starting may be waiting on a required provider metadata Secret or the public `saw-proxy-ca` ConfigMap. The virt-launcher pod is scheduled and sits in ContainerCreating; the kubelet retries the mount when the missing input appears.

```bash
oc get events -n saw-<user> | grep FailedMount
```

## NetworkPolicy upgrade procedure

This release introduces default-deny NetworkPolicy. The standalone
`openshell-saw` chart enables it by default and refuses to render until pod
CIDRs, Service CIDRs, the Kubernetes API Service IP, and exact API EndpointSlice
backend IPs and ports are supplied. `make saw-create` discovers these values
before writing any namespace or Secret. `SAW_VALUES_FILE` remains a Helm
overlay for other settings; conflicting topology values in it are rejected.

For an existing GitOps deployment, `saw-users` starts with NetworkPolicy off
for each user, so a sync does not cut off active VMs. Roll it out one user at a
time:

1. Audit that user's in-cluster inference, MCP, registry, and package-mirror
   destinations. Add each required namespace, pod selector, and TCP port under
   that user's `networkPolicy.extraEgress`.
2. Run `make prereqs-check`. It reads the live Network resource, the
   `default/kubernetes` Service, and its EndpointSlices. Paste the printed
   `defaults.openshellSaw` snippet into `overrides/saw-users.yaml`. An enabled
   user's effective topology must match the live topology or this command
   fails with a replacement snippet.
3. Set that user's `values.networkPolicy.enabled: true`, sync its Argo CD
   Application, and run `tests/test-network-policy.sh` with a dedicated peer.
   Check the user's actual in-cluster workflows before enabling the next user.

Argo CD cannot discover topology during Helm rendering. Run the preflight
before each enablement and after API EndpointSlice changes; update the values
and sync before an old endpoint is removed. Hosted control planes can expose
the API on TCP 443 or another port, so use the discovered endpoint ports, not
an assumed control-plane node port. On a hosted cluster with
`cleanupOnDelete: true` and NetworkPolicy off, supply exact `cleanupApi`
endpoints too; the legacy control-plane node fallback has no target there.
The exact API exception remains in EgressFirewall through a temporary
NetworkPolicy rollback, so restore isolation as soon as its scoped rules are
correct. See [network troubleshooting](troubleshooting.md).

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

The source of truth is `egress.allow` in [`charts/openshell-saw/values.yaml`](../charts/openshell-saw/values.yaml). That list includes Quay and its CDN hosts, GHCR (`ghcr.io` and its blob host `pkg-containers.githubusercontent.com`), Fedora's registry, and every exact host in [`charts/governance-policy/profiles/`](../charts/governance-policy/profiles/). Chart tests check that each shipped profile host and BOM/profile image registry is allowed, that each default allowlist host is a profile host, registry, or documented exception, and that profile ports match the rendered EgressFirewall and NetworkPolicy rules. The chart also allows the Keycloak route host taken from the OIDC issuer URL, using the URL's port (443 when the URL has none).

Node addresses are allowed on TCP 443 and 80 for the ingress router. When uninstall cleanup is enabled, exact API endpoint IP and port rules let the short-lived cleanup Pod reach the Kubernetes API. The VM and CDI importer NetworkPolicies exclude those endpoint IPs from their outside rules, including an API on TCP 443. Kubelet, SSH, and NodePorts are not open in the EgressFirewall. If the ingress is a load balancer address rather than a node IP, the router rule does not cover it. The Keycloak Route host is what the VM uses for login.

Everything else on the public internet is denied, for IPv4 and IPv6. The EgressFirewall can also block traffic to the cluster API: on the 2026-10-11 test cluster, its default deny stopped the cleanup Pod even though that Pod's NetworkPolicy allowed egress. The scoped API rule above is therefore required for deletion on that cluster. The NetworkPolicies below control pod and Service flows.

Hostnames are exact. A name such as `*.quay.io` is rejected at render time, because matching a wildcard needs the `DNSNameResolver` feature gate. Gemini's `*-aiplatform.googleapis.com` cannot be written as a `dnsName` rule. Add the regional host you use under `extraAllow` (for example `us-central1-aiplatform.googleapis.com`).

Quay serves image layers from `cdn01.quay.io` through `cdn06.quay.io`. Those names are on the list. Their addresses change often, and OVN resolves them itself, which can disagree with the VM's own resolver. On cluster-mx8z2, `podman pull quay.io/quay/busybox` succeeded three times in a row and `https://cdn01.quay.io/` returned HTTP 403 (the name is reachable; Quay refuses a bare GET). `registry.npmjs.org` is on the list too, and from that same VM it still timed out: the guest resolved Cloudflare addresses that OVN had not installed for the name. Public NTP (UDP 123) is denied. The guest clock stays on kvm-clock; chrony will not see public pool servers.

Anything that installs npm packages in a sandbox (OpenClaw plugins, NemoClaw onboarding) can fail intermittently for that reason: the timeout is OVN's DNS view disagreeing with the guest's, not a missing entry. If a sandbox flow needs npm reliably, set `egress.enabled: false` for that workspace, or point it at an npm mirror inside the cluster and add a narrow `networkPolicy.extraEgress` rule for its pods and port.

With harness bundles on (`allowDriverConfig: true`, which saw-users sets with `harnessEnabled`), `egress.harnessAllow` adds `rekor.sigstore.dev` and `tuf-repo-cdn.sigstore.dev` for the keyless cosign verification the installer repeats on every apply. Without them the first apply fails verification and removes the harness from the sandbox. A harness image on another registry needs that registry, and its blob host, under `egress.extraAllow`. `signing.mode: enforce` adds the same two Sigstore hosts even when no harness is on. `warn` only logs, so it does not.

An external disk download (`source.httpURL`, or `source.goldenImageURL` / `source.registryURL` when it is `http://` or `https://`) is allowed automatically. So is a `docker://` image on a registry outside the cluster when `source.pullMethod` is `pod` (its registry host and port). With `pullMethod: node`, the default, the node's container runtime pulls the image, outside this firewall, so nothing is added. A registry that serves blobs from a CDN host needs that host under `egress.extraAllow`. The internal registry is never added. Any other host outside the cluster, including a custom inference endpoint, still has to be listed.

To let one deployment reach another host (an enterprise system, or a custom inference endpoint outside the cluster), add it in Git under `egress.extraAllow`. On the pattern path, set that under `defaults.openshellSaw` in [`charts/saw-users/values.yaml`](../charts/saw-users/values.yaml), or on one user. A host inside the cluster (`*.svc`) needs `networkPolicy.extraEgress` for its namespace, pods, and port; it needs no EgressFirewall DNS entry.

```yaml
egress:
  extraAllow:
    - vllm.example.net
```

`egress.enabled: false` removes the firewall. Leave it on.

**Upgrading an existing sandbox.** The next sync turns this firewall on. A custom-inference URL that is outside the cluster lives only in Vault, so the chart cannot see it. Before upgrading, put that host in `egress.extraAllow`, or set `egress.enabled: false` on that user until you do. Calls to that URL time out. OpenShell does not report a policy denial.

### In-cluster NetworkPolicy

> Rolling default-deny NetworkPolicy out on an existing deployment is a staged, one-user-at-a-time procedure — see [NetworkPolicy upgrade procedure](#networkpolicy-upgrade-procedure).

The `openshell-saw` chart renders `saw-default-deny`, `saw-vm`, `saw-cdi-import`, `saw-credential-proxy`, and (when `cleanupOnDelete` is true) `saw-cleanup-hook` after NetworkPolicy is enabled for that SAW. The PreSync CA hook has its own temporary policy for exact API egress. These stable names make policy inspection and rollback consistent. The default-deny selects every pod; the VM allow policy selects only the `virt-launcher` pod carrying `openshell.pattern/role: gateway`. CDI importer pods get DNS, registry, router, and ingress from the CDI namespace; outside egress is added only for an HTTP import or a pod-pulled external registry. The cleanup hook has exact API Service and backend peers while deleting the VM and PVCs.

The VM can use DNS in `openshift-dns` on TCP/UDP 5353, the governance Service's pods on TCP 18081 (interceptor or APF engine), the internal registry on TCP 5000, the configured Keycloak issuer Route via the ingress controller on TCP 443/80, and approved outside destinations. The VM reaches its credential proxy on TCP 3128. The proxy policy permits DNS and bound HTTPS destinations; add scoped in-cluster peers to its `extraEgress` when needed. The in-VM dashboard proxy also uses that issuer Route; there is no direct Keycloak Service allow. Router ingress to the VM is limited to gateway, dashboard, webui, and configured sandbox UI ports. TCP 22 ingress is allowed only from `virt-api` pods in `openshift-cnv` so `virtctl ssh` and the VM SSH helper can use KubeVirt's port-forward tunnel. The outside IPv4 rule allows TCP 443/80 plus configured `networkPolicy.externalPorts` and automatically added issuer or disk URL ports. The EgressFirewall still decides which outside hostnames may answer. `networkPolicy.allow.*` toggles disable individual peers; `networkPolicy.extraIngress` and `extraEgress` add site-specific rules.

The outside rule excludes every pod and Service CIDR, exact API endpoint IPs, and `169.254.0.0/16`, so the Kubernetes API Service, other tenants, and the metadata endpoint do not inherit outside access. **Before installing or upgrading**, compare live topology with this SAW's values:

```bash
oc get network.config cluster -o jsonpath='{.status.clusterNetwork[*].cidr} {.status.serviceNetwork[*]}'
oc get service kubernetes -n default -o jsonpath='{.spec.clusterIP}{"\n"}'
oc get endpointslice -n default -l kubernetes.io/service-name=kubernetes -o yaml
```

The chart has no assumed CIDR or API endpoint values. `make saw-create` discovers them; direct Helm and GitOps users must supply them. `make prereqs-check` compares each enabled pattern user's effective values with the live topology. `extraBlockedCIDRs` excludes another IPv4 range. The template rejects empty or malformed CIDR lists and broad custom rules. The outside rule is IPv4 only; IPv6 has no allow rule and remains denied. NetworkPolicy and EgressFirewall cannot distinguish one Route host from another on TCP 443, so cluster Routes still rely on their own authentication.

The API firewall exception is always present for both cleanup and credential-proxy CA hooks, including with `cleanupOnDelete: false` or during a NetworkPolicy rollback. The VM remains blocked from the API by `saw-vm`. The CA hook uses `restartPolicy: Never` and a 120-second deadline. If exact endpoints were not configured on a policy-disabled, self-managed cluster, the chart uses the older control-plane node TCP 6443 fallback. That fallback does not work on hosted control planes. The cleanup Pod has a 240-second deadline and each API request has bounded curl timeouts. See [network troubleshooting](troubleshooting.md).

**Upgrading an existing sandbox.** Policies do not alter the VM's checksum or restart it. In-cluster custom inference (`http://vllm.<ns>.svc:8000/v1`), an in-cluster MCP server, or an npm mirror needs a narrow `networkPolicy.extraEgress` rule for its namespace, pods, and port before the policy sync. The chart's [`saw-users` values](../charts/saw-users/values.yaml) show a commented example. Quickstart discovers topology on each run; `SAW_VALUES_FILE` remains for other settings and cannot override the discovered topology with conflicting values. See [network troubleshooting](troubleshooting.md) for layer-by-layer checks and [`tests/test-network-policy.sh`](../tests/test-network-policy.sh) for offline and live validation.

For an in-cluster MCP server, also configure its sandbox provider and MCP permissions; see [In-cluster MCP Services](harness-bundles.md#in-cluster-mcp-services).

### Internal Connectivity

| From | To | Protocol | Purpose |
| --- | --- | --- | --- |
| Gateway (VM) | Governance interceptor (pod) | gRPC over HTTP | Policy enforcement |
| Gateway (VM) | Keycloak (pod) | HTTPS | OIDC token validation |
| Gateway (VM) | DNS, registry, ingress controller | TCP/UDP 5353, TCP 5000, TCP 443/80 | Resolution, image pull, Routes |
| CDI importer pod | Registry or configured disk URL | TCP 5000 or allowed outside port | Root disk import |
| Cleanup hook / CA hook pod | Kubernetes API | HTTPS | Delete VM and PVCs / initialize proxy CA |
| Gateway (VM) | Credential proxy | HTTP CONNECT on TCP 3128 | Send markers in HTTPS requests |
| Credential proxy | Bound upstream host | HTTPS on TCP 443 | Inject provider key; keyed in-cluster endpoints also require HTTPS 443 |
| In-guest installer | mounted ConfigMaps, provider metadata Secrets, public proxy CA | virtiofs or iso9660 | Install binaries and apply profiles with markers |
| Credential proxy | full provider Secrets | namespace pod mounts | Inject keys into bound HTTPS requests |
| Dashboard (VM) | Gateway (VM) | gRPC over TLS | Agent operations |

### Authentication Flows

- **CLI:** `openshell gateway login` uses the browser flow by default, or the OIDC device-code flow when `OPENSHELL_NO_BROWSER=1` is set, authenticating against Keycloak. The token is cached locally and sent as a bearer token on gRPC calls.
- **Dashboard:** OAuth2 proxy handles browser-based OIDC login, proxies authenticated requests to the dashboard backend, which connects to the gateway.
- **In-guest installer:** a one-day `OU=openshell-admin` certificate and CLI entry in tmpfs during each apply. The long-running `saw-relay` identity has only the workspace user role. Users still use OIDC. See [Credential isolation](credential-isolation.md).

## Operator Quick Reference

### Prerequisites

```bash
make quickstart-prereqs-check # Verify operators and the CLI version against the gateway BOM
```

Install `uv` before either prerequisite check. The quickstart uses it for
Keycloak user management, redirect registration, and sandbox UI values.

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
# Create (required digest; GitOps uses defaults.openshellSaw.credentialProxy.image)
export CREDENTIAL_PROXY_IMAGE='<repo>/saw-credential-proxy@sha256:<digest>'
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
make test-credential-proxy   # Go vet and race tests
SAW_NS=saw-<user> VM_NAME=<user> make test-credential-isolation
make test-deployment        # Run the dedicated live-cluster test
SKIP_LIVE=1 ./tests/test-network-policy.sh  # Offline policy structure checks
# On two dedicated test SAWs:
SAW_NS=saw-nptest-a VM_NAME=nptest-a PEER_NS=saw-nptest-b \
  PEER_VM_NAME=nptest-b REQUIRE_PEER=1 ./tests/test-network-policy.sh
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
variables; do not add them to a command line. `WEB_SEARCH_API_KEY` is optional.
When unset or empty, the runner installs and reinstalls the pattern with
`WEB_SEARCH_ENABLED=false` and verifies that both the web-search ExternalSecret
and Secret are absent. Omit the web-search entry from the pattern's secrets
file for this run. With a key set, the runner verifies normal secret delivery
and credential preservation on reinstall; supply the matching key to Vault
through the pattern's secrets file. Run both modes and retain both evidence
TSVs; each records `config.web-search` as `on` or `off`. For example:

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
export MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
read -r API_KEY < "$HOME/.nvidia-api-key"
export API_KEY
export CREDENTIAL_PROXY_IMAGE='<repo>/saw-credential-proxy@sha256:<digest>'
# Off-mode run:
unset WEB_SEARCH_API_KEY
# For a separate on-mode run, restore the secrets-file entry and use:
# read -r WEB_SEARCH_API_KEY < "$HOME/.brave-api-key"
# export WEB_SEARCH_API_KEY
export TEST_INFERENCE_CHECK=/absolute/path/check-inference.sh
export TEST_OWNER_ACCESS_CHECK=/absolute/path/check-owner-access.sh
# Optional: override the built-in second-user denial check.
# export TEST_SECOND_USER_DENIED_CHECK=/absolute/path/check-second-user-denied.sh
make test-deployment
unset API_KEY WEB_SEARCH_API_KEY
```

Each check must be an executable script that sends a real request and
verifies the response. The runner sets `TEST_ACTIVE_SAW_NAME` and
`TEST_ACTIVE_SAW_NS` for each manual or pattern SAW. It also passes the
owner's `OIDC_TOKEN_DIR` and `TEST_SECOND_TOKEN_DIR`. The inference check
must return a JSON object such as `{"result":"accepted","status_code":200}`.
The owner check must return `{"result":"allowed","status_code":200}` for
HTTP, or `{"result":"allowed","protocol":"grpc","grpc_code":0}` for gRPC.
The built-in second-user check uses `TEST_SECOND_TOKEN_DIR` to call the
gateway's `ListSandboxes` gRPC API in the default workspace. It requires
gRPC `PERMISSION_DENIED` (7) and returns
`{"result":"denied","protocol":"grpc","grpc_code":7}`. This requires curl
with HTTP/2 support. A request to the gateway root is not an access check:
it returns 404 for both users. An HTTP check override must return
`{"result":"denied","status_code":403}`.
Return a nonzero exit code when a request fails. Do not print tokens or
response bodies. The runner records the protocol, status code, and a SHA-256 hash of
the output. These checks are required; a typed confirmation cannot replace
them.

The uninstall cleanup ownership markers assume pattern
`secure-agent-workspace` and cluster group `prod`. Update the tracking IDs
and cleanup marker logic before using a different pattern or cluster group.

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

`make images-mirror` mirrors the CI-built GHCR golden image into the cluster.
`IMAGE_REPO` defaults to `ghcr.io/validatedpatterns-sandbox`; `IMAGE_TAG` defaults
to `latest`. For reproducible installs, run `make images-mirror IMAGE_TAG=sha-<full-commit>` using a commit published by CI on `main`. Both local
and in-cluster mirroring use that exact tag and fail if it is absent; neither
falls back to another build. The internal image also gets a `latest` alias,
which the default VM disk source uses. For a pinned disk import, set
`source.registryURL` to the GHCR image digest. Changing the source does not
replace an existing VM disk. See [Container images](container-images.md) for
CI image names, public package setup, and intentionally retained Quay dependencies.

The default VM disk source is the `openshell-gateway:latest` image in the
internal registry. To use another registry image, a DataSource, or an HTTP
source, set one of these values in an override file for `charts/openshell-saw`:

```yaml
source:
  registryURL: docker://ghcr.io/validatedpatterns-sandbox/openshell-gateway:latest
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

`make saw-create` prints resource creation status, then directs the operator
to wait for `make saw-status` to report `Done` for install and apply. Its next
steps use the selected OIDC issuer, namespace, and client. `make saw-configure`
registers the gateway and signs in; use `openshell gateway login` later if
that sign-in did not finish or a token expires. The create summary lists
`make sandbox-ui` for enabled UI routes and does not advertise the unusable
dashboard Route.

The `<name>-dashboard` Route forwards to the gateway Service on VM port 18789, but OpenClaw listens inside the sandbox container, which on OpenShell 0.1.x runs in its own network namespace with only loopback (network mode `none`, no port mappings). The Route therefore does not reach the OpenClaw UI and answers 503. Each sandbox has its own namespace, so several OpenClaw sandboxes all listen on 18789 without conflict.

On the pattern path (Option A, including workspaces created in the self-service portal), a sandbox whose profile sets `ui: {route: true}` gets its own Route, `<user>-<workspace>-<sandbox>-ui.apps.<domain>`, signed in through Keycloak and open only to the workspace owner. The local-Keycloak quickstart path (Option B) also creates these Routes for enabled profile UIs. They reach OpenClaw through `openshell forward`, so they work on 0.1.x; see [Opening a sandbox UI](self-service-portal.md#sandbox-web-uis). Use `make sandbox-ui` to list them. `make openclaw-gui` and `make nemoclaw-gui` port-forward to the sandbox UI as another access method.

### Web search in the default sandbox

Web search is on by default for GitOps deployments. If Vault has no
`hub/web-search` key, omit its entry from the secrets file and install with:

```bash
./pattern.sh make install WEB_SEARCH_ENABLED=false
```

Alternatively, set `global.webSearch.enabled: false` in `values-global.yaml`.
A user's `webSearch: {enabled: false}` in `overrides/saw-users.yaml` wins over
the global value; `true` opts that user back in and requires their Vault key.
Off removes web-search and web-search-meta from secret delivery and VM mounts, removes the web-search proxy binding, and disables every
BOM provider whose `credentialSecret` is `web-search`, and removes those
provider names from sandbox lists. Other providers are unchanged. The
quickstart detects a missing web-search Secret and applies the same BOM
setting automatically. A rerun keeps web search on if the Secret exists.

Leaving web search on without its key produces ESO `SecretSyncedError` and
a Degraded secrets Application, and the VM can stay in `ContainerCreating`
with `FailedMount` for `web-search`. If the mount is bypassed, the installer
reports `metadata Secret 'web-search-meta' is not mounted`.
Turn the switch off to avoid all three failures.

When switching an existing workspace off, the per-user Applications use
self-heal without automatic prune. Check for retained objects with
`oc get externalsecret,secret web-search web-search-meta -n saw-<user>` and remove them after
the updated Applications have synced:
`oc delete externalsecret,secret web-search web-search-meta -n saw-<user> --ignore-not-found`. Also check the proxy ConfigMap has no web-search binding and the credential-proxy Deployment is Available.
Removing the VM volume may require `make saw-restart-pending` (review the
listed VMs before confirming). The default installer prune mode is `report`,
so an existing gateway's Brave provider may remain; inspect
`openshell provider list --workspace default` and remove it explicitly if
needed. Turning the switch off does not revoke its credential or promise
to remove a provider already installed on a gateway.

The `notebook` sandbox attaches only the NVIDIA provider, and its policy
allows only that provider's endpoints, so the agent's web search and web
fetch calls fail even with web search on. Attaching the `brave` provider in
`charts/saw-bom/profiles/data-science/default/sandbox.yaml` opens its endpoints.
A live walkthrough also saw OpenClaw's own SSRF guard reject the sandbox's
synthetic DNS answers, so enabling web search may take more than the provider
change. The self-service portal still requires a web-search key in its form.

### Shell access

`openshell sandbox connect` attaches to the sandbox's main process. In SAW sandboxes that process is `sleep infinity`, started without a terminal, so `connect` shows nothing. To get an interactive shell, use `openshell sandbox exec`:

```bash
openshell sandbox exec -n notebook -- sh
openshell sandbox exec -n cuda-sandbox --workspace cuda-dev -- sh
```
