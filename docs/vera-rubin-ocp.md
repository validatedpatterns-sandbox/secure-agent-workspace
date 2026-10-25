# Deploying SAW on OpenShift 5.0 rc5 / arm64 (Vera Rubin)

This guide covers deploying Secure Agent Workspace (SAW) on an **arm64**
OpenShift **5.0 rc5** cluster (the NVIDIA "Vera Rubin" / `verac2` environment).

All the cluster-specific changes live on the **`openshift-vera-rubin`** branch
(not `main`). `main` is unchanged and works on GA OpenShift with the productized
operators; it is not broken. The reason `main` can't deploy here is that OCP 5.0
rc5's operator catalog does not yet ship the productized operators SAW relies on
(`rhbk`, `rhdh`, `rhods`), and several of them are amd64-only. This branch
substitutes community/arm64 equivalents and works around the differences those
introduce. The patterns-operator itself is no longer one of them: the released
operator in `community-operators` runs on arm64, so the pattern is installed
the standard way (`./pattern.sh make install`).

> **TL;DR:** run `preinstall.sh`, `./pattern.sh make install`, run
> `postinstall.sh`, load secrets, set up DNS. See [Install](#install). A cluster
> that still runs the early out-of-catalog patterns-operator build: run
> `migrate-patterns-operator.sh` first (see [Migrating](#migrating-off-the-out-of-catalog-patterns-operator)).

---

## Why these changes exist

Every change on this branch falls into one of three buckets:

### 1. Architecture — productized artifacts are amd64-only
| Change | Reason |
|---|---|
| RHDH Postgres image pinned to `rhel9/postgresql-15` | the community operator's default DB image is amd64 → `Exec format error` on arm64 |
| VM golden disk pulled from the GHCR **multi-arch** image | a VM boot disk is arch-specific; GHCR is amd64+arm64, quay's is amd64-only |

### 2. rc5 catalog gaps — productized operators missing; use community
| Change | Reason |
|---|---|
| Keycloak via `keycloak-operator` (`community-operators`) | productized `rhbk` operator absent from the rc5 catalog |
| RHDH via `rhdh` (`rhdh-community-catalog`, `fast-2.2`) | productized RHDH operator absent / amd64-only |
| 3 RHDH dynamic plugins pinned as **OCI** (OIDC provider, http:backstage:request, keycloak catalog) | the community `rhdh:next` image bundles plugins at different paths than productized 1.10, which the chart hard-codes |
| 2 NetworkPolicies (generator egress, saw-portal→backend ingress) | the community RHDH 2.x operator ships stricter default-deny netpols than 1.10 |
| RHODS (`openshift-ai`) deferred | `rhods-operator` absent from the rc5 catalog |

### 3. This cluster / this OCP version — environment specifics
| Change | Reason |
|---|---|
| `saw-hostpath` StorageClass uses `kubevirt.io.hostpath-provisioner` (dots) | HPP registers the CSI driver with that exact name on this cluster |
| golden disk from GHCR (also here) | the CDI importer resolves via node DNS and can't reach the in-cluster image registry on verac2 |
| installer ConfigMap annotated `argocd.argoproj.io/sync-options: Replace=true` | OCP 5.0's Argo CD does not honor app-level ServerSideApply, so the ~300 KiB ConfigMap overflows the 256 KiB `last-applied-configuration` annotation |

> The one change arguably **general** enough to also land on `main` is the
> `Replace=true` sync option (harmless on older Argo, more robust everywhere).

---

## Prerequisites

- An arm64 OpenShift 5.0 cluster, `oc` logged in as **cluster-admin**.
- **OpenShift Virtualization (CNV) + HPP storage** available (the pattern
  installs the CNV operator; the `saw-hostpath` StorageClass must use the HPP
  CSI provisioner — `postinstall.sh` ensures this).
- `patterns-operator` in the cluster's `community-operators` catalog
  (`oc get packagemanifests -n openshift-marketplace patterns-operator`);
  `preinstall.sh` reports it. Earlier rc5 builds shipped no arm64 patterns-operator
  and the branch carried its own; that is gone now.
- A way to resolve `*.apps.<cluster-domain>` from your workstation (these are not
  public DNS on verac2). See [DNS](#dns-for-apps-routes).
- `python3` (used by the export/diagnostic helpers).

---

## Install

All commands run from a checkout of this fork on the **`openshift-vera-rubin`**
branch:

```
git clone https://github.com/sauagarwa/secure-agent-workspace.git
cd secure-agent-workspace
git checkout openshift-vera-rubin
```

### 1. Pre-install (the one catalog the rc5 cluster lacks)

```
bash scripts/vera-rubin/preinstall.sh
```

Installs the RHDH community CatalogSource (arm64) and checks that
`patterns-operator` is available from the cluster catalog.

### 2. Install the pattern

```
./pattern.sh make install
```

Standard Validated Patterns install: it subscribes to `patterns-operator` from
`community-operators`, and creates the Pattern CR from `values-global.yaml` and
this checkout's git remote and branch (`sauagarwa/secure-agent-workspace` @
`openshift-vera-rubin`). The operator bootstraps OpenShift GitOps and the `prod`
clustergroup; Argo CD then installs the operators (Keycloak, RHDH, pipelines,
CNV, external-secrets, Vault) and the SAW charts.

### 3. Post-install fixes

Once the operators begin installing:

```
bash scripts/vera-rubin/postinstall.sh
```

Fixes the StorageClass provisioner and injects the arm64 Postgres image into
the RHDH subscription. Safe to re-run; each step waits for its prerequisite.

### 4. Load secrets

Once Vault is running:

```
./pattern.sh make load-secrets
```

> On verac2 the in-cluster Keycloak route is not resolvable during
> `load-secrets`. Add a hosts entry pointing the route at the router IP, e.g.:
> ```
> echo "<router-ip>  openshell-keycloak-ingress-saw-keycloak.apps.<cluster-domain>" | sudo tee -a /etc/hosts
> ```

### Migrating off the out-of-catalog patterns-operator

A cluster brought up with an earlier version of this branch runs the arm64
patterns-operator as raw manifests in the `patterns-operator` namespace
(`quay.io/sauagarw/patterns-operator:0.0.4-arm64`). Switch it to the released
operator without redeploying the pattern:

```
bash scripts/vera-rubin/migrate-patterns-operator.sh
```

It removes the raw install (Deployments, webhook, RBAC), leaves the Pattern CRD
and the Pattern CR in place so the GitOps apps keep running, subscribes to
`patterns-operator` in `openshift-operators` from the catalog's default channel,
and waits for the CSV. Re-runnable. If the Subscription does not resolve, the
script prints the `oc` commands to look at; the usual cause is another
unresolvable Subscription in `openshift-operators` blocking OLM resolution for
the namespace.

### DNS for *.apps routes

The portal and workspace UIs live under `*.apps.<cluster-domain>`, which is not
public DNS on verac2. Point it at the cluster's router IP. Wildcard via dnsmasq
(macOS example):

```
brew install dnsmasq
echo 'address=/apps.<cluster-domain>/<router-ip>' | sudo tee -a $(brew --prefix)/etc/dnsmasq.conf
sudo brew services start dnsmasq
sudo mkdir -p /etc/resolver
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolver/<cluster-tld>
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```

Or per-host lines in `/etc/hosts` (`<router-ip>  <host>.apps.<cluster-domain>`).
UI routes use a self-signed `*.apps` certificate — accept the browser warning.

---

## Validate

1. Open the RHDH portal (the `vp-gitops` / `rhdh` route) and sign in via OIDC.
2. Self-Service → Templates → **Create or update my agent workspace**: pick a
   profile, enter keys, submit.
3. The pipeline registers the workspace, Argo CD builds it, and an arm64 VM boots
   from the GHCR golden image (~15–25 min end to end). The workspace appears in
   the Catalog with its web-UI links.
4. The OpenShell web UI terminal gives a shell into the sandbox.

---

## Known issues & caveats

- **Sandbox control-UI gateway is unsupervised.** Each sandbox's openclaw
  control UI (the `*-ui` routes) is launched once as a bare `nohup` process with
  no restart-on-crash. If it dies, the route 502s even though the sandbox is
  healthy. This is **shared code (`apply_bom.py`), identical on `main`** — not an
  rc5/arm64 change. Restart it from the sandbox terminal:
  ```
  nohup openclaw gateway run --allow-unconfigured --bind lan --port 18789 --force >/tmp/gw.log 2>&1 &
  ```
  A proper fix (supervise/relaunch the gateway) belongs on `main`.
- **Gateway admin web UI requires `openshell-admin`.** By design the demo seeds
  workspace owners with `openshell-user`; the gateway admin webui needs
  `openshell-admin`. Grant it in Keycloak, or use the user-facing dashboard.
- **RHODS is deferred** (absent from the rc5 catalog) — the pattern creates no
  DataScienceCluster. Restore the `openshift-ai` subscription in `values-prod.yaml`
  on GA.

---

## Scripts & manifests

Everything lives under `scripts/vera-rubin/`:

| Script | Purpose |
|---|---|
| `preinstall.sh` | RHDH community catalog; reports whether `patterns-operator` is in the cluster catalog |
| `migrate-patterns-operator.sh` | replace the early out-of-catalog patterns-operator with the released one from the catalog |
| `postinstall.sh` | StorageClass provisioner, RHDH arm64 Postgres |
| `export-cluster-state.sh` | capture the manual-step objects from a live cluster into `manifests/` |
| `manifests/` | captured YAML: RHDH CatalogSource, RHDH subscription, StorageClass, HPP CR |
| `diag-*.sh` | diagnostics used while bringing this up (RBAC, netpols, VM/DataVolume, Keycloak tokens, gateway, sandbox) |

The chart/values changes (community operators, OIDC/plugin pins, NetworkPolicies,
golden-image source, installer `Replace=true`) are committed to the branch and
need no manual step.
