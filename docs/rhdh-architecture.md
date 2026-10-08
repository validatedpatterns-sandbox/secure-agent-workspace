# Self-service workspaces with Red Hat Developer Hub: architecture

Users request their own Secure Agent Workspace (SAW) from Red Hat Developer
Hub (RHDH). They choose a SAW-BOM profile, enter only the API keys that
profile needs, and get a namespace `saw-<user>` with a VM, the profile's
OpenShell sandboxes, and a route to each sandbox web UI that only they can
open. Nothing is written to Git: keys go to Vault, and the workspace is an
entry in an in-cluster registry that Argo CD builds.

This page explains the parts and how they connect. To try it, follow the
[user guide](rhdh-user-guide.md). Settings and design details are in
[self-service-portal.md](self-service-portal.md).

## Components

| Component | Where | What it does |
|---|---|---|
| Red Hat Developer Hub | namespace `rhdh`, `Backstage` CR `developer-hub` (RHDH operator) | The portal. Shows the two templates (create, delete) and one catalog entry per workspace. Users sign in with Keycloak. |
| Keycloak realm `openshell` | namespace `saw-keycloak` | One identity for RHDH, the OpenShell gateway and the sandbox UIs. No self-registration; an admin adds users with generated passwords. Client `rhdh` (confidential) for RHDH, `openshell-dashboard` (public, PKCE) for the web UIs. |
| Request API | RHDH proxy endpoints `/saw-requests`, `/saw-pipelineruns` | The only cluster changes the templates make: create a request Secret, start a pipeline. They use RHDH's service account `rhdh-portal`, which can only *create* those two kinds in `saw-portal`. A third endpoint, `/saw-status` (GET), reads progress from the generator. |
| Portal pipelines | namespace `saw-portal`, Tekton `saw-workspace-create` / `saw-workspace-delete` | Run `portal.py` as service account `saw-portal-provisioner`. The first task verifies who the request is for and writes the keys and the registry entry (or marks it for deletion and deletes the Application); each later task waits for one stage of what Argo CD does, so a workspace's whole life shows as one pipeline. |
| Tekton tab | RHDH Kubernetes and Tekton plugins, service account `rhdh-kubernetes-reader` | Each workspace's catalog page shows its create and delete pipeline runs (label `backstage.io/kubernetes-id: saw-<user>`) as a graph with each task's log. Reads only `saw-portal`. |
| Admission policies | `ValidatingAdmissionPolicy` `saw-portal-*` | Pin what `rhdh-portal` may create (Secrets `saw-req-*`, PipelineRuns of the two pipelines with one parameter) and which Argo CD applications the provisioner may delete (`portal-ws-*`, labelled as the portal's). |
| Workspace registry | ConfigMaps `saw-ws-<user>` in `saw-portal` (label `saw.redhat.com/workspace=true`) | One entry per workspace: user name, profile, values for the `saw-users` chart. |
| Generator | Deployment `saw-workspaces-generator` in `saw-portal` | Reads the registry (a malformed entry is skipped and logged). Serves the Argo CD ApplicationSet plugin API (token), the RHDH catalog with each workspace's status (`/catalog.yaml`, no token) and the progress the create template follows (`/status`, the user's Backstage token, through the RHDH proxy endpoint `/saw-status`); a NetworkPolicy admits only RHDH and Argo CD. |
| ApplicationSet `saw-portal-workspaces` | Argo CD namespace (`vp-gitops`) | One Application `portal-ws-<user>` per registry entry, rendering `charts/saw-users` for that one user. Creates and updates only; deleting is done by the delete pipeline. |
| `saw-users` → `openshell-saw` | namespace `saw-<user>` | The same charts as a Git-declared user in `overrides/saw-users.yaml`: External Secrets for the user's keys, the BOM, the VM, the gateway and UI routes. |
| Vault | `secret/data/hub/saw-<user>/<generation>/<secret>` | The user's keys, under the registration's generation (a new one per registration, so a deleted workspace's cleanup never reaches a replacement's keys). The provisioner writes them through the `hub` Kubernetes auth mount with role `saw-portal-writer`, whose policy covers only `secret/*/hub/saw-*` (every portal user's path: the token check in `portal.py` keeps a request to its own). |
| In-VM installer | `apply_bom.py` in the VM | Creates the sandboxes, starts OpenClaw, and runs one OAuth proxy and one port forward per sandbox UI. |
| Cleanup | CronJob `saw-portal-cleanup` | Deletes request Secrets that no pipeline handled. |

## Overview

```mermaid
flowchart LR
  user([User browser])
  subgraph kc[saw-keycloak]
    keycloak[Keycloak realm openshell]
  end
  subgraph rhdhns[rhdh]
    rhdh[RHDH<br/>templates + catalog]
  end
  subgraph portal[saw-portal]
    req[(Secret saw-req-*)]
    tekton[Tekton pipeline<br/>portal.py]
    reg[(ConfigMap saw-ws-user)]
    gen[Generator]
  end
  vault[(Vault<br/>hub/saw-user)]
  subgraph argo[vp-gitops]
    aset[ApplicationSet<br/>saw-portal-workspaces]
  end
  subgraph ws[saw-user]
    eso[ExternalSecrets]
    vm[VM user<br/>OpenShell gateway + sandboxes]
    route[UI route]
  end

  user -- sign in --> keycloak
  user -- template form --> rhdh
  rhdh -- proxy: create --> req
  rhdh -- proxy: start --> tekton
  tekton -- verify token --> rhdh
  tekton -- keys --> vault
  tekton -- entry --> reg
  gen -- reads --> reg
  aset -- plugin generator --> gen
  rhdh -- catalog.yaml --> gen
  aset -- Application portal-ws-user --> ws
  eso -- reads --> vault
  user -- sandbox UI --> route --> vm
```

## Creating a workspace

```mermaid
sequenceDiagram
  actor U as User
  participant R as RHDH
  participant K as Kubernetes API (saw-portal)
  participant P as Pipeline (portal.py)
  participant V as Vault
  participant A as Argo CD
  participant VM as VM in saw-user

  U->>R: Create > "Create or update my agent workspace" (profile + keys)
  R->>K: POST Secret saw-req-xxxx (form + user's Backstage token)
  R->>K: POST PipelineRun saw-workspace-create (request=saw-req-xxxx)
  K->>P: run as saw-portal-provisioner
  P->>R: fetch JWKS, verify token signatures and expiry
  Note over P: user = the token's subject, never the form
  P->>P: check form against the profile catalog,<br/>refuse names taken by Git users or other apps
  P->>V: write secret/data/hub/saw-user/<generation>/<secret>
  P->>K: ConfigMap saw-ws-user (registry entry), delete the request
  A->>K: ApplicationSet asks the generator for workspaces
  A->>A: Application portal-ws-user (charts/saw-users)
  A->>VM: namespace, ExternalSecrets, BOM, VM, routes
  P->>K: tasks argo-cd-apps, vm, vm-running: wait for each
  VM->>VM: installer creates sandboxes, starts OpenClaw, UI proxy
  P->>VM: task sandboxes: wait until every sandbox UI route answers
  R->>K: catalog refresh: Component saw-user with status and UI links
  loop run page, one step per pipeline task
    R->>K: GET /saw-status (generator): task state, then the pipeline's log
  end
```

Argo CD still builds the workspace; the pipeline only watches it after its
first task. Its tasks are the stages:

| Pipeline | Tasks |
|---|---|
| `saw-workspace-create` | `register` (verify, Vault, registry entry) → `argo-cd-apps` → `vm` → `vm-running` → `sandboxes` (every sandbox UI route answers: the installer finished) |
| `saw-workspace-delete` | `unregister` (verify, mark the entry deleting, delete Application `portal-ws-<user>`) → `argo-cd-removes` (apps and namespace gone) → `finish` (Vault keys, then the registry entry) |

A wait task logs each change and fails on a failed Argo CD sync, a VM that
cannot start, or its time limit (30 minutes for `sandboxes`). The run is
labelled `backstage.io/kubernetes-id: saw-<user>`, so RHDH's Tekton tab on
the workspace's catalog page draws it with each task's log; the first task
refuses a run labelled with another user's workspace. The template's run
page shows the same tasks as steps, then the log. The catalog entry shows
the status (`Requested`, `Creating`, `Starting the VM`, `Installing`,
`Ready`, `Failed`, `Deleting`).

While a workspace is deleted its registry entry stays, labelled
`saw.redhat.com/deleting=true`: the ApplicationSet no longer gets it (so it
does not recreate the Application), the catalog still shows it (Deleting,
with its Tekton tab), and a new create for that user is refused until the
`finish` task removes it. Argo CD deletes the namespace and the VM
(`portal.pruneOnRemove`).

The mark names the delete run (annotation `saw.redhat.com/deletion`), and
`finish` destroys the Vault keys first and removes the entry last, only if
it is still that run's mark and only in the version it checked. So a create
cannot slip in between and have its new keys destroyed, and a retried or
stale `finish` leaves a re-created workspace, or a later delete's mark,
alone. A create that finds the entry only on its second look (two requests
at once) reads it again and replaces it conditionally, never over a
deletion mark.

## TLS

Every connection the portal makes is verified. RHDH, the generator and the
Keycloak setup Job build a CA bundle when their pod starts
(`files/ca-bundle.py`, an init container): the image's system CAs, the
cluster's trusted CA bundle (`config.openshift.io/inject-trusted-cabundle`:
proxy CAs), the Kubernetes API and service CAs, the router's CA
(`openshift-config-managed/default-ingress-cert`, for Keycloak's route when
the default ingress certificate is self-signed) and `tls.extraCaBundle`.
RHDH's Node runtime adds it with `NODE_EXTRA_CA_CERTS`; its proxy endpoints
(`secure: true`) and Kubernetes plugin (`caFile`, the service account's CA)
verify. The pipeline checks Vault's certificate against the service CA.
`tls.insecureSkipVerify: true` turns all of it off, for a throwaway test
cluster only.

## Who a request is for

RHDH's proxy endpoints can be called by any signed-in user, so the pipeline
trusts nothing the form says about the user. The template puts the user's
Backstage token (`secrets.backstageToken`) in the request; the pipeline
verifies it against RHDH's published keys:

- the outer token is a plugin token signed by the scaffolder
  (`/api/scaffolder/.backstage/auth/v1/jwks.json`);
- the user is in its `obo` claim, a limited user token signed by the auth
  backend (`/api/auth/.well-known/jwks.json`).

Both signatures and expiries are checked. The user name is the token's
subject (`user:default/<name>`). A user can therefore create, update or
delete only their own workspace, and a create request cannot run the delete
pipeline. A workspace is refused when its namespace exists without the
portal label (the user is declared in Git), when an Argo CD application it
needs belongs to someone else, or when the name could collide with another
user's applications (`-bom`, `-secrets`).

## Opening a sandbox UI

A sandbox with `ui: {route: true}` in its SAW-BOM profile gets a route
`<user>-<workspace>-<sandbox>-ui.apps.<domain>`. The path from the browser to
OpenClaw:

```mermaid
flowchart LR
  b([Browser]) --> r[Route<br/>edge TLS]
  r --> p["oauth2-proxy in the VM<br/>0.0.0.0:420x"]
  p -. sign in .-> k[Keycloak]
  p -- "allowed users file<br/>(owner + allowedUsers)" --> l["relay, at most 16 connections<br/>127.0.0.1:1420x"]
  l --> f["openshell forward<br/>127.0.0.1:2420x"]
  f -- loopback --> g["OpenClaw gateway<br/>in the sandbox :18789"]
```

1. **Keycloak** proves who the user is (their own password).
2. **oauth2-proxy** compares the Keycloak `preferred_username` with the
   allowed users (the workspace owner, plus `sandboxUiProxy.allowedUsers`).
   Anyone else gets 403 here.
3. It forwards the request with that name in `X-Forwarded-Email`,
   overwriting any value the browser sent.
4. A relay lets at most 16 connections at a time through to
   `openshell forward service` and queues the rest: OpenShell refuses more
   than 20 forward connections per sandbox, and a page load opens more.
5. **OpenClaw** runs in trusted-proxy mode: it trusts that header only on
   requests arriving over loopback (where the forward delivers them) and only
   for the same allowed users. A browser device approved this way needs no
   gateway token.

Local clients in the sandbox (the OpenClaw CLI, TUI, `openclaw agent`) use the
gateway secret as `gateway.auth.password`. Sandboxes without a UI route keep
OpenClaw's token mode.

## Users and passwords

- Self-registration is off. An admin adds users from a list
  (`make keycloak-add-users`), each with a generated
  24-character password; existing users are left alone.
- The realm enforces a password policy (14+ characters, upper, lower, digit,
  special, not the user name or email, not one of the last 5) and locks an
  account out for a growing time after 5 failed sign-ins.
- The pattern's test users (developer, admin, alice, bob) get generated
  passwords from Vault (`keycloak-users`); there are no default passwords.

## What is in the RHDH catalog

The catalog is configured by the chart; there is nothing to register by hand.

| Location | Kind | Contents |
|---|---|---|
| `/opt/app-root/src/saw/create-workspace.yaml` (ConfigMap `saw-rhdh-templates`) | Template | "Create or update my agent workspace" |
| `/opt/app-root/src/saw/delete-workspace.yaml` | Template | "Delete my agent workspace" |
| `http://saw-workspaces-generator.saw-portal.svc:4355/catalog.yaml` | Component | One `saw-<user>` per workspace, type `agent-workspace`, owned by `user:default/<user>`, with links to the OpenShell web UI, each sandbox UI and the delete template |

RHDH reads these locations every 30 seconds (`rhdh.catalogProcessingSeconds`).
The create form is generated from the SAW-BOM profiles by
`scripts/saw-profile-catalog.py`, so it asks only for the keys the chosen
profile needs.

## Names

| Thing | Name |
|---|---|
| Namespace | `saw-<user>` (label `saw.redhat.com/portal=true`) |
| VM | `<user>` |
| Argo CD applications | `portal-ws-<user>` → `saw-<user>-secrets`, `saw-<user>-bom`, `saw-<user>` |
| Registry entry | ConfigMap `saw-ws-<user>` in `saw-portal` |
| Keys | `secret/data/hub/saw-<user>/<generation>/<secret>` (e.g. `inference`, `web-search`); the entry's `vaultPrefix` names the generation |
| OpenShell web UI | `https://<user>-webui-saw-<user>.apps.<domain>` |
| Sandbox UI | `https://<user>-<workspace>-<sandbox>-ui.apps.<domain>` |
| RHDH | `https://backstage-developer-hub-rhdh.apps.<domain>` |

User names are lowercase DNS labels of at most 19 characters (they name the
VM).

## Status

Checked on a live cluster (OpenShift with RHDH operator 1.10, OpenClaw
2026.9.5):

- the Keycloak changes: policy, lockout, registration off, generated
  passwords, adding and resetting users;
- the sandbox UI: the Keycloak sign-in through the route, the owner admitted
  and another user refused by oauth2-proxy;
- the RHDH `Backstage` resource against the operator's `v1alpha4` and
  `v1alpha5` schemas;
- the installer across VM restarts.

Still to confirm on a cluster: OpenClaw accepting the owner from
`X-Forwarded-Email` without a token and the CLI password, and the full
request flow from the RHDH form to a running workspace (token shapes on the
installed RHDH, OpenShift Pipelines' defaults against the admission policy,
the ApplicationSet controller in the pattern's Argo CD). The
[user guide](rhdh-user-guide.md) walks through each of these checks.
