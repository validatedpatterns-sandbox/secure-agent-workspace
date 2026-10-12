# APF governance (Agent Policy Fabric)

SAW gateways call one governance service, `governance-interceptor.openshell-agents.svc:18081`.
By default that is the OpenShell governance interceptor ([governance-interceptor.md](governance-interceptor.md)).
One switch replaces it with NVIDIA's **Agent Policy Fabric (APF)**, which serves the same
policy from a **signed bundle**: each file is hashed, the manifest is signed with Ed25519 and
carries a `policy_revision` that must go up with every change (see [Rollback](#rollback)). APF also stamps provenance on every
sandbox (`apf.nvidia.com/*` annotations), refuses policy changes that do not come through a
bundle, and writes a JSONL audit trail.

| | `interceptor` (default) | `apf` |
|---|---|---|
| Serves | `governance-policy` ConfigMaps | signed bundle built from the same files |
| Images | `ghcr.io/validatedpatterns-sandbox/governance-interceptor` (public) | `ghcr.io/mkhaas/apf/*:0.1.0` (private; chart 0.2.0) |
| Policy change | edit `charts/governance-policy`, push | edit, **re-sign** (`make apf-bundle`), push |
| Runtime `openshell policy update` | validated | refused: "policy is managed by APF" |
| Gateway bindings | 4 RPCs (`allowlist`) | APF's own declarations (`dynamic`): 10 RPCs, incl. post-commit audit |

`charts/governance-policy` stays the only place policy is written. A profile APF cannot express
is left out of the bundle, with a message when signing: today that is `gemini`, whose API key goes
in a query parameter; APF credentials have no field for the parameter name, and OpenShell rejects
the whole catalog without it. Sandboxes on `apf` cannot use such a provider. `scripts/apf-bundle.py`
translates `policy.yaml` into APF's `SandboxPolicy` and each `profiles/<id>.yaml` into an APF
`Provider` named after the profile id (the provider type users create).

## The switch

`values-global.yaml`:

```yaml
global:
  governance:
    engine: apf        # or interceptor
```

It reaches two places:

- `charts/governance-interceptor` (app `governance-interceptor`): with `apf` it stops rendering
  its own Deployment and Service and renders instead
  - ConfigMaps `governance-apf-bundle` (the signed tarball) and `governance-apf-trust` (public key),
  - ExternalSecrets `ghcr-pull` (image pull secret), `governance-apf-signing` (the seed) and, in
    the Argo CD namespace, `governance-apf-chart-repo` (lets Argo CD pull the private OCI chart),
  - Argo CD Application `governance-apf`: the APF chart as release `governance-interceptor`
    (`fullnameOverride` keeps the Service name), `openshift: true`, pointed at the objects above,
  - the same NetworkPolicy, now selecting the APF pod.
- `charts/openshell-saw`, through `saw-users` (it passes `global.governance`): each gateway's
  `gateway.toml` uses `binding_policy = "dynamic"` for APF. APF declares one binding per phase
  (three each for `CreateSandbox` and `UpdateConfig`, 14 in all), which OpenShell's `allowlist`
  mode rejects ("declared multiple bindings"). In `dynamic` mode the gateway takes APF's own RPCs,
  phases and per-binding failure policy (fail-open for post-commit audit), limited to the RPCs
  OpenShell allows interceptors on. The endpoint and `fail_closed` do not change; the interceptor
  engine keeps `allowlist` and its four bindings.

`governance.bindings.apf` in `charts/openshell-saw/values.yaml` can narrow APF's bindings (empty:
all of them), and `governance.bindingPolicy` sets the mode per engine.

## Set up (pattern)

1. **GHCR access.** Ask @mkhaas for access to the `ghcr.io/mkhaas/apf` packages, and create a
   GitHub token (classic) with `read:packages`.
2. **Signing key.** `make apf-keys` writes the seed to `~/.apf-keys/apf.seed` (mode 600, never in
   git) and the public key to `charts/governance-interceptor/files/apf/apf.pub`.
3. **Bundle.** `make apf-bundle` signs `charts/governance-policy` into
   `charts/governance-interceptor/files/apf/bundle.tar.gz`. Commit both files to the branch your
   pattern deploys from (your fork or deployment branch).
4. **Secrets.** Uncomment the `ghcr` and `apf-signing` entries in `values-secret.yaml`
   (`~/.ghcr-token` holds the token) and load them (`./pattern.sh make load-secrets`, or install).
5. **Switch.** Set `global.governance.engine: apf`, push.

Argo CD then replaces the interceptor with APF, and every SAW app (pattern and portal
workspaces) re-renders its gateway config. **Running VMs do not pick it up on their own:**
KubeVirt marks them `RestartRequired` and the gateway keeps its old bindings until the VM
reboots. Restart them once `governance-interceptor` is Healthy:

```bash
make saw-restart-pending               # lists the VMs waiting for a restart
make saw-restart-pending CONFIRM=yes   # restarts them; their sandboxes stop meanwhile
```

`make saw-restart OPENSHELL_SAW_NAME=<user>` restarts one VM. Until a VM restarts, its gateway
calls APF with the interceptor's four `allowlist` bindings, or, after switching back, the
interceptor with APF's `dynamic` bindings.

Switching an existing install: the `governance-interceptor` app prunes (values-prod.yaml), so it
drops its Deployment and Service when the engine changes and the `governance-apf` app takes over
the Service name. Argo CD waits for the ExternalSecrets before it creates `governance-apf`, so
load the `ghcr` and `apf-signing` entries first; if a sync gave up meanwhile, sync the app again
(`oc -n vp-gitops patch application governance-interceptor --type merge -p '{"operation":{"sync":{}}}'`).
Switching back is the reverse, plus deleting the `governance-apf` Application, and again
`make saw-restart-pending CONFIRM=yes`: the restart is needed in both directions.

## Set up (quickstart)

```bash
make apf-keys apf-bundle                  # your own key and bundle, not committed upstream
helm uninstall governance-interceptor -n openshell-agents    # if the interceptor is installed
GHCR_USER=<github-user> GHCR_TOKEN=<token> make governance-apf
make saw-create OPENSHELL_SAW_NAME=alice GOVERNANCE_ENGINE=apf ...
```

An existing quickstart SAW keeps its engine until you run `make saw-create` for it again with
the new `GOVERNANCE_ENGINE` and restart its VM (`make saw-restart`).

`make governance-apf` creates the two Secrets, installs `charts/governance-interceptor` as
release `governance-apf-inputs` (bundle, trust root, NetworkPolicy), and the APF chart as release
`governance-interceptor` with the same values the pattern's Application uses.

## Changing policy

Edit `charts/governance-policy`, then `make apf-bundle` (it bumps `policy_revision` only when a
member changed) and commit the bundle with the change on your deployment branch. `make apf-bundle-check` verifies hashes,
the signature and that the bundle matches `charts/governance-policy`; with the pattern on `apf`
the test suite runs the same check, so a policy change without a re-signed bundle fails CI.
Only holders of the seed can change policy: that is the point of signing.

After `make apf-keys --force` (a new key), run `make apf-bundle` even when the policy did not
change: it notices that the bundle's signature no longer matches `apf.pub` and re-signs it with a
new revision.

### Rollback

APF refuses a bundle whose `policy_revision` is not above the last one it loaded, but it keeps
that counter in the pod (`/var/lib/apf`, an `emptyDir` in the APF chart, which has no setting to
persist it). Every new bundle rolls the pod, so a new pod would accept any validly signed
revision, including an older one. The check therefore also runs where the bundle comes from:
`make apf-bundle-check` and the test suite fail when the committed bundle's `policy_revision` is
not above every earlier commit of it, so reverting the bundle in git is caught before Argo CD
deploys it. To undo a policy change, revert `charts/governance-policy` and run `make apf-bundle`,
which signs the old policy with a revision above all of git history. A durable counter in the APF
pod needs an APF chart change (a `state` volume like `audit.persistence`).

APF reads the bundle at start: the chart restarts the APF pod when the ConfigMap changes
(its log says `bundle verified and loaded … counter=<policy_revision>`). Gateways pick up the
provider catalog when they restart.

APF puts the policy on a sandbox when it is created, and refuses changes afterwards. A sandbox
created before the new bundle keeps the old policy; recreate it to get the new one. Each sandbox
records which bundle it got in its `apf.nvidia.com/*` annotations (`bundle-id`,
`document-digest`, `policy-version`, and a `provenance-token` signed with your seed).

Example, verified live: `network_policies` in `charts/governance-policy/policy.yaml` let a
sandbox without providers reach a host. Before the change, `git clone https://github.com/...` in a
new sandbox was refused; after adding this, re-signing and pushing, a new sandbox cloned, while the
one created before still could not:

```yaml
network_policies:
  github_clone:
    name: github-clone
    endpoints:
      - { host: github.com, port: 443 }
    binaries:
      - { path: /usr/bin/git }
      - { path: /usr/lib/git-core/git-remote-http }   # what git uses for HTTPS (git-remote-https links to it)
```

`binaries` are the real executables: check them in the sandbox image with
`readlink -f $(command -v git)` and `readlink -f $(git --exec-path)/git-remote-https`.

## Keys

This repository ships no key and no bundle: `charts/governance-interceptor/files/apf/` is yours
to generate. A key in the shared chart would make every deployment trust bundles signed by one
person, and only that person could change policy. Each deployment makes its own key pair, keeps
the seed in Vault, and commits `apf.pub` and `bundle.tar.gz` to the branch its pattern deploys
from. With `engine: apf` and no bundle, the chart stops with a message pointing here.

The APF chart ships a demo key pair and uses it as the trust root when nothing else is given;
anyone with the chart can sign bundles against it. This setup never uses it: the trust root is
`apf.pub` from this repo and the seed comes from Vault. The key id stays `apf-dev` because the
APF chart mounts the files under that name.

`scripts/apf-bundle.py` signs exactly as `apf-compile genfixture` does (Ed25519 over the manifest
document, then a `YamlSigilSignature.v1alpha1` document); it reproduces APF's demo bundle byte for
byte, so no private image or Docker is needed to sign.

## Check on a cluster

Verified on OpenShift with OpenShell `0.1.2-rhaiv.0` and APF `0.1.0`: the gateway starts with
APF's 14 bindings (`gateway interceptors initialized bindings=14`), provider creation is validated,
the SAW profiles are served (except `gemini`, below), new sandboxes carry APF's provenance, and a
re-signed bundle changes new sandboxes' policy. Confirm these on a new install:

- The gateway starts with APF's bindings (the VM's gateway log: `interceptors initialized`); in
  `dynamic` mode every post-commit binding must come with `fail_open` from APF's manifest.
- **OpenShell 0.1.x (the SAW's BOM since v0.1.2-rhaiv.0).** The gateway negotiates the extension
  protocol (`PeerMetadata`, protocol 1.0) with every interceptor and stops at startup when an
  interceptor does not speak it ("did not provide protocol metadata"), so APF must be a build for
  OpenShell 0.1.x. That is why `apf.values` sets the 0.1.0 images: the APF chart's own 0.2.0
  images were built against 0.0.x and a 0.1.2 gateway refuses them (seen live). 0.1.0 is APF's
  crate version and its first 0.1.x build; the chart stays at 0.2.0.
- **Profile annotations ([NVIDIA/OpenShell#3929](https://github.com/NVIDIA/OpenShell/issues/3929)).**
  0.1.x hashes provider-profile annotations in map order, so a profile served with more than one
  annotation makes every sandbox with that provider fail ("Startup configuration did not
  stabilize"). The OpenShell interceptor build keeps one; check what APF puts on the profiles it
  serves.
- `openshell provider list-profiles` in a SAW shows the SAW profiles (APF serves the catalog
  through `SnapshotProviderProfiles`): `openai`, `nvidia`, `brave` and `web-search`. APF's Provider
  schema accepts only `type`, `endpoints`, `binaries` and `credentials` (name, envVars, required,
  style, header), so OpenShell's `inference_capable`, `category`, `discovery` and `query_param`
  are not in the bundle. OpenShell 0.1.x has no inference routing: the agent calls the provider's
  endpoint with a placeholder key, which needs the profile's `endpoints` and `binaries` (kept).
- `provider profile import` of a profile that is in the bundle is allowed or refused cleanly
  (the installer treats a refusal as non-fatal).
- The APF pod stays up with `interceptor.gatewayEndpoint` empty (SAW has a gateway per user VM,
  so APF has no single gateway to call back).

## Not covered

- Tier 2 (APF's egress content middleware on port 9099): needs TLS between the sandbox supervisor
  and APF, and `network_middlewares` in the policy.
- APF's Cedar rules, annotators and redaction effects: the bundle carries only the sandbox policy
  and provider profiles, which is what the interceptor enforced.
- Per-user or per-profile policy: APF injects one `default` policy, like the interceptor.
- A durable audit volume (`audit.persistence` in the APF chart).
- A durable anti-rollback counter in the APF pod: see [Rollback](#rollback).
- Harness bundles ([harness-bundles.md](harness-bundles.md)). Their mount relies on the patched
  interceptor admitting only the installer's read-only harness volume from an mTLS admin; APF has
  no such guard. With `engine: apf` the chart refuses `allowDriverConfig` (a user with
  `harnessEnabled`) and says so, rather than letting any caller attach the volume.
