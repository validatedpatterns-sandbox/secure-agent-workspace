# APF governance (Agent Policy Fabric)

SAW gateways call one governance service, `governance-interceptor.openshell-agents.svc:18081`.
By default that is the OpenShell governance interceptor ([governance-interceptor.md](governance-interceptor.md)).
One switch replaces it with NVIDIA's **Agent Policy Fabric (APF)**, which serves the same
policy from a **signed bundle**: each file is hashed, the manifest is signed with Ed25519 and
carries a `policy_revision` that cannot go backwards. APF also stamps provenance on every
sandbox (`apf.nvidia.com/*` annotations), refuses policy changes that do not come through a
bundle, and writes a JSONL audit trail.

| | `interceptor` (default) | `apf` |
|---|---|---|
| Serves | `governance-policy` ConfigMaps | signed bundle built from the same files |
| Images | `quay.io/rh-ai-quickstart/governance-interceptor` (public) | `ghcr.io/mkhaas/apf/*:0.2.0` (private) |
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

Argo CD then replaces the interceptor with APF, and every SAW app re-renders its gateway
config, so each user VM restarts once with the new bindings.

Switching an existing install: the `governance-interceptor` app prunes (values-prod.yaml), so it
drops its Deployment and Service when the engine changes and the `governance-apf` app takes over
the Service name. Argo CD waits for the ExternalSecrets before it creates `governance-apf`, so
load the `ghcr` and `apf-signing` entries first; if a sync gave up meanwhile, sync the app again
(`oc -n vp-gitops patch application governance-interceptor --type merge -p '{"operation":{"sync":{}}}'`).
Switching back is the reverse, plus deleting the `governance-apf` Application.

## Set up (quickstart)

```bash
make apf-keys apf-bundle                  # your own key and bundle, not committed upstream
helm uninstall governance-interceptor -n openshell-agents    # if the interceptor is installed
GHCR_USER=<github-user> GHCR_TOKEN=<token> make governance-apf
make openshell-saw-create OPENSHELL_SAW_NAME=alice GOVERNANCE_ENGINE=apf ...
```

`make governance-apf` creates the two Secrets, installs `charts/governance-interceptor` as
release `governance-apf-inputs` (bundle, trust root, NetworkPolicy), and the APF chart as release
`governance-interceptor` with the same values the pattern's Application uses.

## Changing policy

Edit `charts/governance-policy`, then `make apf-bundle` (it bumps `policy_revision` only when a
member changed) and commit the bundle with the change on your deployment branch. `make apf-bundle-check` verifies hashes,
the signature and that the bundle matches `charts/governance-policy`; with the pattern on `apf`
the test suite runs the same check, so a policy change without a re-signed bundle fails CI.
Only holders of the seed can change policy: that is the point of signing.

APF reads the bundle at start: the chart restarts the APF pod when the ConfigMap changes.
Gateways pick up the provider catalog when they restart.

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

These depend on APF 0.2.0 behaviour the chart and README do not spell out, so confirm them on the
first install:

- The gateway starts with APF's bindings (the VM's gateway log: `interceptors initialized`); in
  `dynamic` mode every post-commit binding must come with `fail_open` from APF's manifest.
- **OpenShell 0.1.x (the SAW's BOM since v0.1.2-rhaiv.0).** The gateway negotiates the extension
  protocol (`PeerMetadata`, protocol 1.0) with every interceptor and stops at startup when an
  interceptor does not speak it, so APF must be a release built for OpenShell 0.1.x; 0.2.0 was
  built against 0.0.x and is not verified with it.
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
- Harness bundles ([harness-bundles.md](harness-bundles.md)). Their mount relies on the patched
  interceptor admitting only the installer's read-only harness volume from an mTLS admin; APF has
  no such guard. With `engine: apf` the chart refuses `allowDriverConfig` (a user with
  `harnessEnabled`) and says so, rather than letting any caller attach the volume.
