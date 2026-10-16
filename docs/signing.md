# Signing

SAW has three independent signing layers. Each protects a different artifact
and is configured in a different place; this page says what each one covers and
links to the authoritative detail.

| Layer | Protects | Mechanism | Authoritative doc |
|---|---|---|---|
| Installer bundle + BOM components | What the gateway VM installs and runs | cosign/sigstore (bundle) + per-pull podman policy (components) | [versioned-bom-installer.md](versioned-bom-installer.md#signing) |
| APF policy bundle | The governance policy served to gateways | Ed25519 over a per-file manifest, monotonic `policy_revision` | [apf.md](apf.md) |
| Container images | Harness-bundle images (others are not signed yet) | cosign on harness-bundle images (keyless); component verification pending the publisher key | [container-images.md](container-images.md) |

## 1. Installer bundle and BOM components

The in-VM installer tree (`installer-bom.yaml`, `apply_bom.py`,
`setup-dashboard.sh`, and the shipped provider profiles) is signed as one
bundle, and each OpenShell component image named in the BOM can require its own
signer.

- **Mode.** `signing.mode` is `off`, `warn`, or `enforce` (chart default
  `warn`); the *effective* mode is the stricter of that and a floor the golden
  image pins at `/etc/saw/signing-mode`. Build a production image with
  `signing.floor: enforce` so a namespace editor cannot set `mode: off` next to
  a modified `apply_bom.py`.
- **Bundle.** `/usr/libexec/saw/verify-bundle` checks a cosign signature over a
  manifest of `<sha256>  <path>` lines before `apply_bom.py` runs from a
  root-owned, verified copy. The private key is the GitHub Actions secret
  `COSIGN_PRIVATE_KEY`; the public key lives in the golden image under
  `/etc/saw/trust` and in `signing.trustKeys`. CI signs with
  `.github/workflows/sign-installer-bundle.yml`.
- **Components.** For each BOM component with a `signature`, `apply_bom.py`
  builds a one-image podman policy (`keyRef` → `/etc/saw/trust/<keyRef>.pub`)
  and pulls that digest under it. Keyless `identity`/`issuer` is accepted as a
  BOM shape but **always fails verification today** — use `keyRef`.

Full detail, including the floor, the manifest format, key custody and
rotation: [versioned-bom-installer.md → Signing](versioned-bom-installer.md#signing).

## 2. APF policy bundle

With `GOVERNANCE_ENGINE=apf`, the policy in `charts/governance-policy` is served
from a signed bundle instead of plain ConfigMaps. `make apf-bundle` hashes each
file, signs the manifest with Ed25519, and sets a `policy_revision` that must
increase on every change (anti-rollback). Only a holder of the seed can change
policy.

```bash
make apf-keys          # seed -> ~/.apf-keys/apf.seed (600); public key -> charts/.../apf/apf.pub
make apf-bundle        # sign charts/governance-policy -> charts/.../apf/bundle.tar.gz
make apf-bundle-check  # verify hashes, signature, and that policy_revision only ever rises
```

Commit `apf.pub` and `bundle.tar.gz` to the branch your pattern deploys from.
The default `interceptor` engine serves the same files **without** signing.
Full detail, including rollback and provenance:
[apf.md](apf.md) (see [Keys](apf.md#keys) and [Rollback](apf.md#rollback)).

## 3. Container images

Of the images CI publishes to GHCR, only the **harness-bundle** images
(`saw-harness-<bundle>`) are cosign-signed — keyless, in
`.github/workflows/harness-bundles.yml`, before their public-pull check, so a
visibility failure never skips signing. The gateway, NemoClaw and
governance-interceptor images are **not** signed today. (The installer bundle
is signed separately and key-based — see section 1.)

Component-image *verification* on the VM is wired but still waits on the
OpenShell publisher key:

- Retained `quay.io/opendatahub/odh-openshell-*` digests carry key-based cosign
  signatures (not Fulcio keyless). The golden image installs a checksum-pinned
  `cosign` and ships `/etc/containers/registries.d/saw.yaml`
  (`use-sigstore-attachments: true` for `quay.io/opendatahub`) to fetch them,
  but the publisher key is not yet in `/etc/saw/trust`, so keep
  `signing.mode: warn` until it is known.
- `skopeo inspect --no-creds docker://ghcr.io/validatedpatterns-sandbox/<image>:<tag>`
  only checks that an image is publicly pullable — it is the public-pull check
  from [container-images.md](container-images.md), not a signature check.

Detail on CI signing and the retained dependencies:
[container-images.md](container-images.md).
