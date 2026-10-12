# Container images

Project CI publishes public images to `ghcr.io/<lowercase repository owner>/`.
The shipped defaults use the upstream project's public namespace,
`ghcr.io/validatedpatterns-sandbox`. Fork CI publishes under the fork owner;
consuming a fork requires overriding the Make and Helm image references.
These upstream deployment defaults are intentional: running CI in a fork does
not change the source of shipped images. Fork CI never publishes into the
upstream namespace. To test a fork's publications, set
`IMAGE_REPO=ghcr.io/<lowercase fork owner>` for mirror and build commands, and
override the gateway disk source, installer `bom.spec.nemoclaw.cliImage`,
interceptor `image`, and SAW-BOM profile image references listed below. Keep
those deployment overrides local when preparing changes for upstream.

| Image | CI tags | Consumers |
| --- | --- | --- |
| `openshell-gateway` | `latest`, `sha-<commit>` | Podman VM disk, `make images-mirror`, golden image import |
| `openshell-gateway-docker` | `latest`, `sha-<commit>` | Docker VM disk, `make gateway-build-docker` |
| `nemoclaw-cli` | `latest`, `sha-<commit>` | Installer BOM `spec.nemoclaw.cliImage` |
| `nemoclaw-sandbox` | `latest`, `sha-<commit>` | Data-science default and CUDA profiles |
| `governance-interceptor` | `latest`, `sha-<commit>`, OpenShell ref (currently `v0.1.2`) | Interceptor deployment and image builder |
| `saw-harness-<bundle>` | Bundle version, `sha-<commit>` | Optional digest-pinned `harnessRef.image` |

Pull requests build without registry credentials or pushing. Publishing is
restricted to `main`, including manual workflow dispatches. Every push verifies
the published commit tag with an empty Docker auth configuration (harness builds
check their signed digest): a private package
fails CI. CI adds the repository source label to associate its packages with the
repository. GHCR can create packages as private initially: a package administrator
must set each package's visibility to **Public** in its GitHub package settings,
including newly added harness bundles. Public pulls need no registry Secret.
Publishing uses `GITHUB_TOKEN` with `packages: write`.
The first publication of a new package can therefore fail its public-pull
check after the image is pushed. Set it to Public, then rerun the workflow.
GitHub's documented [package REST API](https://docs.github.com/en/rest/packages/packages)
does not expose a visibility-update endpoint; visibility is an administrator
setup step in [package settings](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).
Harness images are signed before the public-pull check, so a visibility failure
does not skip signing an otherwise successfully published image.

NemoClaw and governance builds share recipes between GitHub Actions and
OpenShift. The canonical CLI and governance Dockerfiles live under their
image-builder chart's `files/` directory; GitHub builds these directly and
Helm embeds the same files in the BuildConfigs. Build parameters come from
each chart's `values.yaml`. Governance uses `build.runtimeImage` for OpenShift
(UBI9 Micro) and `build.ghcrRuntimeImage` for GHCR (the Debian runtime stage).

The sandbox uses the upstream Dockerfile at the chart's pinned source ref.
The discovery manifests, lockfile, Dockerfile, and audited install script live in
`nemoclaw-imagestream/files/`; generated bundles are never committed or put in a
ConfigMap. CI runs the script before building the sandbox, writing the three
artifacts directly into the directory copied by the upstream Dockerfile.

`make sandbox-build` first builds `nemoclaw-discovery-runtime`. It captures that
specific Build's name, follows its logs, tolerates log-streaming errors, and polls
until a terminal phase (with a 30-minute limit). It requires `Complete` and a valid
output digest. It then supplies the artifact image as `source.discoveryImage`
(`image-registry.../nemoclaw-discovery-runtime@sha256:...`). The sandbox BuildConfig
copies `/reviewed-runtime-bundle/mcp-tool-discovery/.` from that digest into its
Git context through `source.images`. Without a digest, the chart creates only the
discovery BuildConfig; tags, image-change triggers, and failed builds cannot
silently select artifacts from an earlier build. Every invocation builds discovery
again before building the sandbox. The first Helm upgrade clears
`source.discoveryImage`, removing any existing `nemoclaw-sandbox` BuildConfig and
its build history; the second upgrade recreates it with the new discovery digest.

CI and the cluster discovery builder use the same Node version from
`build.discoveryNodeVersion`, the same discovery lockfile, and the same install
recipe. The cluster builder uses the official Docker Hub Node image for that
version, pinned by the multi-platform digest in `build.discoveryNodeDigest`.
Update the version and digest together, including the Dockerfile defaults. The
digest prevents tag drift; Docker Hub pull rate limits still apply. This
guarantees shared inputs and checks, not byte-identical output
across platforms. Discovery runs `npm ci`, registry-signature verification,
`npm audit --audit-level=high`, tests, and typechecks. The pinned upstream sandbox
Dockerfile installs the MCPorter lockfile with `npm ci` and invokes
`verify-mcporter-audit.sh`, whose reviewed audit policy uses the high threshold
and supports verified audit receipts. That MCPorter audit is upstream-owned;
its small lockfile ConfigMap is unchanged.

Gateway GitHub CI also installs the bundle verifier, checksum-verified Cosign,
and optional signing floor already supplied by the OpenShift recipe.

```sh
# Exact selected tag; missing tags fail without falling back to latest.
make images-mirror IMAGE_TAG=sha-<commit>
# Select Docker's disk image explicitly when mirroring it.
make images-mirror MIRROR_IMAGES=openshell-gateway-docker
# Inspect without registry credentials.
skopeo inspect --no-creds docker://ghcr.io/validatedpatterns-sandbox/nemoclaw-cli:latest
```

`IMAGE_REPO` replaces the former `QUAY_REPO` option; `IMAGE_TAG` replaces the
former `OPENSHELL_VERSION` mirror/build tag option. These image tags do not select
the OpenShell release inside the VM: that is pinned separately by the installer
BOM. The default internal golden-image reference remains `:latest`; mirroring
stores the exact selected tag and adds this alias. Changing the disk source
only affects new VM disks. To roll back, select a previous `sha-<commit>` tag or
GHCR digest and recreate the VM disk using the documented workspace lifecycle.

Manual cluster builds keep images in the internal registry by default. To publish,
explicitly set `IMAGE_REPO=ghcr.io/<your-owner>`; the upstream namespace
`ghcr.io/validatedpatterns-sandbox` is refused because CI owns its tags.
The mirror command still defaults to that upstream namespace. Authenticate to GHCR with a token
that can write packages using `oc registry login --registry=ghcr.io`; the push
script uses the current containers auth file. For the interceptor BuildConfig,
create a Docker registry Secret named `ghcr-push-secret` in `BUILD_NS`, or override
`output.pushSecretName`. `governance-interceptor-build-local` remains available as a local-only build
and needs no GHCR push credentials. A fork interceptor build also needs
`charts/governance-interceptor`'s `image` override.

## Intentionally retained Quay dependencies

These images are supplied by other projects and are not built by this project's
CI. Rewriting their registry would point at unverified or nonexistent images.

| Quay path | Reason retained |
| --- | --- |
| `quay.io/opendatahub/odh-openshell-{cli,gateway,supervisor,sandbox}` | Versioned OpenShell component images; installer BOM and gateway-image builder pins. The CI-built `openshell-gateway` is a VM disk, not a replacement for the gateway component image. |
| `quay.io/aipcc/base-images/agentic/openclaw` | Digest-pinned standalone OpenClaw sandbox in the BOM profiles. |
| `quay.io/gkrumbach07/openshell-dashboard` | External dashboard running inside the VM. |
| `quay.io/oauth2-proxy/oauth2-proxy` | External dashboard and sandbox UI authentication proxy. |
| `quay.io/validatedpatterns/*` | External Validated Patterns tooling and framework images/charts, including `utility-container`, `patternizer`, `imperative-container`, `pattern-install`, and the operator UI catalog. |

The gateway builder's `registries.yaml` entry for `quay.io/opendatahub` supports
signature attachments for these retained upstream components. Historical signing
observations and registry-neutral test fixtures can also mention Quay.
Disconnected deployments must mirror both GHCR images and these dependencies.
