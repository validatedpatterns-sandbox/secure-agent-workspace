# Running on an arm64 cluster

OpenShift Virtualization runs guests on the host architecture. On an arm64 cluster, the golden VM disk, in-VM components, sandbox images, and pattern pods must all have arm64 builds.

## Images

- The InstallerBOM pins the OpenShell CLI, gateway, supervisor, and sandbox runtime at `0.1.6-rhaiv.4` by multi-architecture index digest. Podman pulls the VM architecture.
- `make images-mirror` copies the multi-architecture Podman golden disk; each node pulls its own architecture. To build the disk on the cluster instead, run `make gateway-build-podman`. The build picks the Fedora Cloud image and cosign by the build node's architecture. The optional Docker disk (`openshell-gateway-docker`) is x86_64 only; ARM clusters use the default Podman runtime. Without an explicit `IMAGE_REPO`, the result stays in the internal registry. Check an existing image and DataVolume before rebuilding: a new build replaces the shared golden image tag.
- The `build-openshell-gateway` workflow builds the Podman disk on amd64 and arm64 and merges their digests into one GHCR tag. The `build-governance-interceptor`, `build-nemoclaw-sandbox`, and `build-nemoclaw-cli` workflows do the same for their images. Check a published tag with `oc image info --show-multiarch <image>` before relying on it. Until the interceptor's GHCR tag includes arm64, run `make governance-interceptor-build-local` and set the `governance-interceptor` application's `image` override to the resulting in-cluster ImageStream tag.
- The NemoClaw sandbox and CLI defaults use GHCR. If their GHCR tags do not yet include arm64, `make sandbox-build` and `make cli-build` build for the cluster architecture. `sandbox-build` detects a single architecture among schedulable nodes and sets the upstream Dockerfile's required `TARGETARCH`; on a mixed cluster, set `BUILD_ARCH=arm64` or `amd64`. The BuildConfig pins its pod to the selected architecture. Set `IMAGE_REPO` to a namespace you control only when you intend to publish; verify the pushed digest and update the workspace image values. The Makefile refuses the upstream namespace.

- `saw-credential-proxy` builds natively on amd64 and arm64. The chart default pins the published multi-architecture index, so arm64 needs no image override. Overrides must be digest-pinned; use an index digest for multi-arch images. An in-cluster PR build is single-arch; override `defaults.openshellSaw.credentialProxy.image` with that build's digest only on a matching cluster.

## Cluster preparation

Ensure the internal image registry is available with persistent storage before building. Confirm the OpenShift Virtualization, Keycloak, RHDH, External Secrets, and Pipelines operators support your OpenShift version and architecture. Check the golden ImageStreamTag and DataVolume before creating workspaces. Use the normal pattern install workflow only for a new deployment; preserve the existing Pattern CR and workspaces during an upgrade.

GPU passthrough has separate requirements and is not covered by this guide.
