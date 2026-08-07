# Switch sandbox runtime from Podman to Docker

**Project:** APPENG
**Type:** Story
**Epic:** Secure Agent Workspace Validated Pattern
**Priority:** High
**Component:** RH_AI_Blueprints
**Labels:** secure_agent_workspace, nemoclaw, docker, openshell

## Summary

Replace Podman with Docker as the container runtime for the OpenShell gateway VM. NemoClaw's onboarding CLI (`nemoclaw onboard`) requires Docker Engine — it explicitly rejects Podman. The current golden image ships with Podman which blocks the NemoClaw onboarding flow and forces manual workarounds.

> **Note:** This is a **stop-gap solution** to unblock NemoClaw onboarding in the near term. NemoClaw is actively working on Podman support (tracked in upstream issue #7883 / epic #7744). Once NemoClaw supports Podman natively, we should revert to Podman as the primary container runtime — Podman is preferred for OpenShift environments due to its rootless, daemonless architecture and better alignment with OpenShift's security model.

## Background

- NemoClaw `onboard` checks for Docker at preflight and fails with: *"Podman is not supported for this NemoClaw integration path. Switch to Docker Engine."*
- The OpenShell gateway's `OPENSHELL_DRIVERS` env var must be set to `docker` (default auto-detection picks Podman first when both are present).
- The OpenShell supervisor 0.0.99 fixes the `/sandbox/.profile` Permission denied issue that affected Podman-based sandboxes, but the NemoClaw CLI still requires Docker.

## Acceptance Criteria

1. Golden gateway VM image ships with Docker CE instead of Podman.
2. `nemoclaw onboard --non-interactive` completes successfully on a fresh VM.
3. Sandbox creation via `openshell sandbox create --from <image>` uses Docker driver.
4. All images are tagged with the OpenShell version (e.g., `v0.0.97-rhaiv.0`) in quay.io for traceability.
5. Gateway and supervisor images are configurable via Helm values and can be upgraded independently.

## Implementation Plan

### 1. Update golden gateway image build (`openshell-gateway-image` chart)

**Files:** `image-builder-charts/helm/openshell-gateway-image/`

- **Replace Podman with Docker in the Dockerfile:**
  - Remove: `podman`, `podman-docker`
  - Add: Docker CE repo and install `docker-ce`, `docker-ce-cli`, `containerd.io`
  - Enable Docker service: `systemctl enable docker`
  - Add `cloud-user` to `docker` group: `usermod -aG docker cloud-user`

- **Update gateway environment (`gateway.env` template):**
  - Change `OPENSHELL_DRIVERS=podman` to `OPENSHELL_DRIVERS=docker`
  - Update `OPENSHELL_GRPC_ENDPOINT` if Docker uses a different network namespace

- **Update image references to configurable versions:**
  ```yaml
  openshell:
    version: "0.0.97+rhaiv.0"
    gatewayImage: "quay.io/opendatahub/odh-openshell-gateway:v0.0.97-rhaiv.0"
    supervisorImage: "quay.io/opendatahub/odh-openshell-supervisor:v0.0.97-rhaiv.0"
  ```

- **Tag the built gateway image with the OpenShell version:**
  - Push to `quay.io/rh-ai-quickstart/openshell-gateway:v0.0.97-rhaiv.0` (not just `:latest`)
  - The `push-image.sh` script should push both `:latest` and the versioned tag

### 2. Update NemoClaw sandbox image build (`nemoclaw-imagestream` chart)

**Files:** `image-builder-charts/helm/nemoclaw-imagestream/`

- Keep the chained BuildConfig (root build + `USER sandbox` layer).
- Add `RUN chown -R sandbox:sandbox /sandbox` in the chained BuildConfig.
- Tag the built image with the OpenShell version: `nemoclaw-sandbox:v0.0.97-rhaiv.0`.
- Push to `quay.io/rh-ai-quickstart/nemoclaw-sandbox:v0.0.97-rhaiv.0`.

### 3. Update NemoClaw CLI image build (`nemoclaw-cli-imagestream` chart)

**Files:** `image-builder-charts/helm/nemoclaw-cli-imagestream/`

- Tag the built image with the OpenShell version: `nemoclaw-cli:v0.0.97-rhaiv.0`.
- Push to `quay.io/rh-ai-quickstart/nemoclaw-cli:v0.0.97-rhaiv.0`.

### 4. Update `copy-images` Makefile target

**Files:** `Makefile-quickstart`

- Mirror versioned tags in addition to `:latest`.
- Add the version tag to the internal registry imagestreams.

### 5. Update sandbox setup flow (`configmap-scripts.yaml`)

**Files:** `charts/openshell-saw/templates/configmap-scripts.yaml`

- **Sandbox creation:** Use `openshell sandbox create --from <image>` (already done in `fix/nemoclaw-onboard-permissions`).
- **NemoClaw onboarding:** After sandbox creation, run `nemoclaw onboard` non-interactively inside the VM:
  ```bash
  NEMOCLAW_PROVIDER=${NEMOCLAW_PROVIDER} \
  NEMOCLAW_MODEL=${NEMOCLAW_MODEL} \
  ${CRED_ENV}=${NEMOCLAW_API_KEY} \
  NEMOCLAW_NON_INTERACTIVE=1 \
  NEMOCLAW_YES=1 \
  NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 \
  NEMOCLAW_SANDBOX_NAME=${SANDBOX_NAME} \
  nemoclaw onboard \
    --non-interactive \
    --name "${SANDBOX_NAME}" \
    --agent "${NEMOCLAW_AGENT}" \
    --yes \
    --yes-i-accept-third-party-software
  ```
- **Remove the `openshell provider create` path** — NemoClaw onboard handles provider configuration inside the sandbox.
- **Remove the `openclaw onboard` path** — NemoClaw CLI replaces it.
- **Docker auth:** Ensure Docker is authenticated to the internal registry before sandbox creation (the setup job already does this for Podman; switch to `docker login`).

### 6. Update gateway VM startup (`openshell-gateway-user-setup.sh`)

**Files:** `image-builder-charts/helm/openshell-gateway-image/templates/`

- Ensure the gateway systemd service starts after Docker: `After=docker.service`
- Set `OPENSHELL_DRIVERS=docker` in the gateway environment file.

### 7. Update Helm values for version tracking

**Files:** `charts/openshell-saw/values.yaml`, `image-builder-charts/helm/*/values.yaml`

- Add `openshell.version` field that controls the image tag for all components.
- Gateway/supervisor images should reference `quay.io/opendatahub/odh-openshell-gateway:v0.0.97-rhaiv.0`.
- The version should be a single value that propagates to all image tags.

## Image Tagging Convention

| Image | Registry | Tag Format | Example |
|-------|----------|------------|---------|
| Gateway VM (qcow2) | quay.io/rh-ai-quickstart/openshell-gateway | v{version} | v0.0.97-rhaiv.0 |
| NemoClaw sandbox | quay.io/rh-ai-quickstart/nemoclaw-sandbox | v{version} | v0.0.97-rhaiv.0 |
| NemoClaw CLI | quay.io/rh-ai-quickstart/nemoclaw-cli | v{version} | v0.0.97-rhaiv.0 |
| Gateway binary | quay.io/opendatahub/odh-openshell-gateway | v{version} | v0.0.97-rhaiv.0 |
| Supervisor binary | quay.io/opendatahub/odh-openshell-supervisor | v{version} | v0.0.97-rhaiv.0 |

All images are also pushed with `:latest` for convenience. The versioned tag is the source of truth.

## Testing

1. `make build-openshell-gateway` — builds golden image with Docker, pushes versioned tag.
2. `make build-nemoclaw` — builds sandbox image, pushes versioned tag.
3. `make build-nemoclaw-cli` — builds CLI image, pushes versioned tag.
4. `make copy-images` — mirrors versioned images to internal registry.
5. Pattern install on a fresh cluster — VM boots with Docker, `nemoclaw onboard` succeeds non-interactively.
6. `nemoclaw <name> connect` — opens a shell without `.profile` Permission denied.
7. `nemoclaw <name> dashboard-url` — returns accessible dashboard URL.

## Dependencies

- OpenShell gateway/supervisor v0.0.97-rhaiv.0 images available on quay.io/opendatahub.
- Docker CE available in Fedora 44 repos (via docker-ce.repo).
- NemoClaw CLI compatible with OpenShell 0.0.97.

## Risks

- Docker requires root daemon; Podman was rootless. The VM runs as a dedicated user so this is acceptable.
- Docker group membership grants root-equivalent access to the daemon — acceptable for single-tenant sandbox VMs.
- The `docker-ce.repo` must be added during the golden image build (not available in default Fedora repos).
