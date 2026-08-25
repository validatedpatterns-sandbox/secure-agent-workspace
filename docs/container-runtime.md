# Container Runtime Support: Docker and Podman

The gateway VM supports two container runtimes, selectable at deploy time via a single Helm value.
No golden image rebuild is required to switch — both images are pre-built and available.

## Runtimes

| Runtime | Golden image | Use case |
|---|---|---|
| `docker` (default) | `openshell-gateway-docker` | NemoClaw onboarding, internal-registry sandbox images |
| `podman` | `openshell-gateway` | openclaw, opencode, and any external sandbox image (ghcr.io, quay.io) |

## Choosing a runtime

The runtime is determined by `onboardCli`:

- **NemoClaw** requires Docker. NemoClaw's preflight check rejects Podman at startup.
- **openclaw / opencode** work with either runtime. Podman is the Fedora default — no extra packages.

Set `containerRuntime` to match:

```yaml
# docker: required for NemoClaw
containerRuntime: docker
onboardCli: nemoclaw

# podman: use for openclaw, opencode, or any external sandbox image
containerRuntime: podman
onboardCli: openclaw
```

Mixing `containerRuntime: podman` with `onboardCli: nemoclaw` is rejected at setup time with an explicit error.

## What changes between runtimes

### Golden image (`image-builder-charts/helm/openshell-gateway-image`)

| Step | Docker | Podman |
|---|---|---|
| Packages | Removes Podman, installs Docker CE | Keeps Fedora-default Podman |
| Runtime service | `docker.service` enabled | `podman.socket` enabled (user-level, rootless) |
| GRPC bridge IP | `172.17.0.1` (Docker bridge default) | `10.88.0.1` (Podman bridge default) |
| Sandbox driver env | `OPENSHELL_DRIVERS=docker` | `OPENSHELL_DRIVERS=podman` |

### Helm chart (`charts/openshell-saw`)

| Resource | Docker | Podman |
|---|---|---|
| DataSource | `openshell-gateway-docker` | `openshell-gateway` |
| cloud-init `OPENSHELL_DRIVERS` | `docker` | `podman` |
| Registry auth | `docker login` to internal OpenShift registry | skipped — external images only |
| Binary extraction | `docker pull/create/cp/rm` | `podman pull/create/cp/rm` |
| Dashboard systemd units | `/usr/bin/docker run` | `/usr/bin/podman run` |
| Sandbox pre-pull | `sudo docker pull` | `sudo podman pull` |

## Building the golden images

```bash
# Docker variant — required for NemoClaw
make build-gateway-docker

# Podman variant — for openclaw/opencode
make build-gateway-podman
```

Each produces a separate ImageStream, DataVolume, and DataSource on the cluster.
Both can coexist in the same namespace.

## Deploying a sandbox

```bash
# Docker runtime + NemoClaw
make openshell-saw-create \
  OPENSHELL_SAW_NAME=my-sandbox \
  CONTAINER_RUNTIME=docker \
  PROVIDER=build MODEL=nvidia/nemotron-3-super-120b-a12b API_KEY=<nvapi-key>

# Podman runtime + openclaw
make openshell-saw-create \
  OPENSHELL_SAW_NAME=my-sandbox \
  CONTAINER_RUNTIME=podman \
  PROVIDER=build MODEL=nvidia/nemotron-3-super-120b-a12b API_KEY=<nvapi-key>
```

Switching an existing sandbox requires a values change and VM recreate:

```bash
helm upgrade <release> charts/openshell-saw --set containerRuntime=podman
# Then delete and recreate the VM by uninstalling and reinstalling the release.
```

## Connecting to the TUI

The gateway uses mTLS. The self-signed server certificate is only valid for `127.0.0.1`, so
external route access (e.g. opening the gateway URL in a browser) won't work for the CLI.
Use a port-forward instead.

### Step 1 — Copy the mTLS client certs from the VM (once per sandbox)

```bash
SANDBOX=<your-sandbox-name>   # e.g. test-docker
NS=openshell-agents

mkdir -p ~/.config/openshell/gateways/${SANDBOX}/mtls

for f in ca.crt tls.crt tls.key; do
  [[ "$f" == "ca.crt" ]] \
    && src="/home/cloud-user/.local/state/openshell/tls/ca.crt" \
    || src="/home/cloud-user/.local/state/openshell/tls/client/${f}"
  virtctl -n ${NS} scp \
    cloud-user@vm/${SANDBOX}:${src} \
    ~/.config/openshell/gateways/${SANDBOX}/mtls/${f} \
    --identity-file=~/.generated-ssh-keys/sandbox-ssh \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null
done

chmod 600 ~/.config/openshell/gateways/${SANDBOX}/mtls/*

cat > ~/.config/openshell/gateways/${SANDBOX}/metadata.json <<EOF
{"name":"${SANDBOX}","gateway_endpoint":"https://127.0.0.1:17670","is_remote":false,"gateway_port":17670,"auth_mode":"mtls"}
EOF
```

### Step 2 — Start port-forward (keep this terminal open)

```bash
oc port-forward svc/${SANDBOX}-gateway 17670:17670 -n openshell-agents
```

### Step 3 — Verify gateway and sandbox are reachable

```bash
openshell gateway select ${SANDBOX}
openshell sandbox list
# Should show the sandbox in Ready or Unspecified phase
```

### Step 4 — Open the TUI

```bash
ssh \
  -o "ProxyCommand=openshell --gateway ${SANDBOX} ssh-proxy --gateway-name ${SANDBOX} --name ${SANDBOX}" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -tt sandbox@openshell-${SANDBOX}.default openclaw
```

> **Note:** The cert-copy step (Step 1) requires `virtctl`. A follow-up improvement is to
> have the setup Job publish the mTLS client cert as a k8s Secret so the local setup can be
> done with `oc extract secret/...` instead.

## Known limitations

**NemoClaw and Podman are incompatible.** NemoClaw's preflight check (`nemoclaw onboard`) requires Docker and will exit at step 1 with `Docker is not reachable` on a Podman image. This is expected. Use `onboardCli: openclaw` with `containerRuntime: podman`.

**The `inference.local` route** (NemoClaw's LLM routing inside the openclaw sandbox) requires the OpenShell gateway to be in Docker-driver mode (openshell ≤ 0.0.97). With the externally-supervised gateway (0.0.99+), `nemoclaw onboard` reaches step 4 then exits with `OpenShell inference route was not configured`. The provider fallback in `setup-nemoclaw.sh` handles this gracefully — inference still works via the gateway-level `inference` provider.

**The `nemoclaw-sandbox` image** must be available in the cluster before the setup Job runs. Either build it with `make build-nemoclaw` or mirror it from `quay.io/rh-ai-quickstart/nemoclaw-sandbox:<version>` using an in-cluster skopeo job (see Bug #1 in `local-docs/deployment-summary.md`).

## Risks

- **Network namespace differences** — Docker uses `172.17.0.0/16`, Podman uses `10.88.0.0/16`. The GRPC endpoint is derived automatically at first boot.
- **Rootless vs rooted** — Podman runs rootless (user socket at `/run/user/1000/podman/podman.sock`). Dashboard containers using `podman run` may need `--userns=keep-id` for correct UID mapping.
- **Two images to maintain** — both golden images need rebuilds when the base Fedora version or OpenShell version changes.

## GPU passthrough (optional, off by default)

Both runtimes can be built with an NVIDIA driver + Container Toolkit baked in for GPU-passthrough
VMs (`gpu.enabled: true` on the `openshell-gateway-image` chart). Docker uses `nvidia-ctk runtime
configure --runtime=docker`; Podman uses the CDI path (`nvidia-ctk cdi generate`) exclusively, since
Podman has no `--gpus` flag equivalent. See [docs/gpu-passthrough.md](gpu-passthrough.md) for the
full runbook, hardware requirements, and a live-validated Podman+CDI example.
