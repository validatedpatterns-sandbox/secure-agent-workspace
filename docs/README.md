# Secure Agent Workspace — documentation

The Secure Agent Workspace (SAW) runs a per-user AI agent sandbox inside a
KubeVirt VM on OpenShift, deployed with Red Hat Validated Patterns and Argo CD
and governed by an admin-controlled policy. This folder is the reference documentation;
the repository [`README.md`](../README.md) has the pattern overview, the
quickstart, and the supported-provider and secrets tables.

## Start here

| Doc | What it covers |
|---|---|
| [Deployment guide](deployment-guide.md) | End-to-end deployment (GitOps and quickstart), network architecture, operator quick reference, live test |
| [Self-service portal — user guide](rhdh-user-guide.md) | Step-by-step: request a workspace from Red Hat Developer Hub, open its sandbox, and verify each step |

## Architecture & reference

| Doc | What it covers |
|---|---|
| [Architecture alignment](architecture-alignment.md) | How this implementation maps to NVIDIA's Secure Agent Workspace reference design — implemented, partial, and gaps |
| [BOM architecture](bom-architecture.md) | Visual overview of how a SAW is assembled from its Bill of Materials |
| [Versioned BOM installer](versioned-bom-installer.md) | The in-VM installer: what runs where, namespaces, upgrading, live inputs, signing, pruning |
| [Self-service portal (RHDH)](self-service-portal.md) | The Developer Hub portal: components, request flow, RBAC, keys, sandbox web UIs, settings |

## Governance (choose one engine)

| Doc | What it covers |
|---|---|
| [Governance interceptor](governance-interceptor.md) | The default engine — policy served from `charts/governance-policy` ConfigMaps |
| [APF governance](apf.md) | NVIDIA Agent Policy Fabric — the same policy served from a signed bundle (monotonic `policy_revision`) |

## Features & how-to

| Doc | What it covers |
|---|---|
| [Harness bundles](harness-bundles.md) | Ship skills, MCP servers and tool plugins into a sandbox |
| [Custom inference](custom-inference.md) | Point a SAW at your own OpenAI-compatible server (vLLM, Ollama, …) |
| [Container runtime](container-runtime.md) | Rootless podman (default) vs. docker (legacy) |
| [Container images](container-images.md) | CI-published images, mirroring, registries, retained Quay dependencies |
| [Signing](signing.md) | What is signed and how — installer bundle, BOM components, APF policy, images |

## Operations

| Doc | What it covers |
|---|---|
| [Network troubleshooting](troubleshooting.md) | Debugging egress, NetworkPolicy, EgressFirewall, routes and cleanup |

## Common tasks

| I want to… | See |
|---|---|
| Deploy the whole pattern end to end | [deployment-guide](deployment-guide.md) |
| Let users request their own workspace | [self-service-portal](self-service-portal.md) + [rhdh-user-guide](rhdh-user-guide.md) |
| Create a harness bundle (skills / MCP / tools) | [harness-bundles](harness-bundles.md) |
| Use my own model server | [custom-inference](custom-inference.md) |
| Build or mirror the container images | [container-images](container-images.md) |
| Switch podman ↔ docker | [container-runtime](container-runtime.md) |
| Apply a new installer / OpenShell version to a VM | [versioned-bom-installer → Upgrading](versioned-bom-installer.md#upgrading) |
| Turn on signed policy, or switch governance engine | [apf](apf.md) + [governance-interceptor](governance-interceptor.md) |
| Sign images, bundles and policy | [signing](signing.md) |
| Debug egress / NetworkPolicy / routes | [troubleshooting](troubleshooting.md) |
| See how this maps to NVIDIA's reference design | [architecture-alignment](architecture-alignment.md) |
