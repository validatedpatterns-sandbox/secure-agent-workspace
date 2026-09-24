# Astra SAW VM deployment discovery

Date: 2026-09-17  
Repository baseline: `f7046f4`  
Status: Repository discovery and proposed requirements; Astra integration has not been validated.

## Purpose and scope

Review the five deployment concerns and identify the work required to provision and maintain a Secure Agent Workspace (SAW) VM through reusable images and declarative configuration in Astra.

This review covers the local charts, image builders, setup scripts, and BOM application code. It does not include a live deployment test, an assessment of Astra APIs, or verification of behavior inside external runtime images. Astra's image and configuration delivery contracts remain discovery questions.

Terminology: a **SAW VM** hosts an OpenShell gateway; a **workspace** groups runtime resources; a **sandbox** is an agent container managed by OpenShell inside that VM. Creating more VMs and creating more sandboxes within a VM are separate requirements.

## Findings at a glance

The repository provides reusable VM provisioning and YAML-driven initial sandbox creation. The main missing capability is a managed path from updated desired configuration to the running VM, sandboxes, and agent harnesses, with observable convergence and defined update behavior.

| Concern | Repository finding | Remaining requirement |
|---|---|---|
| Reusable Astra VM template image | A parameterized golden-image builder, CDI import, and VM cloning already exist. Per-instance Helm inputs are supported. | Package and validate an Astra image blueprint and instance contract. A fork per VM is not required by the inspected provisioning code. |
| VM initializes itself from external configuration | Cloud-init configures and starts the gateway, but the setup Job still performs substantial work over SSH and `virtctl`. | Boot a usable SAW from externally supplied configuration without an external SSH setup sequence. |
| Configuration updates reconcile automatically | The BOM is copied into the VM and applied during setup. Existing healthy sandboxes are skipped during creation. | Detect revisions, compare desired and actual state, apply supported changes, and report success or failure. |
| Multiple sandboxes through YAML | BOM profiles already declare lists of workspaces, providers, and sandboxes. | Support dynamic additions, updates, disabling, and removal without editing or manually rerunning setup scripts. |
| Harness skills and tools through YAML | Harness-specific onboarding and some image-time tool/plugin configuration exist. | Define and reconcile a versioned harness configuration contract covering skills, tools, plugins, and their governance. |

## Review of the proposed approach

The proposed approach aligns with the repository findings, with a distinction between initial provisioning and ongoing updates.

| Proposed assessment | Review |
|---|---|
| A template image is already built and stored in Quay; import it once and reuse it for all VMs. | Aligned with the repository's intended workflow. [Image mirroring](../scripts/mirror-images-incluster.sh) names the Quay gateway images, and [golden-image import](../scripts/import-golden-image.sh) mirrors and imports a disk into a reusable CDI DataSource. VMs clone the imported disk. “Once” applies to the selected image version and accessible source location; publishing a new image does not itself upgrade existing VM disks. Registry availability was not checked. |
| Use the existing BOM from cloud-init instead of SSH and `virtctl`; approximately 1–2 days. | Aligned as a bounded bootstrap change. The BOM application already runs inside the VM, so it can be reused from guest initialization. In the inspected checkout, the external setup Job still delivers and invokes it. Treat 1–2 days as the author's initial estimate for that migration, subject to configuration delivery, dependencies, credentials, and startup ordering. It is not an estimate for continuous reconciliation or full Astra validation. |
| Test with ArgoCD. | Agreed. [values-prod.yaml](../values-prod.yaml) already declares the SAW and BOM applications. Validation must cover guest readiness and later configuration changes as well as cluster resource synchronization. No live ArgoCD test was performed in this discovery. |
| Multiple sandboxes already use a SAW-BOM profile and do not require script changes. | Confirmed for initial creation of supported sandbox types. The YAML list and generic iteration already exist. Dynamic changes to running sandboxes still require a delivery trigger and lifecycle handling. |
| Harness skills/tools are a new feature that can be added to the SAW-BOM profile. | Agreed. The profile is a suitable configuration entry point. Implementation also needs parser/schema support, a harness-specific application mechanism, update/restart behavior, and verification of effective settings. Adding YAML fields alone will not configure the harness. |

The outstanding requirement not resolved by these proposals is automatic reconciliation of existing resources. Moving the current BOM application into cloud-init addresses initial provisioning; it does not introduce a persistent process that observes later ConfigMap revisions and updates existing sandboxes.

### ArgoCD validation checklist

- Fresh deployment: confirm the image source, BOM, bootstrap data, and secrets are available in the required order, and verify gateway plus sandbox readiness.
- Repeat sync with unchanged inputs: confirm there is no unnecessary onboarding, token regeneration, sandbox replacement, or loss of user state.
- BOM-only change: confirm the selected guest delivery mechanism receives the new revision and the declared change takes effect. Before a reconciler exists, explicitly record this as unsupported rather than infer success from synchronized Kubernetes resources.
- Bootstrap-template change: determine what happens to an existing VM and document any explicit restart or replacement procedure.
- Dependency failure and recovery: cover missing secrets, failed image pulls, unavailable governance, and a VM reboot; verify actionable status.
- Multiple instances: confirm each VM receives its intended profile and that one instance's changes do not affect another.

## 1. Reusable VM image blueprint

**Discovery.** The [gateway image BuildConfig](../image-builder-charts/helm/openshell-gateway-image/templates/buildconfig.yaml) downloads a Fedora cloud QCOW2, customizes it with `virt-customize`, installs gateway services, and packages the resulting disk in a container image. The [builder values](../image-builder-charts/helm/openshell-gateway-image/values.yaml) parameterize the base image, runtime, and OpenShell inputs. The [golden-image resources](../image-builder-charts/helm/openshell-gateway-image/templates/golden-image.yaml) expose a CDI DataVolume and DataSource.

The [VM template](../charts/openshell-saw/templates/virtualmachine.yaml) supports registry, HTTP, or DataSource disk sources. The [instance creation script](../scripts/openshell-saw-create.sh) installs a named Helm release with instance parameters. These are foundations for reuse; this checkout does not establish a technical need to fork the repository for every VM.

Some existing documentation describes the image as bootc-based. The inspected build template uses QCOW2 customization, so an Astra blueprint should explicitly identify the supported build and upgrade mechanism rather than assuming bootc lifecycle support.

**Questions to resolve**

- What does Astra accept as a VM template: a QCOW2, a registry disk image, a platform template resource, or another artifact?
- Which base OS, CPU architecture, firmware, container runtime, registry access, and guest initialization mechanisms must be supported?
- What belongs in the image, and what is supplied per instance? Who owns image publication, patching, compatibility testing, and retirement?
- Will existing VM operating systems be upgraded in place or replaced from a newer template, and how will persistent state survive that operation?

**Proposed completion criteria.** Publish one versioned blueprint and use the same image artifact to create two independently configured SAW VMs without source edits or per-instance forks. Record the artifact digest and component versions. Verify that credentials and instance identity are supplied at deployment time.

## 2. VM-owned initialization from external configuration

**Discovery.** The [cloud-init template](../charts/openshell-saw/templates/cloudinit-sandbox.yaml) writes gateway configuration and starts a gateway setup service. However, [run-setup.sh](../charts/openshell-saw/files/run-setup.sh) defines SSH/SCP helpers and sequences binary upgrades, governance checks, and BOM setup. [wait-for-vm.sh](../charts/openshell-saw/files/wait-for-vm.sh) creates the cloud-init Secret from a template ConfigMap and waits for SSH. [setup-bom-profiles.sh](../charts/openshell-saw/files/setup-bom-profiles.sh) reads the BOM ConfigMap, copies files and resolved credentials into the VM, and invokes Python remotely.

The VM currently declares a root disk and a cloud-init disk. It does not declare a continuously consumed BOM configuration volume. The existence of a ConfigMap in the cluster therefore does not establish an ongoing guest configuration delivery path.

**Questions to resolve**

- How will Astra expose initial configuration and later revisions to a running guest: a supported shared mount, authenticated retrieval, or a platform-managed delivery service?
- If a mounted ConfigMap is selected, how do changed bytes reach the running guest, how quickly, and without which restart requirements? This must be demonstrated for the actual VM transport.
- How does the guest obtain a scoped identity for configuration retrieval, status reporting, and credential access?
- Which dependencies must be available before readiness: configuration, identity, registry access, governance, and inference providers?
- What happens when configuration is missing, invalid, or temporarily unavailable at boot?

**Proposed completion criteria.** A new VM reads externally supplied instance configuration, initializes its gateway and declared sandboxes, and publishes readiness without the setup Job using SSH or `virtctl`. Credentials use a separate secret delivery mechanism. Bootstrap failures identify the failed dependency and can recover when it becomes available.

## 3. Continuous reconciliation of existing resources

**Discovery.** The [setup Job](../charts/openshell-saw/templates/job-setup.yaml) is a finite provisioning job. The inspected BOM path has no persistent configuration watcher or reconciliation loop. In [apply_bom.py](../charts/saw-bom/scripts/apply_bom.py), `create_sandbox_generic()` returns when an existing sandbox is not in an Error state; it does not compare that sandbox's image with the declared image. Error-state recreation exists, but it is not an image update strategy. Disabled entries are skipped, with no corresponding removal operation in the main deployment loop.

Updating the BOM ConfigMap alone therefore does not provide the requested convergence. Repeating the current script also does not establish full reconciliation: it combines creation with onboarding and other side effects that need explicit repeatability rules.

**Questions to resolve**

- Which changes can be applied live, which require a harness or sandbox restart, and which require replacement? Validate this against the supported runtime versions.
- What state must survive replacement: workspace files, conversation history, configuration, credentials, and runtime metadata?
- What are the semantics of `enabled: false`, removing an entry, and renaming a resource? How are deletion and data retention controlled?
- What revision identifies desired state, and where are the applied revision, per-resource conditions, and errors reported to Astra?
- How are concurrent revisions, partial failures, retries, manual drift, and unavailable configuration sources handled?

**Proposed completion criteria.** Change a sandbox image reference in configuration and observe the running sandbox converge according to a documented update policy. Reapplying the same revision makes no unnecessary changes. Test an invalid revision, a failed image pull, interrupted application, and recovery. Preserve declared persistent data and expose failures without reporting the revision as successfully applied.

## 4. Dynamic multi-sandbox YAML configuration

**Discovery.** The [BOM chart](../charts/saw-bom/templates/configmap-bom.yaml) packages profile YAML into `saw-bom-profiles`. The [sample sandbox definitions](../charts/saw-bom/profiles/data-science/default/sandbox.yaml) include `openclaw`, `nemoclaw`, and `generic` entries with names, enablement, images, and provider references. The parser and deployment loop iterate over workspaces and sandboxes. Additional instances of supported sandbox types can therefore be described in profile YAML without adding a shell-script branch for each instance.

The missing piece is dynamic lifecycle management. Profiles are chart-packaged files, and the ConfigMap name is fixed within a namespace. The setup code reads that fixed name; a per-VM configuration selector is not present in this path. The YAML documents resemble Kubernetes resources, but this path reads them as files; it does not establish that they are installed CRDs with controllers.

**Questions to resolve**

- Is the Astra input a per-VM document, a selected shared profile with overrides, or a set of managed resources?
- How are profiles assigned to individual VMs, especially when several VMs share a namespace?
- What schema validation, naming rules, provider-reference checks, and resource limits are required?
- How are per-sandbox access, dashboard routing, and resource budgets represented as the number of sandboxes grows?
- Does the first release need dynamic management of multiple SAW VMs as well as multiple sandboxes inside each VM?

**Proposed completion criteria.** Add a second sandbox to a running VM using only configuration. Update it, disable it, and remove it according to explicit lifecycle rules. Verify that configuration intended for one VM does not change another VM, and that unrelated sandbox state remains intact.

## 5. Agent harness configuration and governance

**Discovery.** The BOM `Sandbox` model includes a harness type, agent selection, image, providers, and model. [apply_bom.py](../charts/saw-bom/scripts/apply_bom.py) contains concrete OpenClaw onboarding, token, origin, model, and startup commands. Harness integration is therefore present, but implemented through specific provisioning commands rather than a general managed harness contract.

There are also image-time integrations: the [OpenClaw image](../image-builder-charts/helm/openclaw-openshell-image/Dockerfile) installs an OpenShell sandbox plugin, and the [NemoClaw build](../image-builder-charts/helm/nemoclaw-imagestream/templates/buildconfig.yaml) supplies tool-disclosure and web-search build arguments. These do not demonstrate runtime reconciliation of skills or tools from VM configuration.

The [gateway configuration](../charts/openshell-saw/templates/cloudinit-sandbox.yaml) binds the governance interceptor to sandbox creation, provider creation, configuration updates, and policy analysis. The [interceptor deployment](../charts/governance-interceptor/templates/deployment.yaml) mounts policy/profile ConfigMaps into its pod. That is a separate path from delivering harness configuration into an existing sandbox; neither those bindings nor the mounts establish per-tool-call or skill lifecycle enforcement.

**Questions to resolve**

- Which harnesses and versions must the first Astra release support?
- Which fields are managed: skill sources and versions, tool/MCP endpoints, plugin versions, model settings, credential references, and tool enablement?
- For each harness, what supported file format or API applies those fields, and what requires a restart?
- Which settings are administrator-controlled, which may users customize, and how are conflicting or unauthorized local changes handled?
- How are artifacts approved and versioned, tools revoked, and configuration changes audited? Which controls belong to OpenShell, the harness, or the platform?

**Proposed completion criteria.** For at least one explicitly supported harness, update a declared skill or tool on an existing sandbox through VM configuration, verify the effective harness state, and report the applied revision. Exercise removal or revocation, invalid configuration, and recovery. Document the enforcement boundary for every governed field.

## Proposed implementation direction

Reuse the image builder and BOM concepts, while introducing a guest service responsible for applying desired state. This is a design proposal, not a capability already present in this repository.

1. Astra supplies an instance identity, a versioned configuration reference, and secret references when creating the VM from the reusable image.
2. A service included in the image obtains and validates configuration through the agreed Astra transport.
3. The service compares the revision and actual runtime state, then applies changes through OpenShell operations and explicit harness adapters.
4. The service verifies the result and publishes the applied revision and resource conditions. It retries recoverable failures and retains the last known valid configuration according to an agreed outage policy.

Separate VM image updates, sandbox image updates, and harness configuration updates. Each has different restart, persistence, and recovery requirements. Keep executable reconciler code in a versioned software artifact; the current BOM ConfigMap also carries `apply_bom.py`, which should be reconsidered when defining the boundary between configuration authors and software publishers.

## Delivery sequence and decision gates

| Stage | Deliverable | Evidence required to proceed |
|---|---|---|
| 1. Astra contract | Image format, guest configuration transport, identity, secret delivery, and status contract | Demonstrate initial delivery and a later configuration revision reaching a running guest. |
| 2. Reusable bootstrap | Published image blueprint and VM-owned initialization | Two VMs from one image, with different configuration and no external SSH provisioning. |
| 3. Sandbox lifecycle | Validated schema and persistent reconciler | Add and update existing sandboxes; verify repeatability, isolation, recovery, and data retention. |
| 4. Harness lifecycle | First supported harness adapter and governance mapping | Apply and revoke a skill/tool configuration on an existing sandbox with observable results. |
| 5. Operational readiness | Documented rollback, upgrades, diagnostics, and ownership | Exercise reboot recovery, unavailable dependencies, failed updates, and revision reporting in Astra. |

The first decisions needed are Astra's guest configuration transport, supported image format, initial harness scope, and persistence/update policy. These determine the implementation shape. The proposed 1–2 day estimate applies only to the bootstrap migration described above; estimates for reconciliation, harness lifecycle support, and end-to-end Astra validation remain open.

## Validation limits

Findings are based on repository source inspection at the stated commit. Existing documentation was treated as context where it differed from executable templates. No VM was created or modified, no external harness APIs were tested, and no claims of Astra compatibility or successful runtime reconciliation are made by this discovery.
