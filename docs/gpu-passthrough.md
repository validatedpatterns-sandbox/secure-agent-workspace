# GPU passthrough into a SAW sandbox

GPU support is opt in at every layer:

```text
GPU node (VFIO) -> KubeVirt VM (hostDevices) -> guest NVIDIA driver
                -> Podman CDI -> OpenShell sandbox (--gpu COUNT)
```

A normal SAW asks for no GPU. An existing VM disk is not rebuilt when its
Helm values change; create a new SAW for GPU validation.

## Cluster gate

Check these before changing the cluster:

- The GPU node exposes `/dev/kvm`, `/dev/iommu`, and nonempty
  `/sys/kernel/iommu_groups`. Its GPU is bound to `nvgrace_gpu_vfio_pci` on
  Grace, or the appropriate VFIO driver on other hardware. Record its exact
  `VENDOR:DEVICE` ID from `lspci -Dnnk -d 10de:`. KubeVirt rejects wildcards.
- The node advertises an allocatable GPU host resource. Its GPUs are not still
  assigned to ordinary pods. A `vm-passthrough` workload label changes who
  can use those devices.
### Grace (arm64)

- KubeVirt is at least v1.9 and has the `GraceIOVirtualization`,
  `PCINUMAAwareTopology`, and `IOMMUFD` alpha gates. The node uses the static
  CPU manager. These changes can reboot nodes and need cluster owner approval.
- The VM uses `vm.architecture: arm64`, `vm.machineType: virt`, and
  `vm.dedicatedCpuPlacement: true`. The chart adds a memory limit equal to its
  request for a GPU or dedicated CPUs.

### x86_64 (for example, L40S)

Use a GPU bound to `vfio-pci`. This path does not require the Grace-specific
KubeVirt v1.9 minimum or alpha gates. Leave `vm.architecture` and
`vm.machineType` empty to use KubeVirt's x86 defaults. Dedicated CPU placement
is optional; when enabled it requires the static CPU manager on the node.

A VMI stuck Pending can be a host resource or NUMA scheduling problem. Inspect
virt-launcher events and the kubelet topology manager before changing the VM.

## Configure the cluster

The `openshift-cnv` chart leaves `gpu.pciHostDevices` empty. For each device,
set the exact `pciDeviceSelector` and a resource name; the chart renders
`externalResourceProvider: true` by default when the NVIDIA GPU Operator's
sandbox device plugin advertises it. Set it to `false` for KubeVirt to
advertise a device bound to `vfio-pci` without that plugin. The resource name
must match the one advertised by the cluster. The chart does not bind a driver, label a node,
or enable alpha gates.

```yaml
# Local Helm values for charts/openshift-cnv
# Use the actual PCI ID and advertised resource name from the cluster.
gpu:
  enabled: true
  pciHostDevices:
    - pciDeviceSelector: "<vendor>:<device>"
      resourceName: "example.com/gpu"
      externalResourceProvider: true
```

**Ownership:** the `openshift-cnv` application manages
`HyperConverged/kubevirt-hyperconverged`. Enabling its GPU values replaces the
whole `pciHostDevices` list: copy all existing entries first. Where CNV is
platform-owned, exclude its namespace, Subscription and application from the
Pattern so install and uninstall cannot take ownership of them.

For a platform-owned CNV installation, use an overlay like this:

```yaml
clusterGroup:
  namespaces:
    openshift-cnv:
      disabled: true
  subscriptions:
    openshift-virtualization: null
  applications:
    openshift-cnv: null
```

Use `disabled: true` for namespace map entries. In clustergroup 0.9.58, a
null namespace entry still creates the namespace and an OperatorGroup,
which can break an existing operator with `TooManyOperatorGroups`. Render
the root clustergroup chart before installing and confirm that it contains
no CNV namespace, OperatorGroup, Subscription or application.

Rendering fails if the list or either field is empty. Keep cluster values
outside the repository and supply them through the Pattern's
`extraParameters` or a local values file.

## Build the GPU golden image

`make gateway-build-podman GATEWAY_GPU=true` builds only
`openshell-gateway-gpu` objects: ImageStream, BuildConfig, golden DataVolume,
DataSource, and their RBAC. The normal `openshell-gateway:latest` is untouched.
Do not use `make images-mirror` on a cluster whose normal golden image is
native arm64.

The GPU image installs the NVIDIA open DKMS driver and Container Toolkit. The
build chooses NVIDIA's Fedora 44 x86_64 repository or RHEL 10 SBSA aarch64
repository using `uname -m`. The aarch64 RPM dependency resolution on Fedora
44 must be confirmed with the target builder before relying on the image.
The build installs `kernel-devel` matching the image's installed kernel and
attempts a DKMS build. The first boot runs `nvidia-driver-setup.service` to
build for the running kernel if needed. Every boot runs `saw-gpu-devices.service` before
`saw-install.service`: it loads `nvidia-uvm` and creates both UVM nodes before generating CDI,
checks `nvidia-smi -L`, sets SELinux `device_t` labels, and regenerates
`/etc/cdi/nvidia.yaml`. Where capability nodes exist, it grants rootless
Podman access and inserts their live major/minor numbers. Capability nodes
are optional on non-MIG GPUs. Failure blocks the installer on a GPU enabled VM.
The image masks the toolkit's automatic CDI refresh units so they cannot race
this helper or publish a second specification. CDI generation uses the toolkit's
`no-additional-gids-for-device-nodes` feature (toolkit 1.19 or newer), retaining
OpenShell's resolved workload identity instead of injecting the video group.
After a manual driver update, restart `saw-gpu-devices.service` to regenerate CDI.
The governance filesystem policy permits the NVIDIA control, UVM, capability,
and first GPU device paths. These rules allow access after CDI attachment;
they do not attach a GPU to a CPU-only sandbox. For multiple GPUs, add each
additional `/dev/nvidia<N>` path to your deployment's policy. Missing paths
are tolerated by the existing `best_effort` Landlock setting.

Check the rendered BuildConfig and the package installation logs. The image
build may be long; finish it before a maintenance freeze.

## Create a new SAW

Use a local values file with the host device resource, VM shape, and disk size:

```yaml
vm:
  cores: 16
  memory: 64Gi
  diskSize: 200Gi
  architecture: arm64
  machineType: virt
  dedicatedCpuPlacement: true
  gpu:
    enabled: true
    count: 1
    deviceName: "example.com/gpu"
```

Run `make saw-create` with `OPENSHELL_SAW_NAME`, `PROVIDER`, `MODEL`,
`SAW_VALUES_FILE`, and any provider credentials required by the profile.
`GPU_ENABLED=true`, `GPU_COUNT=1`, and `GPU_DEVICE_NAME=example.com/gpu` are
optional command line overrides. Make defaults do not override the values
file. `make prereqs-check GPU_ENABLED=true GPU_DEVICE_NAME=example.com/gpu`
(or `make quickstart-prereqs-check` with the same variables) checks the
HyperConverged entry and node allocatable; it installs nothing. The check
reads both the v1 `spec.virtualization.permittedHostDevices` layout and the
v1beta1 `spec.permittedHostDevices` layout. Set
`GPU_COUNT` to check for more than one device.

For the sandbox that needs the device, set its SAW-BOM field in a local copy
of the chart:

```yaml
gpu:
  enabled: true
  count: 1
```

The shipped `cuda-sandbox` has `gpu.enabled: false`. The installer passes
`--gpu COUNT` to OpenShell 0.1.2 only for enabled sandboxes, then verifies
`nvidia-smi -L` inside each one. OpenShell's Podman driver attaches CDI
`nvidia.com/gpu` devices. If a sandbox already exists and its GPU request
changes, the installer recreates it and carries its `/sandbox` files over,
as for an environment change. The `saw.redhat.com/gpu` label records the
count. A missing label means no GPU, so upgrading existing CPU sandboxes
keeps them running.

### GitOps (Option A)

Pass the HCO chart's `gpu` values through the clustergroup's
`applications.openshift-cnv` overrides or an `extraValueFiles` overlay. Keep
the platform ownership rules above when CNV is already installed.

Set each user's VM request in `overrides/saw-users.yaml`:

```yaml
users:
  - name: gpu1
    values:
      vm:
        dedicatedCpuPlacement: true
        gpu:
          enabled: true
          count: 1
          deviceName: "example.com/gpu"
```

Enable the sandbox separately in the desired profile's `sandbox.yaml` with
`gpu.enabled: true`, then run `make catalog` and push the GitOps branch.
The shipped profile stays GPU-off. When using a `route.hostTemplate`
extension with a 19-character `{app}` limit, choose a user name of at most
9 characters so `<name>-dashboard` fits. Change managed objects through
GitOps values: Argo CD self-healing can revert manual patches.

## Verify and diagnose

In the guest, check `nvidia-smi`, the generated CDI file, and rootless Podman:

```bash
nvidia-smi
grep -A4 "path: /dev/nvidia-uvm" /etc/cdi/nvidia.yaml
sudo -u cloud-user podman run --rm --device nvidia.com/gpu=all \
  <image-already-in-cloud-users-store> nvidia-smi -L
systemctl status nvidia-driver-setup saw-gpu-devices saw-install saw-apply
```

Then run `openshell sandbox exec -n <sandbox> --workspace <workspace> --
nvidia-smi -L`. If NVML reports `Insufficient Permissions`, inspect the
`/dev/nvidia-caps` nodes, their SELinux labels, and the CDI entries. Compare
the rootless Podman result with the sandbox result before changing
the governance Landlock policy. Add device paths only if a sandbox denial
is confirmed while Podman succeeds; check kernel Landlock audit logs and
retest both GPU and CPU sandboxes. This decision requires live validation.
Reboot the VM and repeat these checks to prove the per boot unit works.

For OIDC, the issuer CA is held in
`~cloud-user/.config/openshell/issuer-trust.pem` and the gateway drop in. It is
not added to the guest system trust store.
