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
- For Grace, KubeVirt is at least v1.9 and has the `GraceIOVirtualization`,
  `PCINUMAAwareTopology`, and `IOMMUFD` alpha gates. The node uses the static
  CPU manager. These changes can reboot nodes and need cluster owner approval.
- The VM uses `vm.architecture: arm64`, `vm.machineType: virt`, and
  `vm.dedicatedCpuPlacement: true`. The chart adds a memory limit equal to its
  request for a GPU or dedicated CPUs.

A VMI stuck Pending can be a host resource or NUMA scheduling problem. Inspect
virt-launcher events and the kubelet topology manager before changing the VM.

## Configure the cluster

The `openshift-cnv` chart leaves `gpu.pciHostDevices` empty. For each device,
set the exact `pciDeviceSelector` and a resource name; the chart renders
`externalResourceProvider: true`. The GPU Operator and KubeVirt configuration
must advertise that same name. The chart does not bind a driver, label a node,
or enable alpha gates.

```yaml
# Local Helm values for charts/openshift-cnv
# Use the actual PCI ID and advertised resource name from the cluster.
gpu:
  enabled: true
  pciHostDevices:
    - pciDeviceSelector: "<vendor>:<device>"
      resourceName: "example.com/gpu"
```

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
The first boot runs `nvidia-driver-setup.service` to compile the module for
the VM's running kernel. Every boot runs `saw-gpu-devices.service` before
`saw-install.service`: it checks `nvidia-smi -L`, grants rootless Podman access
to `/dev/nvidia-caps`, sets SELinux `device_t` labels, regenerates
`/etc/cdi/nvidia.yaml`, and inserts the live major/minor numbers for the
capability nodes. Failure blocks the installer on a GPU enabled VM.

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
file. `make quickstart-prereqs-check GPU_ENABLED=true` checks the GPU Operator
and HyperConverged entries, but does not install or change them.

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
changes, delete that sandbox and reapply the profile to create it with the new
request. The installer does not replace running sandboxes automatically.

## Verify and diagnose

In the guest, check `nvidia-smi`, the generated CDI file, and rootless Podman:

```bash
nvidia-smi
cat /etc/cdi/nvidia.yaml
sudo -u cloud-user podman run --rm --device nvidia.com/gpu=all \
  registry.fedoraproject.org/fedora:44 nvidia-smi -L
systemctl status nvidia-driver-setup saw-gpu-devices saw-install saw-apply
```

Then run `openshell sandbox exec -n <sandbox> --workspace <workspace> --
nvidia-smi -L`. If NVML reports `Insufficient Permissions`, inspect the
`/dev/nvidia-caps` nodes, their SELinux labels, and the CDI entries. OpenShell
0.1.2's supervisor may also need `/dev/nvidia-caps` in the governance
Landlock policy. Reboot the VM and repeat these checks to prove the per boot
unit works.

For OIDC, the issuer CA is held in
`~cloud-user/.config/openshell/issuer-trust.pem` and the gateway drop in. It is
not added to the guest system trust store.
