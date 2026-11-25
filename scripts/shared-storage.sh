#!/usr/bin/env bash
# Ensure a shared-filesystem (ReadWriteMany) StorageClass for container workspaces.
#
# The audit exchange volume is mounted by several Pods at once, so it needs a
# ReadWriteMany class (CephFS, NFS, EFS, ...). Block classes such as EBS
# (gp3-csi) cannot serve it. This script:
#   - a known shared-filesystem class exists -> continue
#   - otherwise, by SAW_SHARED_STORAGE:
#       unset / none  -> print the options and fail (nothing is created)
#       nfs           -> dev/demo only, explicit opt-in: create a small in-cluster
#                        NFS server (privileged SCC) and provisioner (cluster-scoped
#                        role, StorageClass `saw-nfs`) and verify it. One Pod, no
#                        replication: not for production.
#       efs           -> on AWS with working `aws` credentials, offer to create EFS
#                        (filesystem, mount targets, NFS security group), the AWS
#                        EFS CSI Driver Operator and StorageClass `saw-efs`. EFS is
#                        billed per GB; it is tagged kubernetes.io/cluster/<infra-id>.
# For production, provide a real RWX class (ODF CephFS, EFS, vendor NFS) first;
# this script then leaves storage alone.
#
# Container workspaces then name the shared class saw-shared, a copy of the
# shared-filesystem class, so Git holds no cluster-specific class name (other
# volumes use the cluster's default class). An existing saw-shared is kept.
# --classes-only creates just the copy, and only when the cluster can back it
# (make saw-init uses it before any container user exists).
#
# Env: SAW_SHARED_STORAGE, SAW_EFS_STORAGECLASS (saw-efs), SAW_NFS_STORAGECLASS
#      (saw-nfs), SAW_NFS_NAMESPACE (saw-nfs), SAW_NFS_SIZE (20Gi),
#      SAW_STORAGE_ASSUME_YES=1 (accept the EFS prompt unattended)
set -euo pipefail

CLASS="${SAW_EFS_STORAGECLASS:-saw-efs}"
SHARED='["openshift-storage.cephfs.csi.ceph.com","cephfs.csi.ceph.com","nfs.csi.k8s.io",
  "efs.csi.aws.com","file.csi.azure.com","filestore.csi.storage.gke.io","csi.trident.netapp.io",
  "spectrumscale.csi.ibm.com","k8s-sigs.io/nfs-subdir-external-provisioner"]'
CSI_NS=openshift-cluster-csi-drivers
CLASSES_ONLY=0
[ "${1:-}" = --classes-only ] && CLASSES_ONLY=1

err() { echo "$@" >&2; }
interactive() { [ -t 0 ] && [ -t 1 ]; }
ask_yes() {
  [ "${SAW_STORAGE_ASSUME_YES:-0}" = 1 ] && return 0
  interactive || return 1
  local ans
  read -r -p "$1 [y/N] " ans || return 1
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}
guidance() {
  err "Container workspaces need a ReadWriteMany (shared filesystem) StorageClass."
  err "Options, then run make saw-init again:"
  err "  - AWS: EFS with the AWS EFS CSI Driver Operator (this script automates it"
  err "    when 'aws sts get-caller-identity' works for the cluster's account)"
  err "  - OpenShift Data Foundation (CephFS: ocs-storagecluster-cephfs)"
  err "  - an NFS server with the NFS CSI driver (nfs.csi.k8s.io)"
  err "  - dev/demo only: SAW_SHARED_STORAGE=nfs make saw-init creates a small in-cluster NFS"
  err "    server (privileged SCC, cluster-scoped provisioner role; one Pod, no replication)"
  err "  - or name an existing RWX class in containerDefaults.stack.audit.values.exchangeStorageClass"
  err "See docs/container-installation.md."
}

# A Pod writes and reads through a ReadWriteMany claim of the class.
verify_rwx() {
  local ns="$1" class="$2"
  oc apply -n "$ns" -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: rwx-check}
spec: {accessModes: [ReadWriteMany], storageClassName: ${class}, resources: {requests: {storage: 1Mi}}}
EOF
  oc delete pod rwx-check -n "$ns" --ignore-not-found >/dev/null 2>&1
  oc apply -n "$ns" -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: rwx-check}
spec:
  restartPolicy: Never
  containers:
    - name: check
      image: registry.access.redhat.com/ubi9/ubi-minimal
      command: [sh, -c, "echo saw > /data/check && cat /data/check"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      volumeMounts: [{name: data, mountPath: /data}]
  volumes: [{name: data, persistentVolumeClaim: {claimName: rwx-check}}]
EOF
  local phase=""
  for _ in $(seq 60); do
    phase="$(oc get pod rwx-check -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null)"
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 5
  done
  if [ "$phase" = Succeeded ] && [ "$(oc logs rwx-check -n "$ns" 2>/dev/null)" = saw ]; then
    echo "  ok    shared-filesystem StorageClass: ${class} (demo NFS, verified read/write)"
  else
    err "  FAIL  ${class} did not serve a ReadWriteMany volume (check Pod: ${phase:-not started})"
    err "        oc -n ${ns} get pvc,pods; oc -n ${ns} describe pod rwx-check; oc -n ${ns} logs deploy/nfs-provisioner"
    exit 1
  fi
  oc delete pod rwx-check -n "$ns" --wait=false >/dev/null 2>&1 || true
  oc delete pvc rwx-check -n "$ns" --wait=false >/dev/null 2>&1 || true
}

# Create class $2 as a copy of class $1, unless $2 exists.
copy_class() {
  local source="$1" name="$2"
  if oc get storageclass "$name" >/dev/null 2>&1; then
    echo "  ok    StorageClass ${name}"
    return 0
  fi
  [ -n "$source" ] || return 1
  oc get storageclass "$source" -o json | jq --arg n "$name" --arg src "$source" '
    {apiVersion: "storage.k8s.io/v1", kind: "StorageClass",
     metadata: {name: $n, labels: {"app.kubernetes.io/part-of": "secure-agent-workspace"},
                annotations: {"saw.redhat.com/copy-of": $src}},
     provisioner, parameters, reclaimPolicy, volumeBindingMode, allowVolumeExpansion,
     mountOptions, allowedTopologies} | with_entries(select(.value != null))' \
    | oc create -f - >/dev/null || { err "  FAIL  could not create StorageClass ${name}"; return 1; }
  echo "  ok    StorageClass ${name} (a copy of ${source})"
}

# saw-shared, the shared class name the container charts use.
ensure_classes() {
  local shared
  shared="$(oc get storageclass -o json | jq -r --argjson p "$SHARED" '[.items[]
    | select(.metadata.name != "saw-shared") | select(.provisioner as $x | $p | index($x))]
    | sort_by(.metadata.name) | .[0].metadata.name // empty')"
  if [ "$CLASSES_ONLY" = 1 ]; then
    { [ -n "$shared" ] || oc get storageclass saw-shared >/dev/null 2>&1; } && copy_class "$shared" saw-shared
    return 0
  fi
  copy_class "$shared" saw-shared || { err "  FAIL  no shared-filesystem StorageClass to copy as saw-shared"; return 1; }
}

if [ "$CLASSES_ONLY" = 1 ]; then
  ensure_classes
  exit 0
fi

existing="$(oc get storageclass -o json | jq -r --argjson p "$SHARED" \
  '[.items[] | select(.metadata.name != "saw-shared") | select(.provisioner as $x | $p | index($x))] | sort_by(.metadata.name) | .[0].metadata.name // empty')"
if [ -n "$existing" ]; then
  nfs_class="${SAW_NFS_STORAGECLASS:-saw-nfs}"
  if [ "$existing" = "$nfs_class" ]; then
    verify_rwx "${SAW_NFS_NAMESPACE:-saw-nfs}" "$nfs_class"  # our demo server: prove it still works
  else
    echo "  ok    shared-filesystem StorageClass: ${existing}"
  fi
  ensure_classes || exit 1
  exit 0
fi

# SAW_SHARED_STORAGE=nfs (explicit opt-in): a small NFS server inside the cluster.
# One server Pod on a default-class (RWO) volume, exported to a dynamic
# provisioner; not replicated and a single point of failure.
setup_demo_nfs() {
  local ns="${SAW_NFS_NAMESPACE:-saw-nfs}" class="${SAW_NFS_STORAGECLASS:-saw-nfs}" size="${SAW_NFS_SIZE:-20Gi}"
  # Upstream Kubernetes images: the e2e NFS server (kernel nfsd, exports /exports
  # as the NFSv4 root) and the sig-storage subdirectory provisioner.
  local server_image="${SAW_NFS_SERVER_IMAGE:-registry.k8s.io/e2e-test-images/volume/nfs:1.4}"
  local provisioner_image="${SAW_NFS_PROVISIONER_IMAGE:-registry.k8s.io/sig-storage/nfs-subdir-external-provisioner:v4.0.2}"
  echo "  info  no shared-filesystem StorageClass: creating an in-cluster NFS server in ${ns}"
  echo "        (privileged Pod on a ${size} default-class volume, provisioner, StorageClass ${class})."
  echo "        Dev/demo only: one Pod, no replication."

  oc create namespace "$ns" --dry-run=client -o yaml | oc apply -f - >/dev/null
  oc create serviceaccount nfs-server -n "$ns" --dry-run=client -o yaml | oc apply -f - >/dev/null
  oc create serviceaccount nfs-provisioner -n "$ns" --dry-run=client -o yaml | oc apply -f - >/dev/null
  oc adm policy add-scc-to-user privileged -z nfs-server -n "$ns" >/dev/null
  # Pods with nfs volumes need an SCC that allows them.
  oc adm policy add-scc-to-user hostmount-anyuid -z nfs-provisioner -n "$ns" >/dev/null
  oc apply -n "$ns" -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: nfs-data}
spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: ${size}}}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: nfs-server, labels: {app: nfs-server}}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector: {matchLabels: {app: nfs-server}}
  template:
    metadata: {labels: {app: nfs-server}}
    spec:
      serviceAccountName: nfs-server
      containers:
        - name: nfs-server
          image: ${server_image}
          securityContext: {privileged: true}
          ports: [{name: nfs, containerPort: 2049}, {name: mountd, containerPort: 20048}, {name: rpcbind, containerPort: 111}]
          volumeMounts: [{name: data, mountPath: /exports}]
      volumes: [{name: data, persistentVolumeClaim: {claimName: nfs-data}}]
---
apiVersion: v1
kind: Service
metadata: {name: nfs-server}
spec:
  selector: {app: nfs-server}
  ports: [{name: nfs, port: 2049}, {name: mountd, port: 20048}, {name: rpcbind, port: 111}]
EOF
  oc rollout status deployment/nfs-server -n "$ns" --timeout=5m >/dev/null \
    || { err "  FAIL  demo NFS server did not start (oc -n ${ns} describe deployment/nfs-server)"; exit 1; }
  # Nodes mount NFS from the host network, which reaches the Service IP but not cluster DNS.
  local server_ip
  server_ip="$(oc get service nfs-server -n "$ns" -o jsonpath='{.spec.clusterIP}')"
  echo "  ok    demo NFS server at ${server_ip}"

  oc apply -f - >/dev/null <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: saw-nfs-provisioner}
rules:
  - {apiGroups: [""], resources: [persistentvolumes], verbs: [get, list, watch, create, delete]}
  - {apiGroups: [""], resources: [persistentvolumeclaims], verbs: [get, list, watch, update]}
  - {apiGroups: [storage.k8s.io], resources: [storageclasses], verbs: [get, list, watch]}
  - {apiGroups: [""], resources: [events], verbs: [create, update, patch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: saw-nfs-provisioner}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: saw-nfs-provisioner}
subjects: [{kind: ServiceAccount, name: nfs-provisioner, namespace: ${ns}}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: nfs-provisioner-leader, namespace: ${ns}}
rules:
  - {apiGroups: [""], resources: [endpoints], verbs: [get, list, watch, create, update, patch]}
  - {apiGroups: [coordination.k8s.io], resources: [leases], verbs: [get, list, watch, create, update, patch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: nfs-provisioner-leader, namespace: ${ns}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: nfs-provisioner-leader}
subjects: [{kind: ServiceAccount, name: nfs-provisioner, namespace: ${ns}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: nfs-provisioner, namespace: ${ns}, labels: {app: nfs-provisioner}}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector: {matchLabels: {app: nfs-provisioner}}
  template:
    metadata: {labels: {app: nfs-provisioner}}
    spec:
      serviceAccountName: nfs-provisioner
      containers:
        - name: provisioner
          image: ${provisioner_image}
          env:
            - {name: PROVISIONER_NAME, value: k8s-sigs.io/nfs-subdir-external-provisioner}
            - {name: NFS_SERVER, value: "${server_ip}"}
            - {name: NFS_PATH, value: /}
          volumeMounts: [{name: root, mountPath: /persistentvolumes}]
      volumes: [{name: root, nfs: {server: "${server_ip}", path: /}}]
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: ${class}}
provisioner: k8s-sigs.io/nfs-subdir-external-provisioner
parameters: {archiveOnDelete: "false"}
mountOptions: [nfsvers=4.1]
reclaimPolicy: Delete
volumeBindingMode: Immediate
EOF
  oc rollout status deployment/nfs-provisioner -n "$ns" --timeout=5m >/dev/null \
    || { err "  FAIL  demo NFS provisioner did not start (oc -n ${ns} describe deployment/nfs-provisioner)"; exit 1; }

  verify_rwx "$ns" "$class"
}

case "${SAW_SHARED_STORAGE:-}" in
  nfs) setup_demo_nfs; ensure_classes || exit 1; exit 0 ;;
  efs) ;;  # below
  *) err "  FAIL  no shared-filesystem (ReadWriteMany) StorageClass"; guidance; exit 1 ;;
esac

infra="$(oc get infrastructure cluster -o json)"
platform="$(jq -r '.status.platformStatus.type // ""' <<<"$infra")"
if [ "$platform" != AWS ] || ! command -v aws >/dev/null || ! aws sts get-caller-identity >/dev/null 2>&1; then
  err "  FAIL  no shared-filesystem (ReadWriteMany) StorageClass"
  [ "$platform" = AWS ] && err "        (AWS: install the aws CLI and log in to the cluster's account to automate EFS)"
  guidance
  exit 1
fi
if [ "$(oc get cloudcredential cluster -o jsonpath='{.spec.credentialsMode}' 2>/dev/null)" = Manual ]; then
  err "  FAIL  no shared-filesystem StorageClass; this cluster uses short-term AWS credentials (STS),"
  err "        which the EFS operator needs an IAM role for. Follow the OpenShift 'AWS EFS CSI Driver"
  err "        Operator' documentation for STS, then run make saw-init again."
  exit 1
fi

region="$(jq -r '.status.platformStatus.aws.region' <<<"$infra")"
infra_id="$(jq -r '.status.infrastructureName' <<<"$infra")"
export AWS_REGION="$region"
err ""
err "No shared-filesystem StorageClass. On AWS this script can create, in ${region}:"
err "  - an encrypted EFS filesystem saw-${infra_id} with a mount target per worker subnet,"
err "  - a security group allowing NFS (TCP 2049) from the cluster VPC,"
err "  - the AWS EFS CSI Driver Operator and StorageClass ${CLASS}."
err "EFS is billed per GB stored. It is tagged kubernetes.io/cluster/${infra_id}."
if ! ask_yes "Create it now?"; then
  guidance
  exit 1
fi

# Worker instances -> subnets and VPC.
mapfile -t instances < <(oc get nodes -l node-role.kubernetes.io/worker \
  -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' | sed 's#.*/##' | grep '^i-' | sort -u)
[ "${#instances[@]}" -gt 0 ] || { err "no AWS worker instances found"; exit 1; }
read -r -a subnets <<<"$(aws ec2 describe-instances --instance-ids "${instances[@]}" \
  --query 'Reservations[].Instances[].SubnetId' --output text | tr '\t' '\n' | sort -u | tr '\n' ' ')"
vpc="$(aws ec2 describe-instances --instance-ids "${instances[0]}" --query 'Reservations[0].Instances[0].VpcId' --output text)"
cidr="$(aws ec2 describe-vpcs --vpc-ids "$vpc" --query 'Vpcs[0].CidrBlock' --output text)"

sg="$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${vpc}" "Name=group-name,Values=saw-efs-${infra_id}" \
  --query 'SecurityGroups[0].GroupId' --output text)"
if [ "$sg" = None ] || [ -z "$sg" ]; then
  sg="$(aws ec2 create-security-group --group-name "saw-efs-${infra_id}" --vpc-id "$vpc" \
    --description "SAW EFS: NFS from the ${infra_id} cluster VPC" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=kubernetes.io/cluster/${infra_id},Value=owned}]" \
    --query GroupId --output text)"
  aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 2049 --cidr "$cidr" >/dev/null
fi
echo "  ok    security group ${sg} (NFS from ${cidr})"

fs="$(aws efs describe-file-systems --creation-token "saw-${infra_id}" --query 'FileSystems[0].FileSystemId' --output text)"
if [ "$fs" = None ] || [ -z "$fs" ]; then
  fs="$(aws efs create-file-system --creation-token "saw-${infra_id}" --encrypted \
    --performance-mode generalPurpose --throughput-mode elastic \
    --tags "Key=Name,Value=saw-${infra_id}" "Key=kubernetes.io/cluster/${infra_id},Value=owned" \
    --query FileSystemId --output text)"
fi
for _ in $(seq 60); do
  [ "$(aws efs describe-file-systems --file-system-id "$fs" --query 'FileSystems[0].LifeCycleState' --output text)" = available ] && break
  sleep 5
done
echo "  ok    EFS ${fs}"
have="$(aws efs describe-mount-targets --file-system-id "$fs" --query 'MountTargets[].SubnetId' --output text)"
for s in "${subnets[@]}"; do
  [[ " $have " == *" $s "* ]] && continue
  aws efs create-mount-target --file-system-id "$fs" --subnet-id "$s" --security-groups "$sg" >/dev/null \
    || err "  warn  mount target in ${s} not created (one per availability zone)"
done
echo "  ok    mount targets in ${#subnets[@]} worker subnet(s)"

# AWS EFS CSI Driver Operator in openshift-cluster-csi-drivers.
if [ -z "$(oc get operatorgroup -n "$CSI_NS" -o name 2>/dev/null)" ]; then
  oc apply -f - <<EOF >/dev/null
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata: {name: openshift-cluster-csi-drivers, namespace: ${CSI_NS}}
spec: {upgradeStrategy: Default}
EOF
fi
oc apply -f - <<EOF >/dev/null
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata: {name: aws-efs-csi-driver-operator, namespace: ${CSI_NS}}
spec: {channel: stable, name: aws-efs-csi-driver-operator, source: redhat-operators, sourceNamespace: openshift-marketplace}
EOF
for _ in $(seq 60); do
  oc get crd clustercsidrivers.operator.openshift.io >/dev/null 2>&1 \
    && [ "$(oc get csv -n "$CSI_NS" -o json | jq -r '[.items[] | select(.metadata.name | startswith("aws-efs-csi-driver-operator")) | .status.phase][0] // ""')" = Succeeded ] && break
  sleep 10
done
oc apply -f - <<EOF >/dev/null
apiVersion: operator.openshift.io/v1
kind: ClusterCSIDriver
metadata: {name: efs.csi.aws.com}
spec: {managementState: Managed}
EOF
for _ in $(seq 60); do oc get csidriver efs.csi.aws.com >/dev/null 2>&1 && break; sleep 10; done
oc get csidriver efs.csi.aws.com >/dev/null || { err "EFS CSI driver did not become available"; exit 1; }
echo "  ok    AWS EFS CSI driver"
oc apply -f - <<EOF >/dev/null
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: ${CLASS}}
provisioner: efs.csi.aws.com
parameters: {provisioningMode: efs-ap, fileSystemId: ${fs}, directoryPerms: "700"}
reclaimPolicy: Delete
volumeBindingMode: Immediate
EOF
echo "  ok    shared-filesystem StorageClass: ${CLASS} (EFS ${fs})"
ensure_classes || exit 1
