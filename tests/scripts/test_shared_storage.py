"""scripts/shared-storage.sh: the privileged demo NFS server is opt-in only."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "shared-storage.sh"
BLOCK_ONLY = {"items": [{"metadata": {"name": "gp3-csi"}, "provisioner": "ebs.csi.aws.com"}]}

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="shared-storage.sh needs jq")


def run(tmp_path, storage=None):
    """Run the script against a fake oc that records every call."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    classes = tmp_path / "classes.json"
    classes.write_text(json.dumps(BLOCK_ONLY))
    oc = bin_dir / "oc"
    oc.write_text(f"""#!/usr/bin/env bash
echo "$*" >> {calls}
case "$*" in
  *"-f -"*) cat >/dev/null ;;
  "get storageclass -o json") cat {classes} ;;
  "get pod rwx-check"*) echo Succeeded ;;
  "logs rwx-check"*) echo saw ;;
  "create "*"--dry-run=client -o yaml") echo "kind: Namespace" ;;
esac
exit 0
""")
    oc.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
    env.pop("SAW_SHARED_STORAGE", None)
    if storage is not None:
        env["SAW_SHARED_STORAGE"] = storage
    result = subprocess.run(["bash", str(SCRIPT)], env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=60, check=False)
    return result, calls.read_text().splitlines()


@pytest.mark.parametrize("storage", [None, "none"])
def test_without_a_shared_class_it_fails_with_guidance_and_creates_nothing(tmp_path, storage):
    result, calls = run(tmp_path, storage)
    assert result.returncode == 1
    assert "no shared-filesystem (ReadWriteMany) StorageClass" in result.stderr
    assert "SAW_SHARED_STORAGE=nfs" in result.stderr
    assert calls == ["get storageclass -o json"]


def test_the_demo_nfs_server_needs_an_explicit_choice(tmp_path):
    result, calls = run(tmp_path, "nfs")
    assert result.returncode == 0, result.stderr
    assert "adm policy add-scc-to-user privileged -z nfs-server -n saw-nfs" in calls
    assert "verified read/write" in result.stdout


def copies(tmp_path, items, *args):
    """Run against a fake oc that knows the given classes and records creates."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "classes.json").write_text(json.dumps({"items": items}))
    for item in items:
        (tmp_path / (item["metadata"]["name"] + ".json")).write_text(json.dumps(item))
    created = tmp_path / "created"
    oc = bin_dir / "oc"
    oc.write_text(f"""#!/usr/bin/env bash
case "$*" in
  "get storageclass -o json") cat {tmp_path}/classes.json ;;
  "get storageclass "*" -o json") cat {tmp_path}/$3.json ;;
  "get storageclass "*) [ -f {tmp_path}/$3.json ] ;;
  "create -f -") cat >> {created}; echo --- >> {created} ;;
esac
""")
    oc.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
    env.pop("SAW_SHARED_STORAGE", None)
    result = subprocess.run(["bash", str(SCRIPT), *args], env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=60, check=False)
    made = [json.loads(doc) for doc in created.read_text().split("---") if doc.strip()] if created.exists() else []
    return result, made


RBD = {"metadata": {"name": "rbd", "annotations": {"storageclass.kubernetes.io/is-default-class": "true"}},
       "provisioner": "rbd.csi.ceph.com", "parameters": {"pool": "p"}, "reclaimPolicy": "Delete"}
CEPHFS = {"metadata": {"name": "cephfs"}, "provisioner": "openshift-storage.cephfs.csi.ceph.com",
          "parameters": {"fsName": "fs"}, "volumeBindingMode": "Immediate"}


def test_the_shared_class_name_is_a_copy_of_the_clusters_shared_class(tmp_path):
    result, made = copies(tmp_path, [RBD, CEPHFS])
    assert result.returncode == 0, result.stderr
    shared, = made
    assert shared["metadata"]["name"] == "saw-shared"
    assert shared["provisioner"] == "openshift-storage.cephfs.csi.ceph.com"
    assert shared["parameters"] == {"fsName": "fs"} and shared["volumeBindingMode"] == "Immediate"
    assert shared["metadata"]["annotations"] == {"saw.redhat.com/copy-of": "cephfs"}


def test_an_existing_copy_is_kept(tmp_path):
    mine = {"metadata": {"name": "saw-shared"}, "provisioner": "nfs.csi.k8s.io"}
    result, made = copies(tmp_path, [RBD, CEPHFS, mine])
    assert result.returncode == 0, result.stderr
    assert made == [] and "StorageClass saw-shared" in result.stdout


@pytest.mark.parametrize("items", [[RBD], [RBD, CEPHFS]])
def test_classes_only_creates_the_copy_only_where_the_cluster_can_back_it(tmp_path, items):
    result, made = copies(tmp_path, items, "--classes-only")
    assert result.returncode == 0, result.stderr
    assert [m["metadata"]["name"] for m in made] == (["saw-shared"] if CEPHFS in items else [])
    assert not result.stderr
