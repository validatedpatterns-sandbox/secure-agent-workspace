"""make saw-init is the one preparation step: keys, OIDC check, VM image, container checks."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]

FAKE_OC = """#!/usr/bin/env bash
case "$*" in
  *network.config*) echo OVNKubernetes ;;
  *clusterversion*) echo 4.22.0 ;;
  *api-resources*) echo validatingadmissionpolicies.admissionregistration.k8s.io ;;
esac
exit 0
"""


def stub(path, body):
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def run(tmp_path, users, oidc_exit=0, defaults="containerDefaults: {}\n", storage_exit=0, **extra):
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(ROOT / "scripts/saw-init.sh", scripts / "saw-init.sh")
    log = tmp_path / "calls"
    for name in ("generate-keys.sh", "images-mirror.sh"):
        stub(scripts / name, f'echo {name} >> "{log}"\n')
    stub(scripts / "shared-storage.sh", f'echo shared-storage.sh "$@" >> "{log}"\nexit {storage_exit}\n')
    stub(scripts / "check-oidc-ca.sh", f'echo check-oidc-ca.sh >> "{log}"\necho "add oidc.caBundle"\nexit {oidc_exit}\n')
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub(bin_dir / "oc", FAKE_OC.split("\n", 1)[1])
    (repo / "overrides").mkdir()
    users_file = repo / "overrides/saw-users.yaml"
    users_file.write_text("users:\n" + "".join(
        f"  - name: {name}\n    values: {{deployment: {{mode: {mode}}}}}\n" for name, mode in users) if users
        else "users: []\n")
    (repo / "overrides/saw-container-defaults.yaml").write_text(defaults)
    env = {k: v for k, v in os.environ.items() if k not in ("DEPLOYMENT_MODE", "OPENSHELL_SAW_NAME")}
    env.update(PATH=f"{bin_dir}:{os.environ['PATH']}", SAW_INIT_SKIP_IMAGE_CHECK="1", **extra)
    result = subprocess.run([str(scripts / "saw-init.sh")], cwd=repo, env=env, capture_output=True, text=True)
    calls = log.read_text().split() if log.exists() else []
    return result, calls


@pytest.mark.parametrize("users", [[], [("alice", "vm")], [("alice", "container"), ("bob", "vm")]])
def test_vm_workspaces_get_keys_oidc_check_and_the_gateway_image(tmp_path, users):
    result, calls = run(tmp_path, users)
    assert result.returncode == 0, result.stderr
    assert calls[:3] == ["generate-keys.sh", "check-oidc-ca.sh", "images-mirror.sh"]


def test_container_only_users_skip_the_vm_image(tmp_path):
    result, calls = run(tmp_path, [("alice", "container")])
    assert result.returncode == 0, result.stderr
    assert "images-mirror.sh" not in calls
    assert calls[:2] == ["generate-keys.sh", "check-oidc-ca.sh"] and "shared-storage.sh" in calls


@pytest.mark.parametrize(("code", "fails"), [(0, False), (3, False), (1, False), (2, True)])
def test_an_untrusted_oidc_issuer_stops_init(tmp_path, code, fails):
    result, _ = run(tmp_path, [("alice", "vm")], oidc_exit=code)
    assert (result.returncode != 0) is fails
    if fails:
        assert "oidc.caBundle" in result.stderr


def test_a_quickstart_container_install_runs_the_container_checks(tmp_path):
    result, calls = run(tmp_path, [], DEPLOYMENT_MODE="container", OPENSHELL_SAW_NAME="alice")
    assert result.returncode == 0, result.stderr
    assert "images-mirror.sh" not in calls and "shared-storage.sh" in calls
    assert "alice" in result.stdout



def test_without_container_users_init_still_prepares_the_storage_classes(tmp_path):
    """The portal can request a container workspace later."""
    result, calls = run(tmp_path, [("bob", "vm")])
    assert result.returncode == 0, result.stderr
    assert "shared-storage.sh" in calls


def test_a_shared_filesystem_is_optional_without_receipts(tmp_path):
    result, calls = run(tmp_path, [("alice", "container")], storage_exit=1)
    assert result.returncode == 0, result.stderr
    assert "--classes-only" in calls


def test_receipts_require_a_shared_filesystem(tmp_path):
    receipts = "containerDefaults: {auditReceipts: true}\n"
    result, calls = run(tmp_path, [("alice", "container")], defaults=receipts, storage_exit=1)
    assert result.returncode != 0
    assert "shared-storage.sh" in calls and "--classes-only" not in calls
