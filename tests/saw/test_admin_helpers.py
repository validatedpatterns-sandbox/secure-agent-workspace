"""Tests for the safe, operator-facing SAW onboarding helpers."""
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_vault_plan_is_tenant_scoped_and_does_not_apply(tmp_path):
    values = {
        "sawBlueprint": {
            "platform": {
                "issuer": "https://identity.example.test/realms/saw",
                "vault": {"mount": "kubernetes", "prefix": "saw/users", "authMount": "kubernetes", "audience": "vault"},
            },
            "tenants": [{"name": "research", "subject": "immutable-alice", "username": "alice", "credentials": [
                {"name": "inference", "remoteKey": "nvidia", "keys": ["api_key"]},
                {"name": "search", "remoteKey": "brave", "keys": ["api_key"]},
            ]}],
        }
    }
    source = tmp_path / "values.yaml"
    source.write_text(yaml.safe_dump(values))
    result = subprocess.run(
        ["python3", str(ROOT / "tools/saw/render_vault_plan.py"), "--values", str(source), "--tenant", "research"],
        capture_output=True, text=True, check=True,
    )
    assert "bound_service_account_names=saw-vault-reader" in result.stdout
    assert "bound_service_account_namespaces=saw-research-" in result.stdout
    assert "/providers/nvidia" in result.stdout
    assert "/providers/brave" in result.stdout
    assert "vault policy write" in result.stdout
    assert "oc " not in result.stdout


def test_tenant_values_resolve_global_release_and_image(tmp_path):
    digest = "a" * 64
    values = {"sawBlueprint": {
        "imageNamespace": "saw-images",
        "platform": {"issuer": "https://identity.example.test", "vault": {"server": "https://vault.example.test", "mount": "secret", "prefix": "saw/users", "authMount": "kubernetes", "audience": "vault", "caBundle": "CA"}},
        "goldenImages": [{"name": "release", "registryURL": f"docker://registry.example.test/saw@sha256:{digest}", "diskSizeGi": 40}],
        "installer": {"defaultRelease": "release", "releases": [{"name": "release", "bundleRef": f"registry.example.test/installer@sha256:{digest}", "bundleDigest": f"sha256:{digest}", "bom": {"installerVersion": "0.1.0", "openshell": {}}}]},
        "tenants": [{"name": "research", "subject": "alice", "username": "alice", "credentials": [], "goldenImageRef": "release", "instance": {"workspaces": []}}],
    }}
    source = tmp_path / "values.yaml"; source.write_text(yaml.safe_dump(values))
    result = subprocess.run(["python3", str(ROOT / "tools/saw/render_tenant_values.py"), "--values", str(source), "--tenant", "research"], capture_output=True, text=True, check=True)
    rendered = yaml.safe_load(result.stdout)["openshellSaw"]
    assert rendered["installerRelease"]["name"] == "release"
    assert rendered["image"] == {"namespace": "saw-images", "dataSource": rendered["image"]["dataSource"], "diskSizeGi": 40}
    assert rendered["image"]["dataSource"].startswith("release-")


def test_direct_install_rejects_argocd_mode():
    result = subprocess.run(["bash", str(ROOT / "tools/saw/install_tenant.sh")], env={"SAW_TENANT": "research", "SAW_TENANT_MANAGEMENT": "argocd"}, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "Refusing direct Helm installation" in result.stderr


def test_user_values_combine_with_shared_platform_defaults(tmp_path):
    digest = "b" * 64
    platform = {"sawPlatform": {
        "platform": {"issuer": "https://identity.example.test", "vault": {"server": "https://vault.example.test", "mount": "secret", "prefix": "saw/users", "authMount": "kubernetes", "audience": "vault", "caBundle": "CA"}},
        "image": {"namespace": "saw-images", "dataSource": "qualified-saw", "diskSizeGi": 40},
        "installerRelease": {"name": "release", "bundleRef": f"registry.example.test/installer@sha256:{digest}", "bundleDigest": f"sha256:{digest}", "bom": {"installerVersion": "0.1.0", "openshell": {}}},
    }}
    user = {"sawUser": {"name": "research", "subject": "immutable-alice", "instance": {"workspaces": []}}}
    platform_file = tmp_path / "platform.yaml"; platform_file.write_text(yaml.safe_dump(platform))
    user_file = tmp_path / "alice.yaml"; user_file.write_text(yaml.safe_dump(user))
    result = subprocess.run(
        ["python3", str(ROOT / "tools/saw/render_user_values.py"), "--platform-values", str(platform_file), "--user-values", str(user_file)],
        capture_output=True, text=True, check=True,
    )
    rendered = yaml.safe_load(result.stdout)["openshellSaw"]
    assert rendered["tenant"]["username"] == "research"
    assert rendered["image"]["dataSource"] == "qualified-saw"
    assert rendered["installerRelease"]["name"] == "release"


def test_user_install_rejects_argocd_mode():
    result = subprocess.run(["bash", str(ROOT / "tools/saw/install_user.sh")], env={"SAW_USER_VALUES": "user.yaml", "SAW_TENANT_MANAGEMENT": "argocd"}, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "Refusing direct Helm installation" in result.stderr
