"""The ci variant stays at prod parity and deploys a real harness workspace."""

from copy import deepcopy
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ci_differs_from_prod_only_in_the_three_intended_settings():
    prod = yaml.safe_load((ROOT / "values-prod.yaml").read_text())
    expected = deepcopy(prod)
    group = expected["clusterGroup"]
    group["name"] = "ci"
    group["applications"]["saw-users"]["extraValueFiles"] = ["/overrides/saw-users-ci.yaml"]
    group["applications"]["openshell-keycloak"]["overrides"].append(
        {"name": "demo.enabled", "value": "true"})
    assert yaml.safe_load((ROOT / "values-ci.yaml").read_text()) == expected


@pytest.mark.skipif(not shutil.which("helm"), reason="helm is not installed")
def test_ci_renders_harness_enabled_notebook_and_generated_alice_identity(tmp_path):
    result = subprocess.run(["helm", "template", "saw-users", str(ROOT / "charts/saw-users"),
                             "-f", str(ROOT / "overrides/saw-users-ci.yaml"),
                             "--set", "ownerResolution.enabled=true"],
                            capture_output=True, text=True, check=True)
    docs = list(yaml.safe_load_all(result.stdout))
    apps = {doc["metadata"]["name"]: doc for doc in docs if doc and doc["kind"] == "Application"}
    values = lambda name: yaml.safe_load(apps[name]["spec"]["source"]["helm"]["values"])
    assert set(apps) == {"saw-alice", "saw-alice-bom", "saw-alice-secrets"}
    assert values("saw-alice")["allowDriverConfig"] is True
    assert values("saw-alice")["accessControl"]["owner"] == "alice"
    bom = values("saw-alice-bom")
    assert bom == {"profiles": ["data-science"], "harnessEnabled": True}
    bom_file = tmp_path / "bom.yaml"
    bom_file.write_text(yaml.safe_dump(bom))
    result = subprocess.run(["helm", "template", "saw-alice-bom", str(ROOT / "charts/saw-bom"),
                             "-f", str(bom_file)], capture_output=True, text=True, check=True)
    assert "name: notebook" in result.stdout and "ds-default" in result.stdout
    ci = yaml.safe_load((ROOT / "values-ci.yaml").read_text())
    command = ["helm", "template", "keycloak", str(ROOT / "charts/openshell-keycloak")]
    for override in ci["clusterGroup"]["applications"]["openshell-keycloak"]["overrides"]:
        command += ["--set", f"{override['name']}={override['value']}"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    realm = next(doc for doc in yaml.safe_load_all(result.stdout)
                 if doc and doc["kind"] == "KeycloakRealmImport")["spec"]
    alice = next(user for user in realm["realm"]["users"] if user["username"] == "alice")
    assert alice["realmRoles"] == ["openshell-user"]
    assert any(value["secret"] == {"name": "openshell-keycloak-user-passwords", "key": "alice"}
               for value in realm["placeholders"].values())
