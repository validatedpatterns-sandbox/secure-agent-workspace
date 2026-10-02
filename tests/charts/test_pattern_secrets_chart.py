"""Render charts/pattern-secrets: which Secrets a user's namespace syncs from Vault."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "pattern-secrets"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def keys(*args):
    result = subprocess.run([HELM, "template", "x", str(CHART), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    out = {}
    for d in yaml.safe_load_all(result.stdout):
        if d:
            spec = d["spec"]
            out[d["metadata"]["name"]] = ({e["extract"]["key"] for e in spec.get("dataFrom", [])}
                                          | {e["remoteRef"]["key"] for e in spec.get("data", [])})
    return out


def test_defaults_sync_everything_from_the_hub():
    assert keys() == {"inference": {"secret/data/hub/inference"},
                      "web-search": {"secret/data/hub/web-search"},
                      "openshell-ssh-pubkey": {"secret/data/hub/ssh"},
                      "openshell-aap-ssh": {"secret/data/hub/ssh"}}


def test_a_user_prefix_keeps_the_shared_ssh_key(tmp_path):
    values = tmp_path / "v.yaml"
    values.write_text(yaml.safe_dump({"vaultPrefix": "secret/data/hub/saw-bob",
                                      "sshVaultPrefix": "secret/data/hub", "secrets": ["inference"]}))
    got = keys("-f", str(values))
    assert got == {"inference": {"secret/data/hub/saw-bob/inference"},
                   "openshell-ssh-pubkey": {"secret/data/hub/ssh"},
                   "openshell-aap-ssh": {"secret/data/hub/ssh"}}


def test_the_inference_template_needs_only_what_every_workspace_has():
    """Found live: a portal workspace (data-science) has no `model` in Vault,
    and the template's `{{ .model }}` failed the ExternalSecret, so the VM
    booted without the inference Secret. Only keys every source writes may
    be required; the others go through `index … | default`."""
    import json
    import re
    out = subprocess.run([HELM, "template", "x", str(CHART)], capture_output=True, text=True, check=True).stdout
    docs = [d for d in yaml.safe_load_all(out) if d]
    (es,) = [d for d in docs if d["kind"] == "ExternalSecret" and d["metadata"]["name"] == "inference"]
    required = set()
    for value in es["spec"]["target"]["template"]["data"].values():
        required |= set(re.findall(r"\{\{\s*\.(\w+)\s*\}\}", value))
    assert required == {"provider", "api_key"}
    # What the portal writes for every profile's inference Secret: the
    # credential field and the provider it adds.
    catalog = json.loads((ROOT / "charts" / "openshell-rhdh" / "files" / "profile-catalog.json").read_text())
    for name, profile in catalog["profiles"].items():
        if "inference" in profile["secrets"]:
            keys = {f["key"] for f in profile["secrets"]["inference"]["fields"]} | {"provider"}
            assert required <= keys, name
