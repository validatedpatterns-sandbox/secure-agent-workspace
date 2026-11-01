"""Vault's ingress Route must use ingress trust, including on first install."""
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_vault_route_trust_comes_from_the_cluster_ingress_bundle():
    values = yaml.safe_load((ROOT / "values-prod.yaml").read_text())
    provider = values.get("ocpExternalSecrets", {}).get("caProvider", {})
    assert provider.get("enabled") is True
    # This cluster-owned ConfigMap exists before Vault or tenant secrets do.
    assert provider["hostCluster"] == {
        "type": "ConfigMap",
        "name": "default-ingress-cert",
        "namespace": "openshift-config-managed",
        "key": "ca-bundle.crt",
    }


def test_portal_bootstrap_verifies_vault_before_sending_the_root_token():
    play = yaml.safe_load((ROOT / "ansible/playbooks/saw-portal-vault.yaml").read_text())[0]
    assert play["vars"]["vault_ca"] == "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
    tasks = play["tasks"]
    stat = next(i for i, t in enumerate(tasks) if "ansible.builtin.stat" in t)
    guard = next(i for i, t in enumerate(tasks) if "ansible.builtin.fail" in t)
    token = next(i for i, t in enumerate(tasks) if t.get("kubernetes.core.k8s_info", {}).get("name") == "vaultkeys")
    assert stat < guard < token
    assert tasks[stat]["ansible.builtin.stat"]["path"] == "{{ vault_ca }}"
    assert tasks[guard]["when"] == "not vault_ca_file.stat.exists"
    requests = [t["ansible.builtin.uri"] for t in tasks if "ansible.builtin.uri" in t]
    assert len(requests) == 2
    for request in requests:
        assert request["validate_certs"] is True
        assert request["ca_path"] == "{{ vault_ca }}"
