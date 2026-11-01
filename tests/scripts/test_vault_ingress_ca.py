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
