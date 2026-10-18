"""The shared identity chart is opt-in and bootstraps CRDs before operands."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[2] / "charts/spire-identity"
pytestmark = pytest.mark.skipif(not shutil.which("helm"), reason="helm required")


def render(*args):
    return subprocess.run([
        "helm", "template", "saw-spire", str(CHART), "-n",
        "zero-trust-workload-identity-manager", *args,
    ], capture_output=True, text=True)


def test_disabled_is_empty():
    result = render()
    assert result.returncode == 0, result.stderr
    assert not list(filter(None, yaml.safe_load_all(result.stdout)))


def test_bootstrap_only_installs_operator():
    result = render("--set", "spiffe.enabled=true")
    assert result.returncode == 0, result.stderr
    docs = list(filter(None, yaml.safe_load_all(result.stdout)))
    assert {d["kind"] for d in docs} == {"OperatorGroup", "Subscription"}
    sub = next(d for d in docs if d["kind"] == "Subscription")
    assert sub["spec"]["installPlanApproval"] == "Manual"


def test_operands_require_explicit_identity():
    result = render("--set", "spiffe.enabled=true,operands.enabled=true")
    assert result.returncode != 0
    assert "spiffe.trustDomain is required" in result.stderr


def test_operands_use_operator_schemas():
    result = render("--set", "spiffe.enabled=true,operands.enabled=true",
                    "--set", "spiffe.trustDomain=saw.test,spiffe.clusterName=test",
                    "--set", "spiffe.jwtIssuer=https://discovery.saw.test")
    assert result.returncode == 0, result.stderr
    docs = {d["kind"]: d for d in yaml.safe_load_all(result.stdout) if d}
    assert len(docs) == 7
    assert docs["SpireServer"]["spec"]["defaultJWTValidity"] == "5m0s"
    assert docs["SpireOIDCDiscoveryProvider"]["spec"]["managedRoute"] == "true"
    assert all("namespace" not in d["metadata"] for d in docs.values())


def test_registrar_uses_the_launcher_constraint():
    digest = "sha256:" + ("a" * 64)
    result = render("--set", "spiffe.enabled=true,registrar.enabled=true",
                    "--set", "spiffe.trustDomain=saw.test",
                    "--set", "registrar.image=example/registrar@" + digest)
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    role = next(d for d in docs if d["kind"] == "ClusterRole" and d["metadata"]["name"] == "saw-spire-registrar-launcher")
    assert role["rules"] == [{
        "apiGroups": ["security.openshift.io"],
        "resources": ["securitycontextconstraints"],
        "resourceNames": ["kubevirt-controller"],
        "verbs": ["use"],
    }]
    binding = next(d for d in docs if d["kind"] == "ClusterRoleBinding" and d["metadata"]["name"] == "saw-spire-registrar-launcher")
    assert binding["subjects"] == [{
        "kind": "ServiceAccount",
        "name": "saw-spire-registrar",
        "namespace": "zero-trust-workload-identity-manager",
    }]
    granted = []
    for doc in docs:
        for rule in doc.get("rules") or []:
            if "securitycontextconstraints" in (rule.get("resources") or []):
                granted.extend(rule.get("resourceNames") or [])
    assert granted == ["kubevirt-controller"]


def test_registrar_lifetimes_are_validated_and_passed():
    digest = "sha256:" + ("a" * 64)
    result = render("--set", "spiffe.enabled=true,registrar.enabled=true",
                    "--set", "spiffe.trustDomain=saw.test",
                    "--set", "registrar.image=example/registrar@" + digest,
                    "--set", "registrar.joinTokenTTL=600,registrar.jwtSvidTTL=180,registrar.x509SvidTTL=1800")
    assert result.returncode == 0, result.stderr
    deploy = next(d for d in yaml.safe_load_all(result.stdout) if d and d["kind"] == "Deployment")
    env = {item["name"]: item.get("value") for item in deploy["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["JOIN_TOKEN_TTL"] == "600"
    assert env["JWT_SVID_TTL"] == "180"
    assert env["X509_SVID_TTL"] == "1800"
    for raw in ("59", "86401", "10m"):
        bad = render("--set", "spiffe.enabled=true,registrar.enabled=true",
                     "--set", "spiffe.trustDomain=saw.test",
                     "--set", "registrar.image=example/registrar@" + digest,
                     "--set", "registrar.jwtSvidTTL=" + raw)
        assert bad.returncode != 0
        assert "registrar.jwtSvidTTL" in bad.stderr


def test_refuses_wrong_namespace_and_insecure_issuer():
    assert render("--set", "spiffe.enabled=true", "-n", "default").returncode != 0
    result = render("--set", "spiffe.enabled=true,operands.enabled=true",
                    "--set", "spiffe.trustDomain=saw.test,spiffe.clusterName=test",
                    "--set", "spiffe.jwtIssuer=http://discovery.saw.test")
    assert result.returncode != 0
    assert "HTTPS origin" in result.stderr
