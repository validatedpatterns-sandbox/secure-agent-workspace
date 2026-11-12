"""Pin and render the optional stock Agent Sandbox platform dependency."""
import hashlib
import shutil
from pathlib import Path

import pytest
import yaml
from helm_cache import run_helm

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "agent-sandbox"
HELM = shutil.which("helm")
LOCK = yaml.safe_load((CHART / "source-lock.yaml").read_text())


def upstream():
    return [d for d in yaml.safe_load_all(
        (CHART / LOCK["upstream"]["manifestPath"]).read_text()) if d]


def render(*args, namespace="agent-sandbox-system", enabled=True):
    if not HELM:
        pytest.skip("helm is not installed")
    return run_helm([HELM, "template", "agent-sandbox", str(CHART),
                     "-n", namespace, "--set", f"enabled={str(enabled).lower()}", *args],
                    capture_output=True, text=True)


@pytest.fixture(scope="module")
def docs():
    result = render()
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def by_kind(docs, kind):
    matches = [d for d in docs if d["kind"] == kind]
    assert len(matches) == 1
    return matches[0]


def test_vendored_artifact_matches_release_lock():
    data = (CHART / LOCK["upstream"]["manifestPath"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == LOCK["upstream"]["manifestSHA256"]
    assert LOCK["upstream"]["commit"] == "b1277676f8bf0e82ea299928997ecf5d696a92f1"
    assert LOCK["controller"]["digest"] == \
        "sha256:ef1a1a3076afc996e711c44b388fbb7ffb7cd6858953d7e685166b299d77bd38"
    assert "Apache License" in (CHART / LOCK["upstream"]["licensePath"]).read_text()


def test_disabled_by_default():
    assert yaml.safe_load((CHART / "values.yaml").read_text())["enabled"] is False
    result = render(enabled=False)
    assert result.returncode == 0, result.stderr
    assert list(yaml.safe_load_all(result.stdout)) == []


def test_only_stock_core_resources_are_installed(docs):
    assert {d["kind"] for d in docs} == {
        "ServiceAccount", "ClusterRole", "ClusterRoleBinding",
        "Service", "Deployment", "CustomResourceDefinition"}
    assert len(docs) == 6
    for doc in docs:
        if "namespace" in doc["metadata"]:
            assert doc["metadata"]["namespace"] == "agent-sandbox-system"
    assert by_kind(docs, "ClusterRoleBinding")["subjects"] == [{
        "kind": "ServiceAccount", "name": "agent-sandbox-controller",
        "namespace": "agent-sandbox-system"}]


def test_crd_and_rbac_remain_upstream(docs):
    original = upstream()
    assert by_kind(docs, "CustomResourceDefinition")["spec"] == \
        by_kind(original, "CustomResourceDefinition")["spec"]
    assert by_kind(docs, "ClusterRole")["rules"] == by_kind(original, "ClusterRole")["rules"]
    role = by_kind(docs, "ClusterRole")
    assert not any("secrets" in rule["resources"] for rule in role["rules"])
    assert by_kind(docs, "ClusterRoleBinding")["roleRef"]["kind"] == "ClusterRole"


def test_served_api_matches_reviewed_openshell_fields(docs):
    spec = by_kind(docs, "CustomResourceDefinition")["spec"]
    assert spec["group"] == "agents.x-k8s.io"
    assert len(spec["versions"]) == 1
    version = spec["versions"][0]
    assert version["name"] == "v1beta1" and version["served"] and version["storage"]
    properties = version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
    assert set(LOCK["consumer"]["reviewedFields"]) <= properties.keys()
    assert properties["operatingMode"]["enum"] == ["Running", "Suspended"]
    assert "agentSocket" not in properties  # Documented unsupported optional consumer field.
    assert LOCK["consumer"]["qualification"] == "source-reviewed-only"


def test_stock_image_with_process_health_and_restricted_configuration(docs):
    pod = by_kind(docs, "Deployment")["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["image"] == LOCK["controller"]["repository"] + "@" + LOCK["controller"]["digest"]
    assert container["args"] == ["--leader-elect=true"]
    assert container["livenessProbe"]["httpGet"] == {"path": "/healthz", "port": "healthz"}
    assert container["readinessProbe"]["httpGet"] == {"path": "/readyz", "port": "healthz"}
    assert pod["securityContext"] == {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    assert container["securityContext"] == {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    assert "runAsUser" not in pod["securityContext"]
    assert container["resources"]["limits"]["memory"] == "512Mi"


def test_retention_and_in_application_ordering(docs):
    for kind, wave in [("CustomResourceDefinition", "-2"),
                       ("ClusterRole", "-1"), ("Deployment", "0")]:
        annotations = by_kind(docs, kind)["metadata"]["annotations"]
        assert annotations["argocd.argoproj.io/sync-wave"] == wave
        if kind == "CustomResourceDefinition":
            assert annotations["helm.sh/resource-policy"] == "keep"
            assert annotations["argocd.argoproj.io/sync-options"] == "Prune=false,Delete=false"


def test_mirror_keeps_locked_digest():
    result = render("--set", "controller.imageRepository=mirror.example.test:5000/platform/agent-sandbox")
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    image = by_kind(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["image"]
    assert image == "mirror.example.test:5000/platform/agent-sandbox@" + LOCK["controller"]["digest"]


@pytest.mark.parametrize("args,namespace", [
    ([], "workspace-alice"),
    (["--set", "controller.imageRepository=mirror.example.test/controller:latest"], "agent-sandbox-system"),
])
def test_invalid_namespace_or_mutable_image_is_rejected(args, namespace):
    assert render(*args, namespace=namespace).returncode != 0
