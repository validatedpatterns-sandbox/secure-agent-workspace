import json
from pathlib import Path
import shutil

import pytest
import yaml
from helm_cache import run_helm

ROOT = Path(__file__).resolve().parents[2]
HELM = shutil.which("helm")
pytestmark = [pytest.mark.ci_external, pytest.mark.skipif(not HELM, reason="Helm required")]


def render(*args, enabled=True):
    return run_helm([HELM, "template", "identity", str(ROOT / "charts/saw-kubernetes-identity"),
        "-n", "saw-test-trusted", "--set", "enabled=" + str(enabled).lower(),
        "--set", "gateway=saw-test,targetNamespace=saw-test,ownerID=67a9891d-e281-442f-86c3-41771f5ce049",
        "--set", "serverSans[0]=saw-test-gateway.saw-test.svc",
        "--set", "serverSans[1]=saw-test-gateway.saw-test.svc.cluster.local", *args],
        capture_output=True, text=True)


def test_stock_generator_and_restricted_projection_job():
    result = render()
    assert result.returncode == 0, result.stderr
    assert render().stdout == result.stdout
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    assert not any(d["kind"] == "Secret" for d in docs)
    job = next(d for d in docs if d["kind"] == "Job")
    pod = job["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"] == {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    init = pod["initContainers"][0]
    assert init["args"][:3] == ["generate-certs", "--output-dir", "/generated/pki"]
    assert not any(v["name"] == "api" for v in init["volumeMounts"])
    for c in [init, *pod["containers"]]:
        assert "@sha256:" in c["image"]
        assert c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
        assert c["securityContext"]["allowPrivilegeEscalation"] is False
    volume = next(v for v in pod["volumes"] if v["name"] == "generated")
    assert volume["emptyDir"] == {"medium": "Memory", "sizeLimit": "16Mi"}
    cm = next(d for d in docs if d["kind"] == "ConfigMap")
    config = json.loads(cm["data"]["config.json"])
    assert config["namespace"] != config["targetNamespace"]
    assert cm["data"]["bootstrap.py"].rstrip() == (ROOT / "charts/saw-kubernetes-identity/files/bootstrap.py").read_text().rstrip()


def test_limited_get_create_permissions_and_no_secret_updates():
    docs = list(yaml.safe_load_all(render().stdout))
    for role in [d for d in docs if d["kind"] in {"Role", "ClusterRole"}]:
        for rule in role["rules"]:
            assert set(rule["verbs"]) <= {"get", "create"}
            if "get" in rule["verbs"]:
                assert rule["resourceNames"]
    trusted = next(d for d in docs if d["kind"] == "Role" and d["metadata"]["namespace"] == "saw-test-trusted")
    assert trusted["rules"][1]["resourceNames"] == ["saw-test-identity"]
    runtime = next(d for d in docs if d["kind"] == "Role" and d["metadata"]["namespace"] == "saw-test")
    assert not any("admin" in n or "identity" in n for n in runtime["rules"][1]["resourceNames"])


def test_disabled_chart_has_no_resources():
    result = render(enabled=False)
    assert result.returncode == 0 and not result.stdout.strip()


@pytest.mark.parametrize("value", ["targetNamespace=saw-test-trusted", "targetNamespace=kube-system",
    "ownerID=", "gatewayImage=repo:latest", "helperImage=repo:latest", "adminDays=0", "adminDays=91",
    "serverSans[0]=other.example.test"])
def test_bad_inputs_fail_render(value):
    result = render("--set", value)
    assert result.returncode != 0 and not result.stdout.strip()
