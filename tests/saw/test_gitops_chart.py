"""The parent owns shared images; openshell-saw is the only tenant chart."""
import subprocess
from copy import deepcopy
from pathlib import Path
import yaml
from openshell_saw.blueprints import render_image

ROOT = Path(__file__).resolve().parents[2]

def render(chart, values, tmp_path):
    path = tmp_path / "values.yaml"; path.write_text(yaml.safe_dump(values))
    return subprocess.run(["helm", "template", "test", str(ROOT / chart), "--debug", "--namespace", "saw-system", "-f", str(path)], capture_output=True, text=True, check=False)

def fixture_values(enrollment, golden_image, profile_inputs):
    selections, cms = profile_inputs; raw_bom = yaml.safe_load((ROOT / "examples/saw/installer-bom.yaml").read_text())
    bom = raw_bom["spec"]
    release = {"name":"test-release", "bundleRef":"registry.example.test/saw-installer@sha256:" + "b" * 64, "bundleDigest":"sha256:" + "b" * 64, "bom":bom}
    credentials = [{"name": item["name"], "remoteKey": item["remoteKey"], "keys": sorted(item["properties"])} for item in enrollment["spec"]["credentials"]]
    tenant = {"name":"research", "subject":enrollment["spec"]["owner"]["subject"], "username":"alice", "credentials":credentials, "goldenImageRef":"test-release", "profileConfigMaps":[{"name":"profiles", "data":cms[0]["data"]}], "instance":{"workspaces":selections}, "guest":{"enabled":True,"cores":4,"memoryGi":8,"runStrategy":"Halted"}}
    image = {"name": golden_image["metadata"]["name"], **golden_image["spec"]}; image.pop("namespace")
    vault = {key: value for key, value in enrollment["spec"]["vault"].items() if key != "caConfigMap"}
    vault["caBundle"] = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
    return {"sawBlueprint":{"enabled":True,"imageNamespace":"saw-images","deployerServiceAccount":{"name":"argocd","namespace":"gitops"},"applicationSet":{"enabled":True,"repoURL":"https://git.example.test/saw.git","targetRevision":"main","destinationServer":"https://kubernetes.default.svc","project":"default","tenantChartPath":"charts/openshell-saw"},"platform":{"issuer":enrollment["spec"]["owner"]["issuer"],"vault":vault},"installer":{"defaultRelease":"test-release","releases":[release]},"goldenImages":[image],"tenants":[tenant]}}

def test_parent_generates_openshell_saw_applications(enrollment, golden_image, profile_inputs, tmp_path):
    values = fixture_values(enrollment, golden_image, profile_inputs); bob = deepcopy(values["sawBlueprint"]["tenants"][0]); bob.update(subject="bob", username="bob"); values["sawBlueprint"]["tenants"].append(bob)
    result = render("charts/saw-blueprint", values, tmp_path); assert result.returncode == 0, result.stderr
    docs = list(yaml.safe_load_all(result.stdout)); appset = next(d for d in docs if d["kind"] == "ApplicationSet"); elements = appset["spec"]["generators"][0]["list"]["elements"]
    assert appset["spec"]["template"]["spec"]["source"]["path"] == "charts/openshell-saw"; assert len(elements) == 2
    assert all(yaml.safe_load(e["installerRelease"])["name"] == "test-release" for e in elements)
    assert not any(d["kind"] in {"VirtualMachine", "ExternalSecret"} for d in docs)

def test_standalone_chart_projects_global_release_to_tenant(enrollment, golden_image, profile_inputs, tmp_path):
    cfg = fixture_values(enrollment, golden_image, profile_inputs)["sawBlueprint"]; tenant = cfg["tenants"][0]; image = render_image(golden_image)[1]["metadata"]["name"]
    values = {"openshellSaw":{"createNamespace":True,"platform":cfg["platform"],"tenant":tenant,"instance":tenant["instance"],"profileConfigMaps":tenant["profileConfigMaps"],"guest":tenant["guest"],"installerRelease":cfg["installer"]["releases"][0],"image":{"namespace":"saw-images","dataSource":image,"diskSizeGi":40}}}
    result = render("charts/openshell-saw", values, tmp_path); assert result.returncode == 0, result.stdout + result.stderr
    docs = list(yaml.safe_load_all(result.stdout)); assert next(d for d in docs if d["kind"] == "Namespace")["metadata"]["name"].startswith("saw-research-")
    installer = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "research-installer"); assert yaml.safe_load(installer["data"]["release.yaml"])["bundleDigest"] == "sha256:" + "b" * 64
    service_account = next(d for d in docs if d["kind"] == "ServiceAccount" and d["metadata"]["name"] == "saw-guest"); assert service_account["automountServiceAccountToken"] is False
    egress = next(d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "saw-guest-egress")
    assert egress["spec"]["podSelector"]["matchLabels"] == {"vm.kubevirt.io/name": "research"}
    assert egress["spec"]["egress"][0]["to"] == [{
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}},
        "podSelector": {"matchLabels": {"dns.operator.openshift.io/daemonset-dns": "default"}},
    }]
    assert egress["spec"]["egress"][0]["ports"] == [
        {"protocol": "UDP", "port": 5353}, {"protocol": "TCP", "port": 5353}]
    assert egress["spec"]["egress"][1]["ports"] == [
        {"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]
    assert egress["spec"]["egress"][2]["ports"] == [{"protocol": "TCP", "port": 443}]

def test_unknown_release_fails(enrollment, golden_image, profile_inputs, tmp_path):
    values = fixture_values(enrollment, golden_image, profile_inputs); values["sawBlueprint"]["tenants"][0]["installerReleaseRef"]="unknown"
    assert render("charts/saw-blueprint", values, tmp_path).returncode != 0

def test_generated_schema_is_current():
    result = subprocess.run(["python3", str(ROOT / "tools/saw/render_chart_schema.py"), "--check"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
