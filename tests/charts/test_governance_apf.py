"""governance engine switch: the OpenShell governance interceptor or APF.

The APF chart itself is private (ghcr.io/mkhaas/apf), so these tests check
what this repo renders around it: the inputs, the Argo CD Application, the
NetworkPolicy and the gateway bindings of each SAW.
"""
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GOV_CHART = ROOT / "charts" / "governance-interceptor"
SAW_CHART = ROOT / "charts" / "openshell-saw"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")

sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from test_apf_bundle import load_script  # noqa: E402

# crates/openshell-gateway-interceptors/src/routes.rs: the only RPCs a gateway
# lets an interceptor bind to. Anything else stops the gateway at startup.
INTERCEPTABLE = {
    "CreateSandbox", "AttachSandboxProvider", "DetachSandboxProvider", "DeleteSandbox",
    "CreateSshSession", "ExposeService", "DeleteService", "RevokeSshSession",
    "CreateProvider", "ImportProviderProfiles", "UpdateProviderProfiles", "UpdateProvider",
    "ConfigureProviderRefresh", "RotateProviderCredential", "DeleteProviderRefresh",
    "DeleteProvider", "DeleteProviderProfile", "UpdateConfig", "SubmitPolicyAnalysis",
    "ApproveDraftChunk", "RejectDraftChunk", "ApproveAllDraftChunks", "EditDraftChunk",
    "UndoDraftChunk", "ClearDraftChunks",
}


def template(chart, *args, namespace="openshell-agents"):
    return subprocess.run([HELM, "template", "governance-interceptor", str(chart),
                           "--namespace", namespace, *args], capture_output=True, text=True)


def docs(chart, *args):
    result = template(chart, *args)
    assert result.returncode == 0, result.stderr
    return {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(result.stdout) if d}


@pytest.fixture(scope="module")
def apf_chart(tmp_path_factory):
    """The chart with a bundle signed by a throwaway key in files/apf."""
    tmp = tmp_path_factory.mktemp("apf")
    chart = tmp / "governance-interceptor"
    shutil.copytree(GOV_CHART, chart, ignore=shutil.ignore_patterns("files"))
    mod = load_script(tmp / "policy", chart / "files" / "apf", tmp / "keys" / "apf.seed")
    mod.cmd_keygen(type("A", (), {"force": False})())
    mod.cmd_build(type("A", (), {"bump": False})())
    return chart


def test_interceptor_is_the_default():
    rendered = docs(GOV_CHART)
    assert ("Deployment", "governance-interceptor") in rendered
    assert ("Service", "governance-interceptor") in rendered
    assert not [k for k in rendered if k[0] in ("Application", "ExternalSecret")]
    pod = rendered[("NetworkPolicy", "governance-interceptor")]["spec"]["podSelector"]
    assert pod == {"matchLabels": {"app.kubernetes.io/name": "governance-interceptor"}}


def test_the_pattern_sets_the_engine():
    values = yaml.safe_load((ROOT / "values-global.yaml").read_text())
    assert values["global"]["governance"]["engine"] in ("interceptor", "apf")


def test_apf_needs_a_signed_bundle(tmp_path):
    chart = tmp_path / "governance-interceptor"
    shutil.copytree(GOV_CHART, chart, ignore=shutil.ignore_patterns("files"))
    result = template(chart, "--set", "engine=apf")
    assert result.returncode != 0
    assert "make apf-keys apf-bundle" in result.stderr


def test_unknown_engine_fails():
    result = template(GOV_CHART, "--set", "engine=opa")
    assert result.returncode != 0
    assert "interceptor or apf" in result.stderr


def test_global_engine_wins(apf_chart):
    rendered = docs(apf_chart, "--set", "engine=interceptor", "--set", "global.governance.engine=apf")
    assert ("Deployment", "governance-interceptor") not in rendered
    assert ("Application", "governance-apf") in rendered


def test_apf_replaces_the_interceptor(apf_chart):
    rendered = docs(apf_chart, "--set", "engine=apf", "--set", "global.vpArgoNamespace=vp-gitops")
    assert ("Deployment", "governance-interceptor") not in rendered
    assert ("Service", "governance-interceptor") not in rendered

    app = rendered[("Application", "governance-apf")]
    assert app["metadata"]["namespace"] == "vp-gitops"
    # Pruned when the engine switches back: APF's objects must go with it.
    assert app["metadata"]["finalizers"] == ["resources-finalizer.argocd.argoproj.io"]
    source = app["spec"]["source"]
    assert (source["repoURL"], source["chart"], source["targetRevision"]) == \
        ("ghcr.io/mkhaas/apf/charts", "apf", "0.2.0")
    helm = source["helm"]
    # The Service keeps the name every SAW gateway calls.
    assert helm["releaseName"] == "governance-interceptor"
    values = helm["valuesObject"]
    assert values["fullnameOverride"] == "governance-interceptor"
    assert values["openshift"] is True
    assert values["interceptor"]["port"] == 18081
    assert values["interceptor"]["failurePolicy"] == "fail_closed"
    assert values["image"]["pullSecrets"] == [{"name": "ghcr-pull"}]
    assert values["bundle"] == {"existingConfigMap": "governance-apf-bundle", "manifest": "bundle.yaml"}
    assert values["trustRoot"] == {"existingConfigMap": "governance-apf-trust"}
    # Never the dev key baked into the APF chart.
    assert values["signing"] == {"existingSecret": "governance-apf-signing"}
    # A new bundle restarts the APF pod (its chart only watches inputs it renders).
    import hashlib
    files = apf_chart / "files" / "apf"
    assert values["podAnnotations"] == {"governance.openshell.pattern/bundle-checksum": hashlib.sha256(
        (files / "bundle.tar.gz").read_bytes() + (files / "apf.pub").read_bytes()).hexdigest()}
    assert app["spec"]["destination"]["namespace"] == "openshell-agents"
    assert app["spec"]["ignoreDifferences"][0]["name"] == "governance-interceptor-httptoken"
    assert "RespectIgnoreDifferences=true" in app["spec"]["syncPolicy"]["syncOptions"]


def test_apf_inputs_come_from_the_chart_files(apf_chart):
    import base64
    rendered = docs(apf_chart, "--set", "engine=apf")
    bundle = rendered[("ConfigMap", "governance-apf-bundle")]["binaryData"]["bundle.tar.gz"]
    assert base64.b64decode(bundle) == (apf_chart / "files/apf/bundle.tar.gz").read_bytes()
    trust = rendered[("ConfigMap", "governance-apf-trust")]["data"]["apf-dev.pub"]
    assert trust.strip() == (apf_chart / "files/apf/apf.pub").read_text().strip()
    assert "seed" not in str(rendered[("ConfigMap", "governance-apf-trust")])


def test_apf_secrets_come_from_vault(apf_chart):
    rendered = docs(apf_chart, "--set", "engine=apf")
    pull = rendered[("ExternalSecret", "ghcr-pull")]["spec"]
    assert pull["dataFrom"] == [{"extract": {"key": "secret/data/hub/ghcr"}}]
    assert pull["target"]["template"]["type"] == "kubernetes.io/dockerconfigjson"
    dockerconfig = pull["target"]["template"]["data"][".dockerconfigjson"]
    # ESO renders valid JSON even when the token file ends in a newline.
    assert '| toJson' in dockerconfig and '.token | trim' in dockerconfig and '"ghcr.io"' in dockerconfig
    seed = rendered[("ExternalSecret", "governance-apf-signing")]["spec"]
    assert seed["dataFrom"] == [{"extract": {"key": "secret/data/hub/apf-signing"}}]
    assert seed["target"]["template"]["data"] == {"apf-dev.seed": "{{ .seed }}"}
    repo = rendered[("ExternalSecret", "governance-apf-chart-repo")]
    assert repo["metadata"]["namespace"] == "vp-gitops"
    tmpl = repo["spec"]["target"]["template"]
    assert tmpl["metadata"]["labels"] == {"argocd.argoproj.io/secret-type": "repository"}
    assert tmpl["data"]["enableOCI"] == "true"
    assert tmpl["data"]["url"] == "ghcr.io/mkhaas/apf/charts"


def test_quickstart_leaves_out_argo_and_vault(apf_chart):
    rendered = docs(apf_chart, "--set", "engine=apf", "--set", "apf.application.enabled=false",
                    "--set", "apf.externalSecrets.enabled=false")
    assert not [k for k in rendered if k[0] in ("Application", "ExternalSecret")]
    assert ("ConfigMap", "governance-apf-bundle") in rendered


def test_networkpolicy_selects_the_apf_pod(apf_chart):
    rendered = docs(apf_chart, "--set", "engine=apf")
    policy = rendered[("NetworkPolicy", "governance-interceptor")]["spec"]
    # The APF chart's selectorLabels: its chart name and the release name.
    assert policy["podSelector"] == {"matchLabels": {
        "app.kubernetes.io/name": "apf", "app.kubernetes.io/instance": "governance-interceptor"}}
    sources = policy["ingress"][0]["from"]
    assert {"namespaceSelector": {"matchLabels": {"openshell.pattern/saw": "true"}},
            "podSelector": {"matchLabels": {"kubevirt.io": "virt-launcher"}}} in sources
    assert policy["ingress"][0]["ports"] == [{"port": 18081, "protocol": "TCP"}]


# -- the gateway side (openshell-saw) -----------------------------------------------

def gateway_toml_text(*args):
    result = subprocess.run([HELM, "template", "saw-test", str(SAW_CHART), "--namespace", "saw-alice",
                             "--set", "sandboxName=saw-test", *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    for doc in yaml.safe_load_all(result.stdout):
        if doc and doc["kind"] == "ConfigMap" and "gateway.toml" in doc.get("data", {}):
            return doc["data"]["gateway.toml"]
    raise AssertionError("no gateway.toml")


def gateway_toml(*args):
    return tomllib.loads(gateway_toml_text(*args))


GOLDEN = Path(__file__).resolve().parent / "golden"


@pytest.mark.parametrize("golden,args", [
    ("gateway-interceptor.toml", ()),
    ("gateway-interceptor-oidc.toml", ("--set", "oidc.issuerUrl=https://kc.example.com/realms/openshell")),
])
def test_interceptor_engine_gateway_toml_is_byte_identical(golden, args):
    """The default engine must not change a single byte of gateway.toml: the
    installer restarts the gateway whenever the file changes, and existing
    VMs must not restart for this switch. The golden files are what the chart
    rendered before the engine switch (PR #52 review)."""
    assert gateway_toml_text(*args) == (GOLDEN / golden).read_text()


def bindings(interceptor):
    return {b["rpc"].removeprefix("openshell.v1.OpenShell/"): b["phases"] for b in interceptor["bindings"]}


def test_interceptor_engine_keeps_its_four_bindings():
    [gov] = gateway_toml()["openshell"]["gateway"]["interceptors"]
    assert gov["binding_policy"] == "allowlist"
    assert bindings(gov) == {"CreateSandbox": ["modify_operation", "validate"],
                             "CreateProvider": ["validate"], "UpdateConfig": ["validate"],
                             "SubmitPolicyAnalysis": ["validate"]}


@pytest.mark.parametrize("flag", ["governance.engine=apf", "global.governance.engine=apf"])
def test_apf_engine_uses_the_bindings_apf_declares(flag):
    """APF declares one binding per phase (three each for CreateSandbox and
    UpdateConfig). OpenShell's allowlist and exact modes reject that
    ("declared multiple bindings", seen live), so APF runs with dynamic:
    its own RPCs, phases and per-binding failure policy (fail_open for
    post_commit), limited to OpenShell's interceptable RPCs."""
    gateway = gateway_toml("--set", flag)["openshell"]["gateway"]
    [gov] = gateway["interceptors"]
    assert gateway["provider_profile_sources"] == [{"type": "interceptor", "name": "governance"}]
    assert gov["name"] == "governance"
    assert gov["grpc_endpoint"] == "http://governance-interceptor.openshell-agents.svc.cluster.local:18081"
    assert gov["failure_policy"] == "fail_closed"
    assert gov["binding_policy"] == "dynamic"
    assert "bindings" not in gov


def test_apf_bindings_can_still_be_narrowed(tmp_path):
    values = tmp_path / "narrow.yaml"
    values.write_text("governance:\n  engine: apf\n  bindings:\n    apf:\n"
                      "      - { rpc: CreateSandbox, phases: [validate] }\n")
    gov = gateway_toml("-f", str(values))["openshell"]["gateway"]["interceptors"][0]
    assert gov["binding_policy"] == "dynamic"
    assert bindings(gov) == {"CreateSandbox": ["validate"]}
    assert set(bindings(gov)) <= INTERCEPTABLE


def test_unknown_engine_fails_in_openshell_saw():
    result = subprocess.run([HELM, "template", "saw-test", str(SAW_CHART), "--set", "sandboxName=x",
                             "--set", "governance.engine=opa"], capture_output=True, text=True)
    assert result.returncode != 0
    assert "governance.engine" in result.stderr


# -- the committed bundle ---------------------------------------------------------------

def test_committed_bundle_is_signed_and_current():
    """Only once someone has signed a bundle. With the pattern on apf, a
    governance-policy change must come with a re-signed bundle."""
    bundle = GOV_CHART / "files" / "apf" / "bundle.tar.gz"
    if not bundle.exists():
        pytest.skip("no APF bundle committed yet (make apf-keys apf-bundle)")
    engine = yaml.safe_load((ROOT / "values-global.yaml").read_text())["global"]["governance"]["engine"]
    mod = load_script()
    assert mod.verify(check_current=engine == "apf") == []
