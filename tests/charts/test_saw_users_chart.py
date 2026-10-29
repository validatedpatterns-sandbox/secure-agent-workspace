"""Render the saw-users chart and check one list entry per person.

Needs `helm` on PATH. The last test lays out the rendered openshell-saw
values the way the VM mounts them and runs the shipped installer.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from helm_cache import run_helm
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "saw-users"
SAW_CHART = ROOT / "charts" / "openshell-saw"
BOM_CHART = ROOT / "charts" / "saw-bom"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")

FINALIZER = "resources-finalizer.argocd.argoproj.io/foreground"

ALICE = {"name": "alice"}
BOB = {
    "name": "bob",
    "ownerSubject": "3f2c-subject",
    "vaultPrefix": "secret/data/hub/saw-bob",
    "profiles": ["custom"],
    "values": {"dashboard": {"insecureSkipIssuerTlsVerify": True},
               "oidc": {"issuerUrl": "https://sso.example.com/realms/corp"}},
}


def helm(*args):
    command = [HELM, *args]
    if str(SAW_CHART) in command:
        command += ["-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml")]
    return run_helm(command, capture_output=True, text=True)


def render_file(tmp_path, users, extra=None):
    payload = {"users": users, **(extra or {})}
    values_file = tmp_path / "users.yaml"
    values_file.write_text(yaml.safe_dump(payload))
    result = helm("template", "saw-users", str(CHART), "-f", str(values_file))
    return result


def docs_from(result):
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def by_kind(docs, kind):
    return [doc for doc in docs if doc["kind"] == kind]


def app(docs, name):
    found = [doc for doc in by_kind(docs, "Application") if doc["metadata"]["name"] == name]
    assert len(found) == 1, name
    return found[0]


def helm_values(application):
    return yaml.safe_load(application["spec"]["source"]["helm"]["values"])


@pytest.mark.ci_external
def test_catalog_metadata_projection_retains_each_sandbox_model(tmp_path):
    docs = docs_from(render_file(tmp_path, [{"name": "alice", "profiles": ["data-science"]}]))
    values = helm_values(app(docs, "saw-alice-secrets"))
    assert set(values["metaKeys"]["inference"]) == {"provider", "model", "cuda_model"}
    assert all("api_key" not in keys for keys in values["metaKeys"].values())
    path = tmp_path / "metadata-values.yaml"
    path.write_text(yaml.safe_dump(values))
    result = helm("template", "secrets", str(ROOT / "charts/pattern-secrets"), "-f", str(path))
    rendered = docs_from(result)
    meta = next(d for d in rendered if d["metadata"]["name"] == "inference-meta")
    data = meta["spec"]["target"]["template"]["data"]
    assert set(data) == {"provider", "model", "cuda_model"}
    assert data["provider"] == '{{ index . "provider" | default "" }}'
    assert data["cuda_model"] == '{{ index . "cuda_model" | default "" }}'



@pytest.mark.ci_external
def test_ci_nvidia_binds_both_aliases_and_projects_only_provider(tmp_path):
    docs = docs_from(render_file(tmp_path, [{"name": "ciowner", "profiles": ["ci-nvidia"]}]))
    values = helm_values(app(docs, "saw-ciowner"))
    assert values["credentialProxy"]["secrets"] == [
        {"name": "inference", "key": "api_key", "providers": ["nvidia", "build"]}]
    secrets = helm_values(app(docs, "saw-ciowner-secrets"))
    assert secrets["metaKeys"] == {"inference": ["provider"]}

@pytest.mark.ci_external
def test_two_users_get_labelled_namespaces_and_six_apps(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, BOB]))
    namespaces = {doc["metadata"]["name"]: doc for doc in by_kind(docs, "Namespace")}
    assert set(namespaces) == {"saw-alice", "saw-bob"}
    alice_ns = namespaces["saw-alice"]["metadata"]
    assert alice_ns["labels"] == {
        "openshell.pattern/saw": "true",
        "openshell.pattern/owner": "alice",
        "argocd.argoproj.io/managed-by": "vp-gitops",
    }
    assert alice_ns["annotations"]["argocd.argoproj.io/sync-wave"] == "-1"
    assert alice_ns["annotations"]["argocd.argoproj.io/sync-options"] == "Prune=false"

    names = sorted(doc["metadata"]["name"] for doc in by_kind(docs, "Application"))
    assert names == [
        "saw-alice", "saw-alice-bom", "saw-alice-secrets",
        "saw-bob", "saw-bob-bom", "saw-bob-secrets",
    ]
    for name in names:
        application = app(docs, name)
        assert application["metadata"]["namespace"] == "vp-gitops"
        assert "finalizers" not in application["metadata"]
        assert application["spec"]["destination"]["name"] == "in-cluster"
        # Server-side apply, and nothing else (no CreateNamespace: the chart
        # makes the namespaces): client-side apply's last-applied annotation
        # would hold the whole installer ConfigMap, past the 256 KiB limit.
        assert application["spec"]["syncPolicy"] == {"automated": {"selfHeal": True},
                                                      "retry": {"limit": 20},
                                                      "syncOptions": ["ServerSideApply=true"]}
        # Found on the GB200: without server-side diff the VM stayed
        # OutOfSync on the fields KubeVirt defaults. Found on OpenShift:
        # without IncludeMutationWebhook every comparison failed on the
        # user's Routes, so the app never synced a later commit.
        assert (application["metadata"]["annotations"]["argocd.argoproj.io/compare-options"]
                == "ServerSideDiff=true,IncludeMutationWebhook=true")
        assert "ignoreMissingValueFiles" not in application["spec"]["source"]["helm"]


@pytest.mark.ci_external
def test_agent_apps_ignore_only_kubevirt_vm_defaults(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, BOB]))
    pointers = [
        "/metadata/annotations/kubemacpool.io~1transaction-timestamp",
        "/metadata/annotations/kubevirt.io~1latest-observed-api-version",
        "/metadata/annotations/kubevirt.io~1storage-observed-api-version",
        "/spec/template/metadata/annotations/kubevirt.io~1pci-topology-version",
        "/spec/template/spec/architecture",
        "/spec/template/spec/domain/devices/interfaces/0/macAddress",
        "/spec/template/spec/domain/firmware/serial",
        "/spec/template/spec/domain/firmware/uuid",
        "/spec/template/spec/domain/machine",
    ]
    for name in ("saw-alice", "saw-bob"):
        assert app(docs, name)["spec"]["ignoreDifferences"] == [{
            "group": "kubevirt.io", "kind": "VirtualMachine", "jsonPointers": pointers}]
    for name in ("saw-alice-bom", "saw-alice-secrets", "saw-bob-bom", "saw-bob-secrets"):
        assert "ignoreDifferences" not in app(docs, name)["spec"]


@pytest.mark.ci_external
def test_waves_release_names_and_value_overrides(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, BOB]))

    secrets = app(docs, "saw-alice-secrets")
    assert secrets["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "0"
    assert secrets["spec"]["source"]["path"] == "charts/pattern-secrets"
    assert secrets["spec"]["source"]["helm"]["releaseName"] == "saw-alice-secrets"
    assert secrets["spec"]["destination"]["namespace"] == "saw-alice"
    assert helm_values(secrets) == {"vaultPrefix": "secret/data/hub",
                                    "sshVaultPrefix": "secret/data/hub",
                                    "secrets": ["inference", "web-search"],
                                    "metaKeys": {"inference": ["cuda_model", "model", "provider"],
                                                 "web-search": ["provider"]},
                                    "clusterCaSecret": "saw-ingress-ca"}

    bob_secrets = helm_values(app(docs, "saw-bob-secrets"))
    assert bob_secrets == {"vaultPrefix": "secret/data/hub/saw-bob",
                           "sshVaultPrefix": "secret/data/hub",
                           "secrets": ["inference", "web-search"],
                           "metaKeys": {},
                           "clusterCaSecret": "saw-ingress-ca"}

    bom = app(docs, "saw-alice-bom")
    assert bom["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "0"
    assert bom["spec"]["source"]["path"] == "charts/saw-bom"
    assert helm_values(bom) == {"profiles": ["data-science"], "imageOverrides": {}}
    assert helm_values(app(docs, "saw-bob-bom")) == {
        "profiles": ["custom"], "imageOverrides": {}}

    alice = app(docs, "saw-alice")
    assert alice["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "1"
    assert alice["spec"]["source"]["path"] == "charts/openshell-saw"
    assert alice["spec"]["source"]["helm"]["releaseName"] == "alice"
    assert alice["spec"]["source"]["repoURL"] == "https://example.com/secure-agent-workspace.git"
    assert alice["spec"]["source"]["targetRevision"] == "main"
    alice_values = helm_values(alice)
    assert alice_values["accessControl"] == {"owner": "alice", "ownerSubject": ""}
    assert "job" not in alice_values      # no prepare Job to tune
    # The proxies verify the issuer; the VM trusts the cluster's ingress CA.
    assert "insecureSkipIssuerTlsVerify" not in alice_values.get("dashboard", {})
    assert alice_values["oidc"] == {"clusterCaSecret": "saw-ingress-ca"}
    assert alice_values["global"]["clusterDomain"] == "example.com"
    assert "originURL" not in alice_values["global"]
    assert "mtalvi" not in alice["spec"]["source"]["repoURL"]

    bob_values = helm_values(app(docs, "saw-bob"))
    assert bob_values["accessControl"] == {"owner": "bob", "ownerSubject": "3f2c-subject"}
    assert bob_values["dashboard"]["insecureSkipIssuerTlsVerify"] is True
    # A user's own values win; openshell-saw ignores clusterCaSecret for an
    # external issuer.
    assert bob_values["oidc"]["issuerUrl"] == "https://sso.example.com/realms/corp"


@pytest.mark.ci_external
def test_registry_pull_secret_uses_shared_vault_entry(tmp_path):
    extra = {"defaults": {"openshellSaw": {"registry": {
        "host": "image-registry.openshift-image-registry.svc.cluster.local:5000",
        "authSecret": "registry-pull"}}}}
    docs = docs_from(render_file(tmp_path, [ALICE], extra))
    values = helm_values(app(docs, "saw-alice-secrets"))
    assert values["registryPullSecret"] == "registry-pull"
    result = helm("template", "secrets", str(ROOT / "charts/pattern-secrets"),
                  "--set-string", "registryPullSecret=registry-pull",
                  "--set-string", "sshVaultPrefix=secret/data/hub")
    secret_docs = docs_from(result)
    registry = next(doc for doc in secret_docs if doc["kind"] == "ExternalSecret"
                    and doc["metadata"]["name"] == "registry-pull")
    assert registry["spec"]["data"][0]["remoteRef"] == {
        "key": "secret/data/hub/registry-pull", "property": "token"}


@pytest.mark.ci_external
def test_apf_engine_reaches_per_user_saw_policy(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], {
        "global": {"governance": {"engine": "apf"}}}))
    values = helm_values(app(docs, "saw-alice"))
    assert values["global"]["governance"]["engine"] == "apf"
    path = tmp_path / "saw-values.yaml"
    path.write_text(yaml.safe_dump(values))
    rendered = helm("template", "alice", str(SAW_CHART), "-n", "saw-alice",
                    "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                    "-f", str(path))
    assert rendered.returncode == 0, rendered.stderr
    policies = [doc for doc in yaml.safe_load_all(rendered.stdout) if doc
                and doc.get("kind") == "NetworkPolicy"
                and doc["metadata"]["name"] == "saw-vm"]
    # The pattern stages this off by default; select the first user here.
    assert not policies
    topology = yaml.safe_load((ROOT / "tests/fixtures/saw-network-topology.yaml").read_text())
    values["networkPolicy"]["enabled"] = True
    values["networkPolicy"].update(topology["networkPolicy"])
    values["cleanupApi"].update(topology["cleanupApi"])
    path.write_text(yaml.safe_dump(values))
    rendered = helm("template", "alice", str(SAW_CHART), "-n", "saw-alice",
                    "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                    "-f", str(path))
    assert rendered.returncode == 0, rendered.stderr
    vm_policy = next(doc for doc in yaml.safe_load_all(rendered.stdout) if doc
                     and doc.get("kind") == "NetworkPolicy"
                     and doc["metadata"]["name"] == "saw-vm")
    assert any(peer.get("podSelector", {}).get("matchLabels") == {
        "app.kubernetes.io/name": "apf",
        "app.kubernetes.io/instance": "governance-interceptor"}
        for rule in vm_policy["spec"]["egress"] for peer in rule["to"])


@pytest.mark.ci_external
def test_empty_global_values_are_left_out(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], extra={
        "global": {"originURL": "", "repoURL": "https://example.com/repo.git",
                   "targetRevision": "main", "clusterDomain": "example.com",
                   "vpArgoNamespace": "gitops-ns"}}))
    values = helm_values(app(docs, "saw-alice"))
    assert "originURL" not in values["global"]
    assert values["global"]["clusterDomain"] == "example.com"
    assert app(docs, "saw-alice")["metadata"]["namespace"] == "gitops-ns"
    namespace = by_kind(docs, "Namespace")[0]
    assert namespace["metadata"]["labels"]["argocd.argoproj.io/managed-by"] == "gitops-ns"


@pytest.mark.ci_external
def test_demo_harness_turns_on_allow_driver_config(tmp_path):
    docs = docs_from(render_file(tmp_path, [{"name": "alice", "harnessEnabled": True}]))
    assert helm_values(app(docs, "saw-alice-bom")) == {
        "profiles": ["data-science"], "harnessEnabled": True,
        "imageOverrides": {},
    }
    assert helm_values(app(docs, "saw-alice"))["allowDriverConfig"] is True


@pytest.mark.ci_external
def test_demo_harness_off_leaves_allow_driver_config_unset(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE]))
    assert "allowDriverConfig" not in helm_values(app(docs, "saw-alice"))


@pytest.mark.ci_external
def test_a_user_can_override_allow_driver_config_off(tmp_path):
    user = {"name": "alice", "harnessEnabled": True, "values": {"allowDriverConfig": False}}
    docs = docs_from(render_file(tmp_path, [user]))
    assert helm_values(app(docs, "saw-alice"))["allowDriverConfig"] is False


@pytest.mark.ci_external
def test_prune_on_remove_adds_the_foreground_finalizer(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], extra={"pruneOnRemove": True}))
    for application in by_kind(docs, "Application"):
        assert application["metadata"]["finalizers"] == [FINALIZER]
    namespace = by_kind(docs, "Namespace")[0]
    assert "argocd.argoproj.io/sync-options" not in namespace["metadata"]["annotations"]


@pytest.mark.ci_external
def test_prune_on_remove_can_be_set_per_user(tmp_path):
    """Set it on the one entry about to be removed, not for everyone: while it
    is on, deleting the apps (or the saw-users app) deletes that user's VM."""
    docs = docs_from(render_file(tmp_path, [ALICE, {"name": "bob", "pruneOnRemove": True}]))
    for name in ("saw-bob", "saw-bob-bom", "saw-bob-secrets"):
        assert app(docs, name)["metadata"]["finalizers"] == [FINALIZER]
    for name in ("saw-alice", "saw-alice-bom", "saw-alice-secrets"):
        assert "finalizers" not in app(docs, name)["metadata"]
    namespaces = {d["metadata"]["name"]: d["metadata"]["annotations"] for d in by_kind(docs, "Namespace")}
    assert "argocd.argoproj.io/sync-options" not in namespaces["saw-bob"]
    assert namespaces["saw-alice"]["argocd.argoproj.io/sync-options"] == "Prune=false"


@pytest.mark.ci_external
def test_the_vm_cleanup_hook_follows_prune_on_remove(tmp_path):
    """Found live: Argo CD runs openshell-saw's Helm pre-delete hook when the
    Application is deleted, so without this a removed user lost their VM even
    with pruneOnRemove false."""
    docs = docs_from(render_file(tmp_path, [ALICE, {"name": "bob", "pruneOnRemove": True}]))
    assert helm_values(app(docs, "saw-alice"))["cleanupOnDelete"] is False
    assert helm_values(app(docs, "saw-bob"))["cleanupOnDelete"] is True


@pytest.mark.ci_external
def test_a_user_can_opt_out_of_the_chart_wide_prune(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, {"name": "bob", "pruneOnRemove": False}],
                                 extra={"pruneOnRemove": True}))
    assert app(docs, "saw-alice")["metadata"]["finalizers"] == [FINALIZER]
    assert "finalizers" not in app(docs, "saw-bob")["metadata"]


@pytest.mark.ci_external
def test_only_the_globals_openshell_saw_reads_are_passed(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], extra={
        "global": {"repoURL": "https://example.com/repo.git", "targetRevision": "main",
                   "vpArgoNamespace": "vp-gitops", "clusterDomain": "example.com",
                   "deletePattern": "no", "multiSourceSupport": True, "sshPublicKey": "ssh-ed25519 AAA",
                   "governance": {"engine": "apf"}}}))
    assert helm_values(app(docs, "saw-alice"))["global"] == {
        "clusterDomain": "example.com", "sshPublicKey": "ssh-ed25519 AAA",
        "governance": {"engine": "apf"}}


@pytest.mark.ci_external
@pytest.mark.parametrize("name,message", [
    ("Alice", "lowercase DNS label"),
    ("alice_bob", "lowercase DNS label"),
    ("-alice", "lowercase DNS label"),
    ("alice-", "lowercase DNS label"),
    ("", "lowercase DNS label"),
    ("a" * 20, "OpenShell allows 19"),
])
def test_bad_names_fail_at_render(tmp_path, name, message):
    result = render_file(tmp_path, [{"name": name}])
    assert result.returncode != 0, result.stdout
    assert message in result.stderr


@pytest.mark.ci_external
def test_duplicate_names_fail_at_render(tmp_path):
    result = render_file(tmp_path, [{"name": "alice"}, {"name": "alice"}])
    assert result.returncode != 0, result.stdout
    assert 'duplicate user name "alice"' in result.stderr


@pytest.mark.ci_external
def test_nineteen_character_name_is_accepted(tmp_path):
    """The user name is the VM name, as with make openshell-saw-create."""
    name = "a" * 19
    route = f"{name}-dashboard-saw-{name}"
    assert len(route) == 53 and len(route) <= 63
    docs = docs_from(render_file(tmp_path, [{"name": name}]))
    assert app(docs, f"saw-{name}")["spec"]["source"]["helm"]["releaseName"] == name


@pytest.mark.ci_external
def test_shipped_override_renders_alice(tmp_path):
    result = helm("template", "saw-users", str(CHART), "-f", str(ROOT / "overrides" / "saw-users-demo.yaml"))
    docs = docs_from(result)
    assert [doc["metadata"]["name"] for doc in by_kind(docs, "Namespace")] == ["saw-alice"]
    assert helm_values(app(docs, "saw-alice-bom")) == {
        "profiles": ["data-science"], "imageOverrides": {}}


@pytest.mark.ci_external
def test_owner_resolution_writes_only_a_dedicated_input():
    result = helm("template", "saw-users", str(CHART), "-f", str(ROOT / "overrides" / "saw-users-demo.yaml"),
                  "--set", "ownerResolution.enabled=true")
    docs = docs_from(result)
    config = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "saw-owner-subject")
    assert "data" not in config
    role = next(d for d in docs if d["kind"] == "Role" and d["metadata"]["name"] == "saw-owner-resolver")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["configmaps"],
                              "resourceNames": ["saw-owner-subject"], "verbs": ["get", "patch"]}]
    saw_values = helm_values(app(docs, "saw-alice"))
    assert saw_values["accessControl"]["owner"] == "alice"
    assert saw_values["accessControl"]["ownerSubjectSource"] == "resolved"


@pytest.mark.ci_external
def test_missing_repo_url_fails(tmp_path):
    result = render_file(tmp_path, [ALICE], extra={
        "global": {"repoURL": "", "targetRevision": "main", "vpArgoNamespace": "vp-gitops"}})
    assert result.returncode != 0
    assert "global.repoURL is required" in result.stderr


def validate_rendered_user(tmp_path, docs, secrets):
    """Mount both child charts and only the supplied Secrets as /run/saw."""
    values_file = tmp_path / "alice-values.yaml"
    application = app(docs, "saw-alice")
    values_file.write_text(application["spec"]["source"]["helm"]["values"])
    rendered = helm("template", application["spec"]["source"]["helm"]["releaseName"],
                    str(SAW_CHART), "--namespace", "saw-alice",
                    "-f", str(values_file))
    assert rendered.returncode == 0, rendered.stderr
    saw_docs = [doc for doc in yaml.safe_load_all(rendered.stdout) if doc]
    installer = next(doc for doc in saw_docs if doc["kind"] == "ConfigMap"
                     and doc["metadata"]["name"] == "alice-installer")
    bom_values_file = tmp_path / "bom-values.yaml"
    bom_values_file.write_text(app(docs, "saw-alice-bom")["spec"]["source"]["helm"]["values"])
    bom = helm("template", "saw-alice-bom", str(BOM_CHART), "--namespace", "saw-alice",
               "-f", str(bom_values_file))
    assert bom.returncode == 0, bom.stderr
    [profile_cm] = [doc for doc in yaml.safe_load_all(bom.stdout) if doc]

    run_saw = tmp_path / "run-saw"
    for key, value in installer["data"].items():
        (run_saw / "installer").mkdir(parents=True, exist_ok=True)
        (run_saw / "installer" / key).write_text(value)
    for key, value in profile_cm["data"].items():
        (run_saw / "profiles").mkdir(exist_ok=True)
        (run_saw / "profiles" / key).write_text(value)
    for secret, data in secrets.items():
        (run_saw / "secrets" / secret).mkdir(parents=True)
        for key, value in data.items():
            (run_saw / "secrets" / secret / key).write_text(value)
    result = subprocess.run([sys.executable, str(run_saw / "installer" / "apply_bom.py"),
                             "validate", "--inputs", str(run_saw)], capture_output=True, text=True)
    return result, installer


def test_rendered_machine_values_validate_in_the_shipped_installer(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, BOB]))
    result, installer = validate_rendered_user(tmp_path, docs, {
        "inference": {"provider": "build"},
        "web-search": {"provider": "brave"},
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "inputs are valid" in result.stdout
    assert "2 workspace(s) ['cuda-dev', 'default']" in result.stdout
    assert "3 credential(s)" in result.stdout
    config = json.loads(installer["data"]["config.json"])
    assert config["vmName"] == "alice"
    assert config["ownerSubject"] == ""
    assert {(b["name"], b["key"]) for b in config["credentialProxy"]["secrets"]} == {
        ("inference", "api_key"), ("web-search", "api_key")}


@pytest.mark.ci_external
@pytest.mark.parametrize("global_enabled,user_enabled,enabled", [
    (False, None, False),
    ("false", None, False),
    (True, False, False),
    (True, "false", False),
    (False, True, True),
    ("false", "true", True),
])
@pytest.mark.parametrize("profile", ["data-science", "unknown-profile"])
def test_web_search_switch_controls_all_child_apps(
    tmp_path, global_enabled, user_enabled, enabled, profile,
):
    user = {"name": "alice", "profiles": [profile]}
    if user_enabled is not None:
        user["webSearch"] = {"enabled": user_enabled}
    docs = docs_from(render_file(tmp_path, [user], {
        "global": {"webSearch": {"enabled": global_enabled}},
    }))
    assert helm_values(app(docs, "saw-alice-secrets"))["secrets"] == \
        (["inference", "web-search"] if enabled else ["inference"])
    assert helm_values(app(docs, "saw-alice"))["additionalProviderSecrets"] == \
        (["web-search"] if enabled else [])
    machine = helm_values(app(docs, "saw-alice"))
    child_values = tmp_path / "machine.yaml"
    child_values.write_text(yaml.safe_dump(machine))
    child_docs = docs_from(helm("template", "alice", str(SAW_CHART), "-f", str(child_values)))
    installer = next(d for d in child_docs if d["kind"] == "ConfigMap"
                     and d["metadata"]["name"] == "alice-installer")
    proxy = json.loads(installer["data"]["config.json"])["credentialProxy"]
    assert [b["name"] for b in proxy["secrets"]] == \
        (["inference", "web-search"] if enabled else ["inference"])
    if profile == "data-science":
        inference = next(b for b in proxy["secrets"] if b["name"] == "inference")
        assert "build" in inference["providers"]
    assert helm_values(app(docs, "saw-alice-bom")) == {
        "profiles": [profile], **({} if enabled else {"webSearch": {"enabled": False}}),
        "imageOverrides": {},
    }


def test_web_search_off_validates_without_a_web_search_secret(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], {
        "global": {"webSearch": {"enabled": False}},
    }))
    result, installer = validate_rendered_user(tmp_path, docs, {
        "inference": {"provider": "build"},
    })
    assert [b["name"] for b in json.loads(installer["data"]["config.json"])["credentialProxy"]["secrets"]] == ["inference"]
    assert result.returncode == 0, result.stdout + result.stderr
    assert "inputs are valid" in result.stdout
    assert "2 credential(s)" in result.stdout


@pytest.mark.ci_external
@pytest.mark.parametrize("enabled", [False, True])
def test_pattern_override_preserves_the_boolean_install_knob(tmp_path, enabled):
    """Reproduce clustergroup 0.9's parameter handoff offline.

    The operator writes extraParametersNested values as unquoted YAML; the
    chart uses printf %s on those booleans, then applies the app's overrides
    with tpl/toString. The last parameter of a given name wins in Argo/Helm.
    """
    bridge = tmp_path / "clustergroup-bridge"
    (bridge / "templates").mkdir(parents=True)
    (bridge / "Chart.yaml").write_text("apiVersion: v2\nname: bridge\nversion: 0.0.0\n")
    (bridge / "templates" / "parameters.yaml").write_text('''parameters:
{{- range $name, $value := .Values.extraParametersNested }}
  - name: {{ $name }}
    value: {{ printf "%s" $value | quote }}
{{- end }}
{{- range (index .Values.clusterGroup.applications "saw-users").overrides }}
  - name: {{ .name }}
    value: {{ tpl (toString .value) $ | quote }}
    forceString: {{ .forceString | default false }}
{{- end }}
''')
    flags = tmp_path / "flags.yaml"
    flags.write_text(yaml.safe_dump({
        "global": {"webSearch": {"enabled": enabled}},
        "extraParametersNested": {"global.webSearch.enabled": enabled},
    }))
    result = helm("template", "bridge", str(bridge),
                  "-f", str(ROOT / "values-global.yaml"),
                  "-f", str(ROOT / "values-prod.yaml"), "-f", str(flags))
    assert result.returncode == 0, result.stderr
    parameters = [p for p in yaml.safe_load(result.stdout)["parameters"]
                  if p["name"] == "global.webSearch.enabled"]
    assert parameters[0]["value"] == f"%!s(bool={str(enabled).lower()})"
    assert parameters[-1] == {"name": "global.webSearch.enabled",
                               "value": str(enabled).lower(), "forceString": True}
    docs = docs_from(render_file(tmp_path, [ALICE], {
        "global": {"webSearch": {"enabled": parameters[-1]["value"]}},
    }))
    assert ("web-search" in helm_values(app(docs, "saw-alice-secrets"))["secrets"]) == enabled


def test_web_search_on_without_its_secret_reproduces_the_installer_failure(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE]))
    result, _ = validate_rendered_user(tmp_path, docs, {
        "inference": {"provider": "build"},
    })
    assert result.returncode != 0
    assert "metadata Secret 'web-search-meta' is not mounted" in \
        result.stdout + result.stderr



# -- profile catalog: sandbox UI routes and the Secrets to sync ----------------

def test_the_profile_catalog_is_current():
    """files/profile-catalog.json is generated from charts/saw-bom/profiles."""
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "saw-profile-catalog.py"), "--check"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.ci_external
def test_ui_routes_come_from_the_profiles(tmp_path):
    """data-science flags the default workspace's notebook and the cuda-dev
    workspace's NemoClaw sandbox (ui.route: true)."""
    values = helm_values(app(docs_from(render_file(tmp_path, [ALICE])), "saw-alice"))
    assert values["sandboxUi"] == [{"workspace": "cuda-dev", "sandbox": "cuda-sandbox",
                                    "proxyPort": 4201, "forwardPort": 14201},
                                   {"workspace": "default", "sandbox": "notebook",
                                    "proxyPort": 4202, "forwardPort": 14202}]


@pytest.mark.ci_external
def test_ui_routes_are_sorted_and_numbered(tmp_path):
    user = {"name": "carol", "sandboxUi": [{"workspace": "zeta", "sandbox": "b"},
                                            {"workspace": "alpha", "sandbox": "a"}]}
    values = helm_values(app(docs_from(render_file(tmp_path, [user])), "saw-carol"))
    assert [(e["workspace"], e["proxyPort"], e["forwardPort"]) for e in values["sandboxUi"]] == [
        ("alpha", 4201, 14201), ("zeta", 4202, 14202)]


@pytest.mark.ci_external
def test_too_many_ui_routes_fail_the_render(tmp_path):
    user = {"name": "carol", "sandboxUi": [{"workspace": "w", "sandbox": f"s{i}"} for i in range(9)]}
    result = render_file(tmp_path, [user])
    assert result.returncode != 0 and "at most 8" in result.stderr


@pytest.mark.ci_external
def test_only_the_profiles_secrets_are_synced_and_mounted(tmp_path):
    """custom-inference reads inference (with url and model) and web-search."""
    user = {"name": "dave", "profiles": ["custom-inference"]}
    docs = docs_from(render_file(tmp_path, [user]))
    assert helm_values(app(docs, "saw-dave-secrets"))["secrets"] == ["inference", "web-search"]
    vm = helm_values(app(docs, "saw-dave"))
    assert vm["inference"]["secretName"] == "inference"
    assert vm["additionalProviderSecrets"] == ["web-search"]
    assert vm["sandboxUi"] == []


@pytest.mark.ci_external
def test_ci_nvidia_profile_uses_only_the_available_key(tmp_path):
    user = {"name": "ciowner", "profiles": ["ci-nvidia"]}
    docs = docs_from(render_file(tmp_path, [user]))
    assert helm_values(app(docs, "saw-ciowner-secrets"))["secrets"] == ["inference"]
    vm = helm_values(app(docs, "saw-ciowner"))
    assert vm["inference"]["secretName"] == "inference"
    assert vm["additionalProviderSecrets"] == []
    assert helm_values(app(docs, "saw-ciowner-bom"))["profiles"] == ["ci-nvidia"]


@pytest.mark.ci_external
def test_namespace_labels_are_added(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], {"namespaceLabels": {"saw.redhat.com/portal": "true"}}))
    [ns] = [d for d in docs if d["kind"] == "Namespace"]
    assert ns["metadata"]["labels"]["saw.redhat.com/portal"] == "true"
    assert ns["metadata"]["labels"]["openshell.pattern/saw"] == "true"


@pytest.mark.ci_external
@pytest.mark.parametrize("name", ["alice-bom", "alice-secrets"])
def test_names_that_would_take_another_users_apps_are_refused(tmp_path, name):
    """saw-<u>-bom is user u's BOM app, and the VM app of a user named u-bom."""
    result = render_file(tmp_path, [{"name": name}])
    assert result.returncode != 0 and "ends in -bom or -secrets" in result.stderr


@pytest.mark.ci_external
def test_a_user_can_opt_into_the_demo_harness(tmp_path):
    docs = docs_from(render_file(tmp_path, [dict(ALICE, harnessEnabled=True)]))
    assert helm_values(app(docs, "saw-alice-bom")) == {
        "profiles": ["data-science"], "harnessEnabled": True,
        "imageOverrides": {}}


@pytest.mark.ci_external
def test_the_personal_assistant_profile_turns_its_harness_on(tmp_path):
    docs = docs_from(render_file(tmp_path, [{'name':'carol','profiles':['personal-assistant']}]))
    assert helm_values(app(docs,'saw-carol-bom'))['harnessEnabled'] is True
    machine = helm_values(app(docs,'saw-carol'))
    assert machine['allowDriverConfig'] is True
    bindings = machine['credentialProxy']['secrets']
    assert {(b['name'],b['key']) for b in bindings} == {('gmail','access_token'),('slack','bot_token'),('inference','api_key')}
    assert next(b for b in bindings if b['name']=='gmail')['refresh'] is True
    metadata = helm_values(app(docs,'saw-carol-secrets'))['metaKeys']
    assert metadata['gmail'] == ['provider'] and metadata['slack'] == ['provider']
