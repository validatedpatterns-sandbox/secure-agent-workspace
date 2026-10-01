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
    "values": {"dashboard": {"insecureSkipIssuerTlsVerify": False}},
}


def helm(*args):
    return subprocess.run([HELM, *args], capture_output=True, text=True)


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
        assert application["spec"]["syncPolicy"] == {"automated": {"selfHeal": True},
                                                      "retry": {"limit": 20}}
        assert "ignoreMissingValueFiles" not in application["spec"]["source"]["helm"]
        assert "syncOptions" not in application["spec"]["syncPolicy"]


def test_waves_release_names_and_value_overrides(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, BOB]))

    secrets = app(docs, "saw-alice-secrets")
    assert secrets["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "0"
    assert secrets["spec"]["source"]["path"] == "charts/pattern-secrets"
    assert secrets["spec"]["source"]["helm"]["releaseName"] == "saw-alice-secrets"
    assert secrets["spec"]["destination"]["namespace"] == "saw-alice"
    assert helm_values(secrets) == {"vaultPrefix": "secret/data/hub"}

    bob_secrets = helm_values(app(docs, "saw-bob-secrets"))
    assert bob_secrets == {"vaultPrefix": "secret/data/hub/saw-bob"}

    bom = app(docs, "saw-alice-bom")
    assert bom["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "0"
    assert bom["spec"]["source"]["path"] == "charts/saw-bom"
    assert helm_values(bom) == {"profiles": ["data-science"]}
    assert helm_values(app(docs, "saw-bob-bom")) == {"profiles": ["custom"]}

    alice = app(docs, "saw-alice")
    assert alice["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "1"
    assert alice["spec"]["source"]["path"] == "charts/openshell-saw"
    assert alice["spec"]["source"]["helm"]["releaseName"] == "alice"
    assert alice["spec"]["source"]["repoURL"] == "https://example.com/secure-agent-workspace.git"
    assert alice["spec"]["source"]["targetRevision"] == "main"
    alice_values = helm_values(alice)
    assert alice_values["accessControl"] == {"owner": "alice", "ownerSubject": ""}
    assert alice_values["job"]["waitForSecrets"] is True
    assert alice_values["job"]["backoffLimit"] == 5
    assert alice_values["dashboard"]["insecureSkipIssuerTlsVerify"] is True
    assert alice_values["global"]["clusterDomain"] == "example.com"
    assert "originURL" not in alice_values["global"]
    assert "mtalvi" not in alice["spec"]["source"]["repoURL"]

    bob_values = helm_values(app(docs, "saw-bob"))
    assert bob_values["accessControl"] == {"owner": "bob", "ownerSubject": "3f2c-subject"}
    assert bob_values["dashboard"]["insecureSkipIssuerTlsVerify"] is False
    assert bob_values["job"]["waitForSecrets"] is True


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


def test_prune_on_remove_adds_the_foreground_finalizer(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], extra={"pruneOnRemove": True}))
    for application in by_kind(docs, "Application"):
        assert application["metadata"]["finalizers"] == [FINALIZER]
    namespace = by_kind(docs, "Namespace")[0]
    assert "argocd.argoproj.io/sync-options" not in namespace["metadata"]["annotations"]


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


def test_the_vm_cleanup_hook_follows_prune_on_remove(tmp_path):
    """Found live: Argo CD runs openshell-saw's Helm pre-delete hook when the
    Application is deleted, so without this a removed user lost their VM even
    with pruneOnRemove false."""
    docs = docs_from(render_file(tmp_path, [ALICE, {"name": "bob", "pruneOnRemove": True}]))
    assert helm_values(app(docs, "saw-alice"))["cleanupOnDelete"] is False
    assert helm_values(app(docs, "saw-bob"))["cleanupOnDelete"] is True


def test_a_user_can_opt_out_of_the_chart_wide_prune(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, {"name": "bob", "pruneOnRemove": False}],
                                 extra={"pruneOnRemove": True}))
    assert app(docs, "saw-alice")["metadata"]["finalizers"] == [FINALIZER]
    assert "finalizers" not in app(docs, "saw-bob")["metadata"]


def test_only_the_globals_openshell_saw_reads_are_passed(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE], extra={
        "global": {"repoURL": "https://example.com/repo.git", "targetRevision": "main",
                   "vpArgoNamespace": "vp-gitops", "clusterDomain": "example.com",
                   "deletePattern": "no", "multiSourceSupport": True, "sshPublicKey": "ssh-ed25519 AAA",
                   "governance": {"engine": "apf"}}}))
    assert helm_values(app(docs, "saw-alice"))["global"] == {
        "clusterDomain": "example.com", "sshPublicKey": "ssh-ed25519 AAA",
        "governance": {"engine": "apf"}}


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


def test_duplicate_names_fail_at_render(tmp_path):
    result = render_file(tmp_path, [{"name": "alice"}, {"name": "alice"}])
    assert result.returncode != 0, result.stdout
    assert 'duplicate user name "alice"' in result.stderr


def test_nineteen_character_name_is_accepted(tmp_path):
    """The user name is the VM name, as with make openshell-saw-create."""
    name = "a" * 19
    route = f"{name}-dashboard-saw-{name}"
    assert len(route) == 53 and len(route) <= 63
    docs = docs_from(render_file(tmp_path, [{"name": name}]))
    assert app(docs, f"saw-{name}")["spec"]["source"]["helm"]["releaseName"] == name


def test_shipped_override_renders_alice(tmp_path):
    result = helm("template", "saw-users", str(CHART), "-f", str(ROOT / "overrides" / "saw-users.yaml"))
    docs = docs_from(result)
    assert [doc["metadata"]["name"] for doc in by_kind(docs, "Namespace")] == ["saw-alice"]
    assert helm_values(app(docs, "saw-alice-bom")) == {"profiles": ["data-science"]}


def test_missing_repo_url_fails(tmp_path):
    result = render_file(tmp_path, [ALICE], extra={
        "global": {"repoURL": "", "targetRevision": "main", "vpArgoNamespace": "vp-gitops"}})
    assert result.returncode != 0
    assert "global.repoURL is required" in result.stderr


def test_rendered_machine_values_validate_in_the_shipped_installer(tmp_path):
    docs = docs_from(render_file(tmp_path, [ALICE, BOB]))
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
    bom = helm("template", "saw-alice-bom", str(BOM_CHART), "--namespace", "saw-alice")
    assert bom.returncode == 0, bom.stderr
    [profile_cm] = [doc for doc in yaml.safe_load_all(bom.stdout) if doc]

    run_saw = tmp_path / "run-saw"
    for key, value in installer["data"].items():
        (run_saw / "installer").mkdir(parents=True, exist_ok=True)
        (run_saw / "installer" / key).write_text(value)
    for key, value in profile_cm["data"].items():
        (run_saw / "profiles").mkdir(exist_ok=True)
        (run_saw / "profiles" / key).write_text(value)
    for secret, data in {"inference": {"api_key": "k1", "provider": "build"},
                         "web-search": {"api_key": "k2"}}.items():
        (run_saw / "secrets" / secret).mkdir(parents=True)
        for key, value in data.items():
            (run_saw / "secrets" / secret / key).write_text(value)
    result = subprocess.run([sys.executable, str(run_saw / "installer" / "apply_bom.py"),
                             "validate", "--inputs", str(run_saw)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "inputs are valid" in result.stdout
    assert "2 workspace(s) ['cuda-dev', 'default']" in result.stdout
    assert "3 credential(s)" in result.stdout
    config = json.loads(installer["data"]["config.json"])
    assert config["vmName"] == "alice"
    assert config["ownerSubject"] == ""
