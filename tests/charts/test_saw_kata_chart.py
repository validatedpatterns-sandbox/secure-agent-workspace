"""charts/saw-kata: the KataConfig is opt-in and never selects control-plane nodes."""
from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/saw-kata"


def render(*args):
    result = subprocess.run(["helm", "template", "saw-kata", str(CHART), *args], capture_output=True, text=True)
    return result, [d for d in yaml.safe_load_all(result.stdout or "") if d]


def test_off_by_default():
    result, docs = render()
    assert result.returncode == 0, result.stderr
    assert docs == []


def test_enabled_selects_plain_workers_only():
    result, docs = render("--set", "enabled=true")
    assert result.returncode == 0, result.stderr
    config, = [d for d in docs if d["kind"] == "KataConfig"]
    assert config["kind"] == "KataConfig" and config["spec"]["enablePeerPods"] is False
    # Eligibility needs NFD labels; without NFD an enabled check blocks the install.
    assert config["spec"]["checkNodeEligibility"] is False
    _, (checked, _runtime) = render("--set", "enabled=true", "--set", "checkNodeEligibility=true")
    assert checked["spec"]["checkNodeEligibility"] is True
    expressions = config["spec"]["kataConfigPoolSelector"]["matchExpressions"]
    assert {"key": "node-role.kubernetes.io/control-plane", "operator": "DoesNotExist"} in expressions
    assert {"key": "node-role.kubernetes.io/master", "operator": "DoesNotExist"} in expressions


def test_enabled_ships_an_attachable_copy_of_the_operator_class():
    result, docs = render("--set", "enabled=true")
    runtime, = [d for d in docs if d["kind"] == "RuntimeClass"]
    assert runtime["metadata"]["name"] == "saw-kata"
    # OpenShell refuses a class without this label; nobody labels it by hand.
    assert runtime["metadata"]["labels"] == {"openshell.ai/sandbox-attachable": "true"}
    assert runtime["handler"] == "kata"
    assert runtime["overhead"] == {"podFixed": {"cpu": "250m", "memory": "350Mi"}}
    assert runtime["scheduling"] == {"nodeSelector": {"node-role.kubernetes.io/kata-oc": ""}}


def test_the_class_must_stay_kata_and_placed():
    for override in (["--set", "runtimeClass.handler=runc"], ["--set-json", "runtimeClass.nodeSelector=null"]):
        result, _ = render("--set", "enabled=true", *override)
        assert result.returncode != 0


def test_an_empty_selector_is_refused():
    result, _ = render("--set", "enabled=true", "--set-json", "poolSelector=null")
    assert result.returncode != 0


def test_the_pattern_installs_the_operator_and_leaves_the_pool_off():
    values = yaml.safe_load((ROOT / "values-prod.yaml").read_text())["clusterGroup"]
    assert values["subscriptions"]["sandboxed-containers"]["name"] == "sandboxed-containers-operator"
    namespace = values["namespaces"]["openshift-sandboxed-containers-operator"]
    assert namespace["targetNamespaces"] == ["openshift-sandboxed-containers-operator"]
    app = values["applications"]["saw-kata"]
    assert app["path"] == "charts/saw-kata"
    # Enabling reboots nodes: a per-cluster choice, never the shared default.
    assert not [o for o in app.get("overrides", []) if o["name"] == "enabled"]
