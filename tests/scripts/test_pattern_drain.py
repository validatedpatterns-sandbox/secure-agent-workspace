"""Regression coverage for the destructive part of the documented uninstall."""
import copy
import importlib.util
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def drain():
    path = Path(__file__).resolve().parents[2] / "scripts/pattern-drain-applications.py"
    spec = importlib.util.spec_from_file_location("pattern_drain", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def leaf():
    return {"metadata": {"uid": "old-leaf", "resourceVersion": "11", "name": "openshell-rhdh",
                         "namespace": "vp-gitops", "finalizers": ["resources-finalizer.argocd.argoproj.io/foreground"],
                         "labels": {"validatedpatterns.io/pattern": "secure-agent-workspace"},
                         "annotations": {"argocd.argoproj.io/tracking-id":
                                         "secure-agent-workspace-prod:argoproj.io/Application:vp-gitops/openshell-rhdh"}},
            "spec": {"destination": {"name": "in-cluster"}, "source": {"path": "charts/openshell-rhdh"}, "syncPolicy": {"automated": {}}},
            "operation": {"sync": {"revision": "test"}}, "status": {"operationState": {"phase": "Running"}}}


@pytest.mark.parametrize("change", [
    lambda m: m.update(uid="replacement"),
    lambda m: m["labels"].clear(),
    lambda m: m["annotations"].update({"argocd.argoproj.io/tracking-id": "other:argoproj.io/Application:vp-gitops/openshell-rhdh"}),
    lambda m: m.update(namespace="foreign"),
    lambda m: m["finalizers"].clear(),
])
def test_foreign_or_replaced_leaf_fails_closed(drain, change):
    item = leaf()
    change(item["metadata"])
    with pytest.raises(RuntimeError, match="unverified or replaced"):
        drain.validate_child(item, "secure-agent-workspace-prod", "openshell-rhdh", "old-leaf")


def test_only_a_local_foreground_leaf_can_be_drained(drain):
    item = leaf()
    drain.validate_child(item, "secure-agent-workspace-prod", "openshell-rhdh", "old-leaf")
    item["spec"]["destination"] = {"name": "other-cluster"}
    with pytest.raises(RuntimeError, match="unverified or replaced"):
        drain.validate_child(item, "secure-agent-workspace-prod", "openshell-rhdh", "old-leaf")


def test_prune_requires_parent_to_release_the_exact_namespaced_application(drain):
    resource = {"group": "argoproj.io", "kind": "Application", "namespace": "vp-gitops", "name": "openshell-rhdh"}
    parent = {"status": {"resources": [resource]}}
    assert not drain.released(parent, "openshell-rhdh")
    resource["requiresPruning"] = True
    assert drain.released(parent, "openshell-rhdh")
    resource["namespace"] = "foreign"
    assert not drain.released(parent, "openshell-rhdh")


def test_termination_precedes_preconditioned_foreground_delete(drain, monkeypatch):
    item = leaf()
    writes = []
    monkeypatch.setattr(drain, "oc", lambda *args, body: writes.append((args, copy.deepcopy(body))))
    drain.drain_child(item)
    assert writes[-1][1][-1] == {"op": "remove", "path": "/spec/syncPolicy/automated"}
    item["spec"]["syncPolicy"].clear()
    drain.drain_child(item)
    patch = writes[-1][1]
    assert patch[:2] == [{"op": "test", "path": "/metadata/uid", "value": "old-leaf"},
                         {"op": "test", "path": "/metadata/resourceVersion", "value": "11"}]
    assert patch[-1] == {"op": "replace", "path": "/status/operationState/phase", "value": "Terminating"}
    item["status"]["operationState"]["phase"] = "Terminating"
    drain.drain_child(item)
    assert len(writes) == 2
    item.pop("operation")
    drain.drain_child(item)
    args, body = writes[-1]
    assert args[:2] == ("delete", "--raw") and args[2].endswith("/namespaces/vp-gitops/applications/openshell-rhdh")
    assert body["preconditions"] == {"uid": "old-leaf", "resourceVersion": "11"}
    assert body["propagationPolicy"] == "Foreground"


def test_disable_is_guarded_by_pattern_uid_and_entire_spec(drain, monkeypatch):
    pattern = {"metadata": {"uid": "pattern-uid", "resourceVersion": "3",
                            "namespace": "patterns-operator", "name": drain.PATTERN},
               "spec": {"clusterGroupName": "prod", "extraParameters": []}}
    writes = []
    monkeypatch.setattr(drain, "oc", lambda *args, body: writes.append(body))
    drain.disable_consumers(pattern, ["saw-users"])
    assert writes[0][:2] == [
        {"op": "test", "path": "/metadata/uid", "value": "pattern-uid"},
        {"op": "test", "path": "/spec", "value": pattern["spec"]}]
    assert writes[0][2]["path"] == "/spec/extraParameters/-"


def test_disable_is_idempotent_and_preserves_other_site_overrides(drain, monkeypatch):
    key = "clusterGroup.applications.openshell-rhdh.disabled"
    pattern = {"spec": {"extraParameters": [{"name": "unrelated", "value": "keep"},
                                             {"name": key, "value": "false"}]}}
    patches = []
    monkeypatch.setattr(drain, "patch", lambda kind, obj, edits: patches.append(edits))
    drain.disable_consumers(pattern, ["openshell-rhdh"])
    assert patches == [[{"op": "replace", "path": "/spec/extraParameters/1/value", "value": "true"}]]
    pattern["spec"]["extraParameters"][1]["value"] = "true"
    drain.disable_consumers(pattern, ["openshell-rhdh"])
    assert len(patches) == 1



def test_documented_target_drains_writers_before_vm_cleanup():
    root = Path(__file__).resolve().parents[2]
    commands = subprocess.check_output(["make", "-n", "pre-uninstall"], cwd=root, text=True)
    assert commands.index("pattern-drain-applications.py") < commands.index("pattern-pre-uninstall.sh")
