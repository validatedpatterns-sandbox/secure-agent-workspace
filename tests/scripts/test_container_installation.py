"""Standalone entry point: public inputs, ownership and shared lifecycle."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("container_installation", ROOT / "scripts/container-workspace.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


def inputs():
    site = yaml.safe_load((ROOT / "tests/fixtures/container-site.yaml").read_text())["portal"]["containerSites"]["alice"]
    user = dict(name="alice", registration="a"*16, installationID="22222222-2222-4222-8222-222222222222",
                ownerSubject=site["subject"], profiles=["data-science"], intentGeneration=1,
                vaultPrefix="secret/data/hub/saw-alice/"+"a"*16, pruneOnRemove=True,
                values={"deployment": {"mode": "container"}})
    return {"users": [user, {"name": "bob"}], "containerSites": {"alice": site},
            "ownerResolution": {"enabled": True},
            "global": {"vpArgoNamespace": "vp-gitops", "clusterDomain": "cluster.example.test"}}


def test_select_isolates_container_without_modifying_vm_or_input():
    values = inputs()
    before = copy.deepcopy(values)
    selected, user = install.select(values, "alice")
    assert values == before
    assert selected["users"] == [user]
    assert selected["ownerResolution"]["enabled"] is False
    assert selected["projection"]["enabled"] is True


@pytest.mark.parametrize("fault", ["missing", "duplicate", "mode", "subject", "registration", "generation", "cleanup"])
def test_invalid_input_cannot_start_installation(fault):
    values = inputs()
    user = values["users"][0]
    if fault == "missing": values["users"] = []
    if fault == "duplicate": values["users"].append(copy.deepcopy(user))
    if fault == "mode": user["values"]["deployment"]["mode"] = "vm"
    if fault == "subject": user["ownerSubject"] = "33333333-3333-4333-8333-333333333333"
    if fault == "registration": user["registration"] = "unbound"
    if fault == "generation": user["intentGeneration"] = True
    if fault == "cleanup": user["pruneOnRemove"] = False
    with pytest.raises(install.InstallError): install.select(values, "alice")


@pytest.mark.parametrize("field", ["registration", "installationID", "ownerSubject", "name"])
def test_update_cannot_adopt_another_registration(field):
    values, user = install.select(inputs(), "alice")
    existing = copy.deepcopy(values)
    existing["users"][0][field] = "different"
    with pytest.raises(install.InstallError, match="refusing adoption"):
        install.check_existing(existing, user)
    install.check_existing(values, user)


def test_preflight_fails_without_required_api_and_never_installs_dependency(monkeypatch):
    calls = []
    def get(kind, name, namespace=None):
        calls.append((kind, name))
        return None if name == "sandboxes.agents.x-k8s.io" else {"metadata": {}}
    monkeypatch.setattr(install, "get", get)
    with pytest.raises(install.InstallError, match="sandboxes.agents.x-k8s.io"):
        install.preflight(inputs(), "workspaces")
    assert calls and all(kind == "crd" for kind, name in calls)


def test_namespace_create_is_explicit_and_never_patches_existing_namespace(monkeypatch):
    calls = []
    monkeypatch.setattr(install, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    install.ensure_namespace({}, "workspaces", "vp-gitops")
    assert calls[0][0] == ("oc", "create", "-f", "-")
    body = json.loads(calls[0][1]["input_text"])
    assert body["metadata"]["labels"]["argocd.argoproj.io/managed-by"] == "vp-gitops"
    install.ensure_namespace(body, "workspaces", "vp-gitops")
    assert len(calls) == 1


def test_status_uses_shared_readiness_and_never_reads_secrets(monkeypatch):
    values, user = install.select(inputs(), "alice")
    observations = []
    monkeypatch.setattr(install, "get", lambda *args: observations.append(args))
    def check(read, owner, site, argo, domain, ping, catalog):
        assert owner == user and site["subject"] == user["ownerSubject"]
        assert argo == "vp-gitops" and domain == "cluster.example.test"
        read("/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/saw-alice")
        read("/api/v1/namespaces/saw-alice/configmaps/saw-runtime-status")
        assert callable(ping) and "data-science" in catalog
        return {"ready": False}
    monkeypatch.setattr(install.workspace, "container_status", check)
    assert install.status(user, values) == {"ready": False}
    assert observations == [("application", "saw-alice", "vp-gitops"),
                            ("configmap", "saw-runtime-status", "saw-alice")]


@pytest.mark.parametrize("action", ["apply", "status", "delete"])
def test_commands_use_only_owned_helm_release_and_public_observations(action, monkeypatch, tmp_path):
    values, user = install.select(inputs(), "alice")
    filename = tmp_path / "values.yaml"
    filename.write_text(yaml.safe_dump(values))
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("helm", "list"): return json.dumps([{"name": "workspace-alice"}])
        if args[:3] == ("helm", "get", "values"): return json.dumps(values)
        return ""
    monkeypatch.setattr(install, "run", run)
    monkeypatch.setattr(install.shutil, "which", lambda _: "/tool")
    def get(kind, name, namespace=None):
        if kind == "ingress.config.openshift.io": return {"spec": {"domain": "apps.cluster.example.test"}}
        return {"metadata": {"labels": {"saw.redhat.com/runtime-owner": user["installationID"]}}}
    monkeypatch.setattr(install, "get", get)
    monkeypatch.setattr(install, "status", lambda *_: {"ready": True})
    monkeypatch.setattr(install, "preflight", lambda *_: ({"metadata": {}}, "vp-gitops"))
    monkeypatch.setattr(sys, "argv", ["container-workspace.py", action, "--name", "alice", "--values", str(filename)])
    assert install.main() == 0
    writes = [args for args in calls if args[:2] in (("helm", "upgrade"), ("helm", "uninstall"))]
    assert len(writes) == (action != "status")
    if action != "status": assert "workspace-alice" in writes[0]
    if action == "delete": assert writes[0][-5:] == ("--cascade", "foreground", "--wait", "--timeout", "5m")
    assert not any("secret" in args or "patch" in args or "delete" in args for args in calls)


@pytest.mark.parametrize(("error", "expected"), [
    ("Unable to connect to the server: dial tcp: lookup example: no such host", "DNS lookup failed"),
    ("Error from server (Forbidden): access denied", "HTTP 403"),
    ("unexpected response", "oc operation failed"),
])
def test_oc_diagnostic_does_not_echo_stderr(monkeypatch, error, expected):
    def failed(*args, **kwargs):
        return install.subprocess.CompletedProcess(args, 1, "", error + " private-fixture-value")
    monkeypatch.setattr(install.subprocess, "run", failed)
    with pytest.raises(install.InstallError, match=expected) as exc:
        install.run("oc", "get", "namespace", "test")
    assert "private-fixture-value" not in str(exc.value)


def test_make_applies_checked_overlay_before_render_and_fails_before_mutation_on_drift(monkeypatch, tmp_path):
    values, user = install.select(inputs(), "alice")
    values["containerSites"]["alice"]["automaticEnrollment"]["enabled"] = False
    base = tmp_path / "site.yaml"
    overlay = tmp_path / "net.yaml"
    base.write_text(yaml.safe_dump(values))
    network = install.container_topology
    site = values["containerSites"]["alice"]
    ip = ["10.0.0.7"]
    def discover(config, probe, container):
        assert probe == "ops/probe" and config["containerSites"]["alice"] == site
        result = {"projection": {"egress": []}, "containerSites": {"alice": {}}}
        o = result["containerSites"]["alice"]
        for path in (network.GATEWAY + ("oidc", "issuerUrl"), network.RELAY + ("issuer",)):
            network.put(o, path, "https://issuer.example")
        for path in (network.BOOTSTRAP, network.RELAY + ("egress",), network.GATEWAY + ("kubernetes", "network", "gatewayEgress")):
            network.put(o, path, [network.host_rule(ip[0], 443)])
        return result

    monkeypatch.setenv("SAW_TOPOLOGY_OVERLAY", str(overlay))
    monkeypatch.setenv("SAW_TOPOLOGY_PROBE", "ops/probe")
    monkeypatch.setattr(network, "container_overlay", discover)
    monkeypatch.setattr(sys, "argv", ["container-workspace.py", "apply", "--name", "alice", "--values", str(base)])
    monkeypatch.setattr(install.shutil, "which", lambda _: "/tool")
    monkeypatch.setattr(install, "get", lambda kind, *a: {"spec":{"domain":"apps.cluster.example.test"}}
                        if kind == "ingress.config.openshift.io" else None)
    monkeypatch.setattr(install, "preflight", lambda *args: ({}, "vp-gitops"))
    writes = []
    monkeypatch.setattr(install, "ensure_namespace", lambda *args: writes.append("namespace"))
    def run(*args, **kwargs):
        if args[:2] == ("helm", "list"):
            return "[]"
        if args[:2] in (("helm", "template"), ("helm", "upgrade")):
            rendered_values = json.loads(Path(args[args.index("-f")+1]).read_text())
            assert network.path_value(rendered_values["containerSites"]["alice"], network.RELAY + ("egress",)) == [
                network.host_rule("10.0.0.7", 443)]
        if args[:2] == ("helm", "upgrade"):
            writes.append("helm")
        return ""
    monkeypatch.setattr(install, "run", run)
    assert install.main() == 0 and writes == ["namespace", "helm"]
    ip[0] = "10.0.0.8"
    writes.clear()
    with pytest.raises(SystemExit):
        install.main()
    assert not writes
