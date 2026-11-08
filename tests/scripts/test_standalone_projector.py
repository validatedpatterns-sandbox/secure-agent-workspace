import copy
import importlib.util
import json
from pathlib import Path
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "charts/saw-users/files"


def load(name):
    spec = importlib.util.spec_from_file_location(name, FILES / (name+".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def projector(monkeypatch):
    monkeypatch.setitem(sys.modules, "workspace", load("workspace"))
    return load("projector")


def config():
    site = yaml.safe_load((ROOT/"tests/fixtures/container-site.yaml").read_text())["portal"]["containerSites"]["alice"]
    user = dict(name="alice", ownerSubject=site["subject"], registration="a"*16,
                installationID="22222222-2222-4222-8222-222222222222", profiles=["data-science"],
                values={"deployment": {"mode": "container"}}, pruneOnRemove=True,
                intentGeneration=1, vaultPrefix="secret/data/hub/saw-alice/"+"a"*16)
    return dict(users=[user], containerSites={"alice": site}, global_={})


def catalog():
    return json.loads((FILES/"profile-catalog.json").read_text())["profiles"]


def test_standalone_uses_exact_portal_projection_without_mutating_inputs(projector):
    cfg = config()
    before = copy.deepcopy(cfg)
    params, = projector.parameters(cfg, catalog(), lambda _: {})
    expected = projector.workspace.project_workspace(cfg["users"][0], {"global_": {}, "projection": {"enabled": False}, "ownerResolution": {"enabled": False}},
                                                       cfg["containerSites"]["alice"], catalog(), lambda _: {})
    assert json.loads(params["workspaceValues"]) == expected
    assert "values" not in params  # reserved by the ApplicationSet plugin protocol
    assert cfg == before
    assert set(expected["containerSites"]["alice"]["targets"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}


def test_standalone_uses_same_selected_revision_for_application_and_children(projector):
    cfg = config()
    cfg["global"] = {"repoURL": "https://example.com/repo.git", "targetRevision": "main"}
    cfg["workspaceRevisions"] = {"alice": "a"*40}
    params, = projector.parameters(cfg, catalog(), lambda _: {})
    values = json.loads(params["workspaceValues"])
    assert params["revision"] == values["global"]["targetRevision"] == "a"*40
    assert values["global"]["repoURL"] == cfg["global"]["repoURL"]
    cfg["workspaceRevisions"] = {}
    params, = projector.parameters(cfg, catalog(), lambda _: {})
    assert params["revision"] == "main"


@pytest.mark.parametrize("fault", ["missing-site", "duplicate", "unapproved", "wrong-mode", "broken-publication"])
def test_projection_failure_never_returns_an_empty_desired_set(projector, fault):
    cfg = config()
    read = lambda _: {}
    if fault == "missing-site": cfg["containerSites"] = {}
    if fault == "duplicate": cfg["users"].append(copy.deepcopy(cfg["users"][0]))
    if fault == "unapproved": cfg["users"][0]["profiles"] = ["missing"]
    if fault == "wrong-mode": cfg["users"][0]["values"]["deployment"]["mode"] = "vm"
    if fault == "broken-publication": read = lambda _: {"metadata": {}, "data": {"binding.json": "{}"}}
    with pytest.raises(projector.ProjectionError):
        projector.parameters(cfg, catalog(), read)


class MemoryApi:
    def __init__(self):
        self.objects = {}
        self.created = []
        for ns, group, kind, plural in [("workspaces", "apps/v1", "Deployment", "deployments"),
                                         ("gitops", "argoproj.io/v1alpha1", "ApplicationSet", "applicationsets")]:
            self.objects["/api/v1/namespaces/"+ns] = {"metadata": {"uid": ns+"-uid"}}
            self.objects[f"/apis/{group}/namespaces/{ns}/{plural}/projector"] = {
                "metadata": {"uid": kind+"-uid", "labels": {"saw.redhat.com/projector-owner": "installation"}}}

    def call(self, method, path, body=None):
        if method == "GET": return copy.deepcopy(self.objects.get(path))
        assert method == "POST" and path.endswith("/secrets")
        name = path+"/"+body["metadata"]["name"]
        assert name not in self.objects
        self.created.append(name)
        self.objects[name] = copy.deepcopy(body)


def identity_config():
    return dict(namespace="workspaces", argoNamespace="gitops", name="projector", owner="installation")


def test_plugin_identity_is_random_retained_projected_and_garbage_collected_with_owners():
    identity = load("projector_identity")
    api = MemoryApi()
    identity.provision(identity_config(), api)
    first = api.objects["/api/v1/namespaces/workspaces/secrets/projector"]
    peer = api.objects["/api/v1/namespaces/gitops/secrets/projector"]
    assert first["data"] == peer["data"]
    assert first["immutable"] and peer["immutable"]
    assert first["metadata"]["ownerReferences"][0]["kind"] == "Deployment"
    assert peer["metadata"]["ownerReferences"][0]["kind"] == "ApplicationSet"
    identity.provision(identity_config(), api)
    assert len(api.created) == 2


@pytest.mark.parametrize("fault", ["owner", "namespace", "token", "mutable"])
def test_plugin_identity_never_overwrites_foreign_or_changed_material(fault):
    identity = load("projector_identity")
    api = MemoryApi()
    identity.provision(identity_config(), api)
    obj = api.objects["/api/v1/namespaces/workspaces/secrets/projector"]
    if fault == "owner": obj["metadata"]["ownerReferences"][0]["uid"] = "replacement"
    if fault == "namespace": api.objects["/api/v1/namespaces/workspaces"]["metadata"]["uid"] = "replacement"
    if fault == "token": obj["data"]["token"] = "invalid"
    if fault == "mutable": obj["immutable"] = False
    with pytest.raises(identity.IdentityError): identity.provision(identity_config(), api)
    assert len(api.created) == 2


def test_http_plugin_authentication_and_error_are_not_a_prune_request(projector, tmp_path):
    settings, profiles, token = [tmp_path / name for name in ("config.json", "catalog.json", "token")]
    settings.write_text(json.dumps(config()))
    profiles.write_text(json.dumps({"profiles": catalog()}))
    token.write_text("test-only-plugin-token")
    with projector.server(settings, profiles, token, lambda _: {}, ("127.0.0.1", 0)) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = "http://127.0.0.1:"+str(server.server_address[1])+"/api/v1/getparams.execute"
        def call(bearer):
            req = Request(url, method="POST", data=b"{}", headers={"Authorization": "Bearer "+bearer})
            try:
                with urlopen(req, timeout=2) as res: return res.status, json.load(res)
            except HTTPError as error:
                with error: return error.code, json.load(error)
        try:
            assert call("wrong")[0] == 403
            code, result = call(token.read_text())
            assert code == 200 and result["output"]["parameters"][0]["name"] == "alice"
            assert "workspaceValues" in result["output"]["parameters"][0]
            settings.write_text("invalid json")
            code, result = call(token.read_text())
            assert code == 503 and "output" not in result
            settings.write_text(json.dumps({"users": [], "containerSites": {}}))
            assert call(token.read_text()) == (200, {"output": {"parameters": []}})
        finally:
            server.shutdown()
            worker.join(timeout=3)


def test_missing_peer_projection_resumes_with_the_same_identity():
    identity = load("projector_identity")
    api = MemoryApi()
    identity.provision(identity_config(), api)
    first = copy.deepcopy(api.objects["/api/v1/namespaces/workspaces/secrets/projector"])
    del api.objects["/api/v1/namespaces/gitops/secrets/projector"]
    identity.provision(identity_config(), api)
    assert api.objects["/api/v1/namespaces/workspaces/secrets/projector"] == first
    assert api.objects["/api/v1/namespaces/gitops/secrets/projector"]["data"] == first["data"]


def test_orphaned_plugin_identity_is_not_silently_replaced():
    identity = load("projector_identity")
    api = MemoryApi()
    identity.provision(identity_config(), api)
    del api.objects["/api/v1/namespaces/workspaces/secrets/projector"]
    with pytest.raises(identity.IdentityError, match="orphaned"):
        identity.provision(identity_config(), api)
    assert len(api.created) == 2


def test_missing_publication_holds_only_an_already_bound_owner(projector):
    cfg = config()
    bob = copy.deepcopy(cfg["users"][0])
    bob.update(name="bob", registration="b"*16, installationID="33333333-3333-4333-8333-333333333333")
    cfg["users"].append(bob)
    cfg["containerSites"]["bob"] = copy.deepcopy(cfg["containerSites"]["alice"])
    cfg.setdefault("workspaceRevisions", {})["bob"] = "c"*40
    initial, _ = projector.parameters(cfg, catalog(), lambda _: {})
    last = json.loads(initial["workspaceValues"])
    last["containerSites"]["alice"]["enrollment"] = {"registration": "a"*16}

    class Reader:
        def __call__(self, path):
            return {}
        def previous(self, owner):
            return copy.deepcopy(last) if owner["name"] == "alice" else None

    a, b = projector.parameters(cfg, catalog(), Reader())
    assert json.loads(a["workspaceValues"]) == last
    assert b["name"] == "bob" and b["revision"] == "c"*40
    assert "enrollment" not in json.loads(b["workspaceValues"])["containerSites"]["bob"]


@pytest.mark.parametrize("field",["reference","relay","revision","image","buildNamespace"])
def test_invalid_enabled_site_reports_owner_and_field(projector, field):
    cfg = config()
    auto = cfg["containerSites"]["alice"]["automaticEnrollment"]
    auto.pop(field)
    with pytest.raises(projector.ProjectionError, match="alice.*"+field):
        projector.parameters(cfg, catalog(), lambda _: {})
