"""The relay registrar: created without a manual step, never adopts foreign state."""
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "charts/openshell-keycloak/files"))
SCRIPT = ROOT / "charts/openshell-keycloak/files/relay-provisioner.py"
SPEC = importlib.util.spec_from_file_location("relay_provisioner", SCRIPT)
prov = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prov)

ISSUER = "https://keycloak.apps.example.test/realms/openshell"


class FakeKube:
    """One Secret, with the API's create/get/merge-patch behaviour."""

    def get(self, path):
        return self(path)

    def __init__(self, secret=None):
        self.secret, self.writes = secret, []

    def __call__(self, path, method="GET", body=None, patch=False):
        if method == "GET":
            if self.secret is None:
                raise prov.HttpError(404, "not found")
            return json.loads(json.dumps(self.secret))
        self.writes.append(method)
        if method == "POST":
            assert path.endswith("/secrets") and self.secret is None
            self.secret = {"metadata": {**body["metadata"], "resourceVersion": "1"},
                           "data": {k: base64.b64encode(v.encode()).decode()
                                    for k, v in body["stringData"].items()}}
        else:
            assert patch
            self.secret["data"] = {k: base64.b64encode(v.encode()).decode()
                                   for k, v in body["stringData"].items()}
        return json.loads(json.dumps(self.secret))


def secret(labels, data=None):
    return {"metadata": {"name": prov.NAME, "labels": labels, "resourceVersion": "7"},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in (data or {}).items()}}


def test_a_new_cluster_gets_its_credential_without_a_manual_step():
    kube = FakeKube()
    values = prov.credential(kube, "saw-keycloak", ISSUER)
    assert kube.writes == ["POST"]
    assert values["client-id"] == prov.NAME and values["issuer"] == ISSUER
    assert len(values["client-secret"]) >= 40
    assert kube.secret["metadata"]["labels"] == {prov.LABEL: prov.NAME}


def test_the_credential_is_kept_across_runs():
    kube = FakeKube()
    first = prov.credential(kube, "saw-keycloak", ISSUER)
    assert prov.credential(kube, "saw-keycloak", ISSUER) == first
    assert kube.writes == ["POST"]


def test_a_secret_from_the_old_setup_script_is_adopted():
    """Clusters set up by hand with the retired script keep their client."""
    data = {"client-id": prov.NAME, "client-secret": "s" * 54, "issuer": ISSUER}
    kube = FakeKube(secret({prov.LABEL: prov.NAME}, data))
    assert prov.credential(kube, "saw-keycloak", ISSUER) == data and kube.writes == []


def test_an_empty_owned_secret_is_filled():
    kube = FakeKube(secret({prov.LABEL: prov.NAME}))
    assert prov.credential(kube, "saw-keycloak", ISSUER)["client-id"] == prov.NAME
    assert kube.writes == ["PATCH"]


@pytest.mark.parametrize("labels,data,message", [
    ({}, {"client-id": prov.NAME, "client-secret": "x", "issuer": ISSUER}, "not this helper's"),
    ({prov.LABEL: prov.NAME}, {"client-id": prov.NAME, "client-secret": "x", "issuer": "https://other/realms/x"},
     "issuer"),
    ({prov.LABEL: prov.NAME}, {"client-id": "other", "client-secret": "x", "issuer": ISSUER}, "unexpected"),
])
def test_foreign_or_mismatched_secrets_are_refused(labels, data, message):
    kube = FakeKube(secret(labels, data))
    with pytest.raises(ValueError, match=message):
        prov.credential(kube, "saw-keycloak", ISSUER)
    assert kube.writes == []


def test_errors_are_retried_rather_than_crashing(monkeypatch):
    class Stop(Exception):
        pass
    monkeypatch.setenv("KEYCLOAK_NAMESPACE", "saw-keycloak")
    monkeypatch.setenv("KEYCLOAK_NAME", "openshell-keycloak")
    monkeypatch.setenv("REALM", "openshell")
    monkeypatch.setenv("KC_URL", "https://keycloak.apps.example.test")
    monkeypatch.setattr(prov, "Kube", lambda: FakeKube())
    monkeypatch.setattr(prov.saw_tls, "tls_context", lambda *a: None)
    calls, sleeps = [], []
    def setup(*args):
        calls.append(args)
        if len(calls) == 1:
            raise prov.HttpError(503, "keycloak starting")
    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise Stop
    monkeypatch.setattr(prov, "setup", setup)
    monkeypatch.setattr(prov.time, "sleep", sleep)
    with pytest.raises(Stop):
        prov.main(["relay-provisioner.py"])
    assert sleeps == [15, 300] and calls[1][2] == ISSUER
