"""Create-once identity and crash recovery; fake API, real OpenSSL leaf issuance."""
import copy
import importlib.util
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("identity_bootstrap", ROOT / "charts/saw-kubernetes-identity/files/bootstrap.py")
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


@pytest.fixture
def config():
    return dict(ownerID="67a9891d-e281-442f-86c3-41771f5ce049", namespace="saw-test-trusted",
                targetNamespace="saw-test", gateway="saw-test",
                serverSans=["saw-test-gateway.saw-test.svc", "saw-test-gateway.saw-test.svc.cluster.local"])


def material(prefix="test"):
    data = {key: boot.encode((prefix + key).encode()) for key in
            ("ca", "serverCert", "serverKey", "signing", "public", "kid")}
    data["kek"] = boot.encode(boot.encode(b"a" * 32).encode())
    return data


class Api:
    def __init__(self, config):
        self.namespaces = {name: {"metadata": {"uid": name + "-uid", "labels": {boot.OWNER: config["ownerID"]}}}
                           for name in (config["namespace"], config["targetNamespace"])}
        self.values, self.created = {}, []
        self.fail_after = None

    def request(self, method, path, body=None):
        parts = path.split("/")
        ns = parts[4]
        assert parts[5] == "configmaps"
        if method == "GET":
            return self.get(ns, parts[6])
        assert method == "POST"
        return self.create(ns, body)

    def namespace(self, name):
        return copy.deepcopy(self.namespaces[name])

    def get(self, ns, name):
        return copy.deepcopy(self.values.get((ns, name)))

    def create(self, ns, body):
        key = ns, body["metadata"]["name"]
        if key not in self.values:
            self.values[key] = copy.deepcopy(body)
            self.created.append(key)
        if self.fail_after == len(self.created):
            raise boot.Failure("simulated ambiguous create")


def never():
    pytest.fail("existing retained bundle must not regenerate identity")


def test_repeat_sync_preserves_identity_without_retained_administrator(config):
    api = Api(config)
    boot.run(api, config, material)
    before = copy.deepcopy(api.values)
    boot.run(api, config, never)
    assert before == api.values and len(api.created) == 6
    runtime = [v for (ns, _), v in api.values.items() if ns == config["targetNamespace"]]
    assert len(runtime) == 4
    assert not any("admin" in name.lower() for v in api.values.values() for name in v["data"])
    for (_, name), value in api.values.items():
        assert value["immutable"] is (not name.endswith("-client-ca"))
        assert not value["metadata"].get("ownerReferences")
    public = api.get(config["namespace"], "saw-test-gateway-ca")
    assert public["kind"] == "ConfigMap" and set(public["data"]) == {"ca.crt"}
    assert not any("ca.key" in v["data"] for v in api.values.values())


@pytest.mark.parametrize("point", range(1, 7))
def test_resume_after_ambiguous_create(config, point):
    api = Api(config)
    api.fail_after = point
    with pytest.raises(boot.Failure):
        boot.run(api, config, material)
    retained = api.get(config["namespace"], "saw-test-identity")
    api.fail_after = None
    boot.run(api, config, never)
    assert api.get(config["namespace"], "saw-test-identity") == retained
    assert len(api.created) == 6


def test_racing_creator_uses_atomic_winner(config):
    api = Api(config)
    create = api.create
    def winner(ns, body):
        if body["metadata"]["name"].endswith("-identity"):
            body = copy.deepcopy(body)
            body["data"] = material("winner")
        create(ns, body)
    api.create = winner
    boot.run(api, config, material)
    assert api.get(config["targetNamespace"], "saw-test-server")["data"]["tls.key"] == material("winner")["serverKey"]


def test_orphaned_projection_never_regenerates(config):
    api = Api(config)
    api.values[(config["targetNamespace"], "saw-test-server")] = {"data": {}}
    with pytest.raises(boot.Failure, match="orphaned"):
        boot.run(api, config, never)
    assert not api.created


@pytest.mark.parametrize("mutation", ["uid", "owner", "san", "deleting", "data", "gc", "mutable"])
def test_foreign_or_changed_identity_fails_without_mutation(config, mutation):
    api = Api(config)
    boot.run(api, config, material)
    retained = api.values[(config["namespace"], "saw-test-identity")]
    if mutation == "uid":
        api.namespaces[config["targetNamespace"]]["metadata"]["uid"] = "replacement"
    elif mutation == "owner":
        retained["metadata"]["labels"][boot.OWNER] = "other"
    elif mutation == "san":
        config["serverSans"].append("new.example.test")
    elif mutation == "deleting":
        retained["metadata"]["deletionTimestamp"] = "now"
    elif mutation == "data":
        del retained["data"]["serverKey"]
    elif mutation == "gc":
        retained["metadata"]["ownerReferences"] = [{"kind": "Job"}]
    elif mutation == "mutable":
        retained["immutable"] = False
    with pytest.raises(boot.Failure):
        boot.run(api, config, never)
    assert len(api.created) == 6


def test_conflicting_projection_is_not_overwritten(config):
    api = Api(config)
    boot.run(api, config, material)
    api.values[(config["targetNamespace"], "saw-test-kek")]["data"]["key-encryption-key"] = "foreign"
    with pytest.raises(boot.Failure, match="foreign"):
        boot.run(api, config, never)
    assert len(api.created) == 6


@pytest.mark.parametrize("field,value", [("targetNamespace", "saw-test-trusted"), ("ownerID", "not-uuid"),
    ("serverSans", ["https://bad"]), ("serverSans", []), ("adminDays", True), ("adminDays", 91),
    ("gateway", "../../bad"), ("namespace", "bad/name")])
def test_invalid_inputs_fail_before_api(config, field, value):
    config[field] = value
    with pytest.raises(boot.Failure):
        boot.run(None, config, never)


@pytest.mark.skipif(not shutil.which("openssl"), reason="OpenSSL required")
def test_real_stock_server_identity_has_no_administrator_key(config, tmp_path, capsys):
    def command(*args):
        subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True)
    (tmp_path / "server").mkdir()
    (tmp_path / "jwt").mkdir()
    command("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", tmp_path / "ca.key", "-out", tmp_path / "ca.crt", "-days", "2", "-subj", "/CN=test-ca")
    command("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", tmp_path / "server/tls.key", "-out", tmp_path / "server/request", "-subj", "/CN=gateway")
    (tmp_path / "server/ext").write_text("subjectAltName=" + ",".join("DNS:" + n for n in config["serverSans"]) + "\n")
    command("x509", "-req", "-in", tmp_path / "server/request", "-CA", tmp_path / "ca.crt",
            "-CAkey", tmp_path / "ca.key", "-set_serial", "2", "-days", "2", "-extfile", tmp_path / "server/ext",
            "-out", tmp_path / "server/tls.crt")
    for name in ("signing.pem", "public.pem", "kid"):
        (tmp_path / "jwt" / name).write_text("synthetic-jwt-fixture")
    data = boot.generate(config, tmp_path)
    assert not (tmp_path / "ca.key").exists()
    assert not (tmp_path / "admin").exists()
    assert not {"adminKey", "adminCert"}.intersection(data)
    assert len(boot.decode(boot.decode(data["kek"]))) == 32
    assert not capsys.readouterr().out


def test_orphaned_public_ca_never_regenerates(config):
    api = Api(config)
    api.values[(config["namespace"], "saw-test-gateway-ca")] = {"data": {}}
    with pytest.raises(boot.Failure, match="orphaned"):
        boot.run(api, config, never)
    assert not api.created


def test_existing_admin_bundle_is_rejected_before_new_projections(config):
    api = Api(config)
    boot.run(api, config, material)
    api.values[(config["namespace"], "saw-test-identity")]["data"]["adminKey"] = boot.encode(b"obsolete")
    with pytest.raises(boot.Failure, match="incomplete"):
        boot.run(api, config, never)
    assert len(api.created) == 6


def test_repeat_bootstrap_does_not_remove_active_public_session(config):
    api = Api(config)
    boot.run(api, config, material)
    trust = api.values[(config["targetNamespace"], "saw-test-client-ca")]
    trust["data"]["session-67a9891d-e281-442f-86c3-41771f5ce049.crt"] = boot.encode(b"public-certificate")
    trust["data"]["ca.crt"] = boot.encode(b"active-public-bundle")
    trust["metadata"]["annotations"]["saw.redhat.com/admin-sessions"] = "fixture"
    before = copy.deepcopy(api.values)
    boot.run(api, config, never)
    assert api.values == before
