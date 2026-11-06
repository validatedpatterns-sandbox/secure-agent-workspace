"""Per-operation identity, public trust updates and cleanup under failure."""
import base64
from contextlib import contextmanager
import copy
import json
import os
import ssl
import subprocess
import uuid

import pytest

from saw_kubernetes import admin_session as sessions
from saw_kubernetes.compiler import ContractError
from saw_kubernetes.controller import ApiError

OWNER = "67a9891d-e281-442f-86c3-41771f5ce049"
PODS = {"controller": str(uuid.uuid4()), "bind-job": str(uuid.uuid4())}


@pytest.fixture
def ca(tmp_path):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(tmp_path/"ca.key"),
                    "-out", str(tmp_path/"ca.crt"), "-days", "2", "-subj", "/CN=server-ca"],
                   check=True, capture_output=True)
    return (tmp_path/"ca.crt").read_bytes()


def local_identity(ca, path):
    # Unit fixture: exercise real issuance without requiring a Linux tmpfs or shred.
    path.mkdir(exist_ok=True)
    return sessions.admin.identity(ca, path, require_tmpfs=False, erase=lambda p: p.unlink())


class Api:
    def __init__(self, ca):
        self.secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": False,
                       "metadata": {"namespace": "runtime", "name": "gateway-client-ca",
                                    "uid": str(uuid.uuid4()), "resourceVersion": "1",
                                    "labels": {sessions.OWNER: OWNER}},
                       "data": {"base.crt": sessions.encoded(ca),
                                "ca.crt": sessions.encoded(sessions.bundle(ca, {}))}}
        self.pods = {name: {"metadata": {"uid": uid}, "status": {"phase": "Running"}}
                     for name, uid in PODS.items()}
        self.writes, self.conflict, self.ambiguous = 0, None, False

    def request(self, method, path, body=None):
        if path.startswith("/api/v1/namespaces/trusted/pods/"):
            assert method == "GET"
            name = path.rsplit("/", 1)[1]
            if name not in self.pods:
                raise ApiError(404)
            return copy.deepcopy(self.pods[name])
        assert path == "/api/v1/namespaces/runtime/secrets/gateway-client-ca"
        if method == "GET":
            return copy.deepcopy(self.secret)
        assert method == "PUT"
        if self.conflict:
            callback, self.conflict = self.conflict, None
            callback()
        if body["metadata"]["resourceVersion"] != self.secret["metadata"]["resourceVersion"]:
            raise ApiError(409)
        version = int(self.secret["metadata"]["resourceVersion"])+1
        self.secret = copy.deepcopy(body)
        self.secret["metadata"]["resourceVersion"] = str(version)
        self.writes += 1
        if self.ambiguous:
            self.ambiguous = False
            raise ApiError()
        return copy.deepcopy(self.secret)

    def trust(self, ca, pod="controller", **kwargs):
        return sessions.TrustBundle(self.request, "runtime", "trusted", "gateway", OWNER,
                                    ca, pod, PODS[pod], **kwargs)


def published(api):
    return json.loads(api.secret["metadata"].get("annotations", {}).get(sessions.SESSIONS, "{}"))


def test_shared_identity_roles_permissions_and_private_cleanup(ca, tmp_path):
    runtime = tmp_path/"runtime"
    with local_identity(ca, runtime) as identity:
        tls = identity["tls"]
        result = subprocess.run(["openssl", "x509", "-in", str(tls/"client/tls.crt"),
                                 "-noout", "-text"], capture_output=True, text=True, check=True)
        assert "openshell-admin" in result.stdout
        assert "TLS Web Client Authentication" in result.stdout and "CA:FALSE" in result.stdout
        assert (tls/"ca.crt").read_bytes() == ca
        assert not list(runtime.rglob("ca.key"))
        assert os.stat(tls/"client/tls.key").st_mode & 0o777 == 0o600
        assert os.stat(tls.parent).st_mode & 0o777 == 0o700
    assert not tls.exists() and not list(runtime.rglob("*.key"))


def test_starting_job_waits_for_its_own_running_phase_before_issuing_or_publishing(ca, tmp_path, monkeypatch):
    api = Api(ca)
    runtime = tmp_path/"runtime"
    runtime.mkdir()
    api.pods["bind-job"]["status"]["phase"] = "Pending"
    trust = api.trust(ca, "bind-job")
    elapsed = [0]
    def sleep(seconds):
        assert not published(api) and api.writes == 0
        assert not list(runtime.rglob("*.key")) and not list(runtime.glob("saw-admin.*"))
        elapsed[0] += seconds
        if elapsed[0] >= 1:
            api.pods["bind-job"]["status"]["phase"] = "Running"
    wait = trust.wait_for_holder
    monkeypatch.setattr(trust, "wait_for_holder", lambda: wait(sleep=sleep, monotonic=lambda: elapsed[0]))
    identity = sessions.admin.identity
    monkeypatch.setattr(sessions.admin, "identity", lambda ca, runtime:
                        identity(ca, runtime, require_tmpfs=False, erase=lambda p: p.unlink()))
    monkeypatch.setattr(sessions.admin, "require_memory", lambda _: None)
    calls = []
    class Gateway:
        def __init__(self, *args, **kwargs): pass
        def call(self, method, body):
            assert published(api) and trust.live({"pod": trust.pod, "uid": trust.pod_uid})
            calls.append(method)
        def close(self): pass
    with sessions.GatewaySessions(trust, "https://gateway:17670", runtime, gateway_factory=Gateway).open():
        assert elapsed[0] == 1 and calls == ["GetGatewayInfo"]
        assert len(published(api)) == 1
    assert not published(api) and not list(runtime.rglob("*.key"))


@pytest.mark.parametrize("state", ["missing", "replacement", "deleting", "Succeeded", "Failed", "Unknown", "unset"])
def test_startup_wait_fails_closed_for_nonstarting_identity(ca, tmp_path, monkeypatch, state):
    api = Api(ca)
    pod = api.pods["bind-job"]
    if state == "missing": del api.pods["bind-job"]
    elif state == "replacement": pod["metadata"]["uid"] = str(uuid.uuid4())
    elif state == "deleting": pod["metadata"]["deletionTimestamp"] = "now"
    elif state == "unset": pod["status"] = {}
    else: pod["status"]["phase"] = state
    monkeypatch.setattr(sessions.admin, "require_memory", lambda _: None)
    def identity(*args, **kwargs): pytest.fail("issued private identity before holder readiness")
    monkeypatch.setattr(sessions.admin, "identity", identity)
    with pytest.raises(ContractError, match="administrator session holder"):
        with sessions.GatewaySessions(api.trust(ca, "bind-job"), "https://gateway:17670", tmp_path).open():
            pytest.fail("unavailable holder was admitted")
    assert not published(api) and api.writes == 0


def test_startup_wait_timeout_is_bounded_and_does_not_publish(ca):
    api = Api(ca)
    api.pods["bind-job"]["status"]["phase"] = "Pending"
    elapsed = [0]
    with pytest.raises(ContractError, match="before the deadline"):
        api.trust(ca, "bind-job").wait_for_holder(timeout=2,
            sleep=lambda seconds: elapsed.__setitem__(0, elapsed[0]+seconds), monotonic=lambda: elapsed[0])
    assert elapsed[0] == 2 and api.writes == 0 and not published(api)


@pytest.mark.parametrize("code", [0, 403, 503])
def test_startup_wait_does_not_retry_api_errors_or_publish(ca, code):
    api = Api(ca)
    trust = api.trust(ca, "bind-job")
    def unavailable(*args, **kwargs): raise ApiError(code)
    trust.request = unavailable
    def no_sleep(_): pytest.fail("retried API error as a Pending Pod")
    with pytest.raises(ApiError) as error:
        trust.wait_for_holder(sleep=no_sleep)
    assert error.value.code == code and api.writes == 0


def test_publication_rechecks_uid_after_successful_startup_wait(ca, tmp_path, monkeypatch):
    api = Api(ca)
    runtime = tmp_path/"runtime"
    runtime.mkdir()
    monkeypatch.setattr(sessions.admin, "require_memory", lambda _: None)
    original = sessions.admin.identity
    @contextmanager
    def identity(base, runtime):
        with original(base, runtime, require_tmpfs=False, erase=lambda p: p.unlink()) as value:
            api.pods["bind-job"]["metadata"]["uid"] = str(uuid.uuid4())
            yield value
    monkeypatch.setattr(sessions.admin, "identity", identity)
    with pytest.raises(ContractError, match="holder unavailable"):
        with sessions.GatewaySessions(api.trust(ca, "bind-job"), "https://gateway:17670", runtime).open():
            pytest.fail("replacement holder was admitted")
    assert not published(api) and api.writes == 0 and not list(runtime.rglob("*.key"))


def test_concurrent_sessions_preserve_trust_with_compare_and_swap(ca, tmp_path):
    api = Api(ca)
    first, second = api.trust(ca), api.trust(ca, "bind-job")
    with local_identity(ca, tmp_path/"one") as one, local_identity(ca, tmp_path/"two") as two:
        api.conflict = lambda: second.update(add=two)
        first.update(add=one)
        assert set(published(api)) == {one["id"], two["id"]}
        assert all(b"PRIVATE KEY" not in base64.b64decode(v) for v in api.secret["data"].values())
        first.update(remove=one["id"])
        assert set(published(api)) == {two["id"]}
        second.update(remove=two["id"])
        assert not published(api)
        assert api.secret["data"]["ca.crt"] == sessions.encoded(sessions.bundle(ca, {}))


@pytest.mark.parametrize("dead", ["deleted", "replaced", "terminating", "completed", "expired"])
def test_abandoned_session_pruned_without_dropping_live_session(ca, tmp_path, dead):
    api = Api(ca)
    with local_identity(ca, tmp_path/"one") as one, local_identity(ca, tmp_path/"two") as two:
        api.trust(ca).update(add=one)
        api.trust(ca, "bind-job").update(add=two)
        if dead == "deleted": del api.pods["controller"]
        if dead == "replaced": api.pods["controller"]["metadata"]["uid"] = str(uuid.uuid4())
        if dead == "terminating": api.pods["controller"]["metadata"]["deletionTimestamp"] = "now"
        if dead == "completed": api.pods["controller"]["status"]["phase"] = "Succeeded"
        if dead == "expired":
            values = published(api)
            values[one["id"]]["expires"] = 1
            api.secret["metadata"]["annotations"][sessions.SESSIONS] = json.dumps(values)
        api.trust(ca, "bind-job").update(add=two)
        assert set(published(api)) == {two["id"]}


@pytest.mark.parametrize("damage", ["owner", "immutable", "base", "bundle", "private", "uid", "gc"])
def test_foreign_or_malformed_trust_is_not_written(ca, tmp_path, damage):
    api = Api(ca)
    trust = api.trust(ca)
    with local_identity(ca, tmp_path/"one") as one:
        trust.update(add=one)
        if damage == "owner": api.secret["metadata"]["labels"][sessions.OWNER] = "foreign"
        if damage == "immutable": api.secret["immutable"] = True
        if damage == "base": api.secret["data"]["base.crt"] = sessions.encoded(b"foreign")
        if damage == "bundle": api.secret["data"]["ca.crt"] = sessions.encoded(ca)
        if damage == "uid": api.secret["metadata"]["uid"] = str(uuid.uuid4())
        if damage == "gc": api.secret["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
        if damage == "private":
            value = one["ca"].encode()+(one["tls"]/"client/tls.key").read_bytes()
            api.secret["data"]["session-"+one["id"]+".crt"] = sessions.encoded(value)
            api.secret["data"]["ca.crt"] = sessions.encoded(sessions.bundle(ca, {one["id"]: value}))
        before = api.writes
        with pytest.raises(ContractError): trust.update(remove=one["id"])
        assert api.writes == before


def test_no_withdrawal_of_another_live_holder(ca, tmp_path):
    api = Api(ca)
    with local_identity(ca, tmp_path/"one") as one:
        api.trust(ca).update(add=one)
        with pytest.raises(ContractError): api.trust(ca, "bind-job").update(remove=one["id"])
        assert one["id"] in published(api)


def test_pod_api_error_does_not_prune_trust(ca, tmp_path):
    api = Api(ca)
    trust = api.trust(ca)
    with local_identity(ca, tmp_path/"one") as one:
        trust.update(add=one)
        def unavailable(holder): raise ApiError(503)
        trust.live = unavailable
        with pytest.raises(ApiError): trust.update(remove=one["id"])
        assert one["id"] in published(api)


@pytest.mark.parametrize("failure", ["operation", "ambiguous-publish", "probe"])
def test_session_cleanup_on_every_failure(ca, tmp_path, monkeypatch, failure):
    api = Api(ca)
    identity_factory = sessions.admin.identity
    def identity(base, runtime):
        return identity_factory(base, runtime, require_tmpfs=False, erase=lambda p: p.unlink())
    monkeypatch.setattr(sessions.admin, "identity", identity)
    monkeypatch.setattr(sessions.admin, "require_memory", lambda _: None)
    clients = []
    class Gateway:
        def __init__(self, *args, **kwargs):
            self.closed = False
            clients.append(self)
        def call(self, method, body):
            assert method == "GetGatewayInfo"
            if failure == "probe": raise sessions.RpcError("PERMISSION_DENIED")
        def close(self): self.closed = True
    api.ambiguous = failure == "ambiguous-publish"
    factory = sessions.GatewaySessions(api.trust(ca), "https://gateway:17670", tmp_path, gateway_factory=Gateway)
    with pytest.raises((ApiError, RuntimeError, sessions.RpcError)):
        with factory.open():
            assert published(api)
            raise RuntimeError("operation failed")
    assert not published(api)
    assert all(client.closed for client in clients)
    assert not list(tmp_path.rglob("tls.key"))


def test_trust_wait_is_bounded():
    elapsed = [0]
    def sleep(seconds): elapsed[0] += seconds
    with pytest.raises(sessions.admin.AdminSessionError):
        sessions.admin.wait_for_trust(lambda: False, timeout=3, sleep=sleep, monotonic=lambda: elapsed[0])
    assert elapsed[0] == 3


def test_temporary_identity_authenticates_only_while_its_ca_is_trusted(ca, tmp_path):
    """Real TLS over memory BIOs; no sockets or gateway-specific reload simulation."""
    def handshake(identity, ca_bundle):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.maximum_version = ssl.TLSVersion.TLSv1_2
        server.load_cert_chain(tmp_path/"ca.crt", tmp_path/"ca.key")
        server.verify_mode = ssl.CERT_REQUIRED
        server.load_verify_locations(cadata=ca_bundle.decode())
        client = ssl.create_default_context(cadata=ca.decode())
        client.load_cert_chain(identity["tls"]/"client/tls.crt", identity["tls"]/"client/tls.key")
        si, so, ci, co = (ssl.MemoryBIO() for _ in range(4))
        endpoints = [(client.wrap_bio(ci, co, server_hostname="server-ca"), co, si),
                     (server.wrap_bio(si, so, server_side=True), so, ci)]
        done = set()
        for _ in range(20):
            for index, (connection, outgoing, incoming) in enumerate(endpoints):
                try:
                    connection.do_handshake()
                    done.add(index)
                except ssl.SSLWantReadError:
                    pass
                while outgoing.pending:
                    incoming.write(outgoing.read())
            if len(done) == 2: return
        pytest.fail("TLS handshake did not complete")

    api = Api(ca)
    trust = api.trust(ca)
    with local_identity(ca, tmp_path/"one") as one:
        with pytest.raises(ssl.SSLError): handshake(one, ca)
        trust.update(add=one)
        handshake(one, base64.b64decode(api.secret["data"]["ca.crt"]))
        trust.update(remove=one["id"])
        with pytest.raises(ssl.SSLError): handshake(one, base64.b64decode(api.secret["data"]["ca.crt"]))
        with local_identity(ca, tmp_path/"two") as two:
            assert one["id"] != two["id"] and one["ca"] != two["ca"]
            trust.update(add=two)
            handshake(two, base64.b64decode(api.secret["data"]["ca.crt"]))
            with pytest.raises(ssl.SSLError): handshake(one, base64.b64decode(api.secret["data"]["ca.crt"]))
            trust.update(remove=two["id"])


def test_same_pod_restart_removes_its_abandoned_session_only(ca, tmp_path, monkeypatch):
    api = Api(ca)
    runtime = tmp_path/"runtime"
    runtime.mkdir()
    stale = runtime/"saw-admin.abandoned"
    stale.mkdir()
    (stale/"tls.key").write_text("private fixture")
    monkeypatch.setattr(sessions.admin, "require_memory", lambda _: None)
    with local_identity(ca, tmp_path/"old") as old, local_identity(ca, tmp_path/"relay") as relay:
        api.trust(ca).update(add=old)
        api.trust(ca, "bind-job").update(add=relay)
        factory = sessions.GatewaySessions(api.trust(ca), "https://gateway:17670", runtime)
        with factory._exclusive():
            assert not stale.exists()
            assert set(published(api)) == {relay["id"]}
            # A second process must not remove the current process's files/trust.
            fresh = runtime/"saw-admin.active"
            fresh.mkdir()
            other = sessions.GatewaySessions(api.trust(ca), "https://gateway:17670", runtime)
            with pytest.raises(ContractError, match="another administrator operation"):
                with other._exclusive(): pytest.fail("concurrent session was admitted")
            assert fresh.exists() and set(published(api)) == {relay["id"]}


def test_restart_erases_private_files_even_when_trust_api_is_unavailable(ca, tmp_path, monkeypatch):
    stale = tmp_path/"saw-admin.abandoned"
    stale.mkdir()
    (stale/"tls.key").write_text("private fixture")
    api = Api(ca)
    def unavailable(*args, **kwargs): raise ApiError(503)
    trust = api.trust(ca)
    trust.request = unavailable
    monkeypatch.setattr(sessions.admin, "require_memory", lambda _: None)
    with pytest.raises(ApiError):
        with sessions.GatewaySessions(trust, "https://gateway:17670", tmp_path)._exclusive():
            pytest.fail("operation proceeded without trust recovery")
    assert not stale.exists()


def test_abandoned_cleanup_does_not_follow_authority_symlink(tmp_path):
    root, outside = tmp_path/"runtime", tmp_path/"outside"
    root.mkdir()
    outside.mkdir()
    (outside/"session.keep").mkdir()
    (root/"saw-authorities").symlink_to(outside)
    with pytest.raises(sessions.admin.AdminSessionError, match="symlink"):
        sessions.admin.remove_abandoned(root)
    assert (outside/"session.keep").exists()
