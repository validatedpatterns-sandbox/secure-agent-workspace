"""Named-ConfigMap controller contracts with no cluster/network or real credentials."""

import copy
import io
import json
from urllib.error import HTTPError

import pytest

from saw_kubernetes.compiler import ContractError, OWNER, canonical, digest
from saw_kubernetes.controller import (
    ApiError, CONTROLLER, Controller, ConfigMapClient, MANAGED, MAX_BODY,
    Scope, _NoRedirect,
)
from saw_kubernetes.reconcile import Busy, RpcError
from .test_runtime import FakeGateway, flat_profile, source


OWNER_ID = "b032b2e4-2cd5-47a7-8ef8-ac73e15700b1"


class FakeAPI:
    def __init__(self, scope):
        self.scope = scope
        self.objects, self.calls, self.writes, self.watches = {}, [], [], []
        self.version = 10
        self.conflicts = 0
        self.on_get = None
        self.on_watch = lambda: iter(())

    def configmap(self, name, data, **metadata):
        self.version += 1
        obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": name, "namespace": self.scope.namespace, "uid": name + "-uid",
            "resourceVersion": str(self.version), **metadata}, "data": copy.deepcopy(data)}
        self.objects[name] = obj
        return obj

    def get(self, name):
        assert name in {self.scope.profile_name, self.scope.bindings_name, self.scope.status_name}
        self.calls.append(name)
        if self.on_get:
            self.on_get(name)
        return copy.deepcopy(self.objects.get(name))

    def write_status(self, body, *, resource_version=None):
        assert body["metadata"]["name"] == self.scope.status_name
        self.writes.append((copy.deepcopy(body), resource_version))
        if self.conflicts:
            self.conflicts -= 1
            raise ApiError(409)
        old = self.objects.get(self.scope.status_name)
        if (old is not None and resource_version != old["metadata"]["resourceVersion"]
                or old is None and resource_version is not None):
            raise ApiError(409)
        self.version += 1
        saved = copy.deepcopy(body)
        saved["metadata"].update(uid=self.scope.status_name + "-uid", resourceVersion=str(self.version))
        self.objects[self.scope.status_name] = saved
        return copy.deepcopy(saved)

    def watch(self, name, resource_version, *, timeout_seconds):
        self.watches.append((name, resource_version, timeout_seconds))
        return self.on_watch()


@pytest.fixture
def setup(tmp_path):
    scope = Scope("saw-alice", "saw-alice-bom", "saw-runtime-intent", "saw-runtime-status", OWNER_ID)
    api = FakeAPI(scope)
    files = {"profiles__generic__default__workspace.yaml": "workspace source",
             "profiles__generic__default__sandbox.yaml": "sandbox source"}
    profile = api.configmap(scope.profile_name, files)
    intent = {"schemaVersion": 1, "generation": 1, "desiredState": "Running",
              "profileRef": {"name": scope.profile_name, "uid": profile["metadata"]["uid"], "sha256": digest(files)},
              "bindings": {"ownerID": OWNER_ID, "namespace": scope.namespace}}
    api.configmap(scope.bindings_name, {"intent.json": canonical(intent)}, labels={OWNER: OWNER_ID})
    compiled, calls, verified = [], [], []

    def compile_files(flat, bindings):
        compiled.append((copy.deepcopy(flat), copy.deepcopy(bindings)))
        return {"flat": flat, "bindings": bindings}

    def core(plan, **kwargs):
        calls.append((copy.deepcopy(plan), kwargs))
        return {"phase": "GenericReady", "retry_after_seconds": 0,
                "message": "must-not-be-published", "credentials": "must-not-be-published"}

    controller = Controller(api, scope, tmp_path / "state", compile_files, core, lambda plan: verified.append(plan))
    return controller, api, intent, compiled, calls, verified


def update_intent(setup, change):
    controller, api, intent, *_ = setup
    change(intent)
    api.version += 1
    obj = api.objects[controller.scope.bindings_name]
    obj["data"] = {"intent.json": canonical(intent)}
    obj["metadata"]["resourceVersion"] = str(api.version)


def test_existing_flat_files_compile_before_verified_core_pass(setup):
    c, api, intent, compiled, calls, verified = setup
    status = c.reconcile_once()
    assert status["phase"] == "GenericReady" and status["observedGeneration"] == 1
    assert calls[0][1] == {"generation": 1, "desired_state": "Running"}
    assert compiled[0][0] == api.objects[c.scope.profile_name]["data"]
    assert verified == [calls[0][0]]
    assert "must-not-be-published" not in canonical(api.objects[c.scope.status_name])
    before = len(api.writes)
    c.reconcile_once()
    assert len(api.writes) == before, "unchanged status must not churn resourceVersions"
    state = c.store.load()
    assert state["inputUIDs"] == {"bindings": c.scope.bindings_name + "-uid", "profile": c.scope.profile_name + "-uid"}
    assert state["intent"]["revision"] == status["inputRevision"]


def test_real_shared_compiler_and_reconciler_compose_with_restart_and_stop(setup, source):
    from saw_kubernetes import Reconciler, compile_profile_files

    c, api, _, _, _, _ = setup
    files = flat_profile(source)
    api.objects[c.scope.profile_name]["data"] = files
    update_intent(setup, lambda i: i.update(bindings=source[1],
                  profileRef={**i["profileRef"], "sha256": digest(files)}))
    gateway = FakeGateway()
    state_root = c.store.directory.parent
    reconciler = Reconciler(gateway, state_root, lambda plan: None)
    c.compile_files, c.core_pass = compile_profile_files, reconciler.reconcile
    assert c.reconcile_once()["phase"] == "Pending"  # owner membership
    assert c.reconcile_once()["phase"] == "Pending"  # Sandbox created
    instance = gateway.sandboxes[("default", "toolbox")]
    instance["status"]["phase"] = "SANDBOX_PHASE_READY"
    sandbox_id = instance["metadata"]["id"]
    resumed = Controller(api, c.scope, state_root, compile_profile_files,
                         Reconciler(gateway, state_root, lambda plan: None).reconcile, lambda plan: None)
    assert resumed.reconcile_once()["phase"] == "GenericReady"
    assert sum(method == "CreateSandbox" for method, _ in gateway.calls) == 1
    resumed.verify_boundary = lambda _: (_ for _ in ()).throw(RuntimeError("revoked"))
    assert resumed.reconcile_once()["reason"] == "BoundaryRejected"
    update_intent(setup, lambda i: i.update(generation=2, desiredState="Stopped"))
    assert resumed.reconcile_once()["phase"] == "Pending"
    instance["status"]["phase"] = "SANDBOX_PHASE_STOPPED"
    assert resumed.reconcile_once()["phase"] == "Stopped"
    assert instance["metadata"]["id"] == sandbox_id
    assert sum(method == "CreateSandbox" for method, _ in gateway.calls) == 1


def test_missing_boundary_verifier_fails_before_api_access(setup):
    c, api, *_ = setup
    with pytest.raises(ContractError, match="boundary verifier"):
        Controller(api, c.scope, c.store.directory, c.compile_files, c.core_pass, None)
    assert api.calls == []


@pytest.mark.parametrize("bad_name", ["a.-b", "a-.b", "a..b", "a.-.b"])
def test_scope_requires_each_dns_subdomain_label_to_be_valid(bad_name):
    with pytest.raises(ContractError, match="explicit Kubernetes names"):
        Scope("saw-alice", bad_name, "intent", "status", OWNER_ID)


def test_scope_accepts_valid_dotted_configmap_names():
    scope = Scope("saw-alice", "profile.prod-1", "intent.prod-1", "status.prod-1", OWNER_ID)
    assert scope.profile_name == "profile.prod-1"


@pytest.mark.parametrize("missing", ["profile_name", "bindings_name"])
def test_missing_or_deleted_input_never_implies_stop_or_purge(setup, missing):
    c, api, _, _, calls, _ = setup
    c.reconcile_once()
    del api.objects[getattr(c.scope, missing)]
    assert c.reconcile_once()["reason"] == "MissingInputs"
    assert len(calls) == 1
    assert {body["metadata"]["name"] for body, _ in api.writes} == {c.scope.status_name}


def test_gitops_half_revision_waits_without_mutating_then_converges(setup):
    c, api, _, _, calls, _ = setup
    c.reconcile_once()
    profile = api.objects[c.scope.profile_name]
    profile["data"]["profiles__generic__default__sandbox.yaml"] = "new source"
    profile["metadata"]["resourceVersion"] = "profile-new"
    assert c.reconcile_once()["reason"] == "InputRevisionMismatch"
    assert len(calls) == 1
    update_intent(setup, lambda i: i.update(generation=2, profileRef={**i["profileRef"], "sha256": digest(profile["data"])}))
    assert c.reconcile_once()["phase"] == "GenericReady"
    assert calls[-1][1]["generation"] == 2


def test_change_during_double_read_refuses_mixed_snapshot(setup):
    c, api, _, _, calls, _ = setup
    reads = 0

    def change(name):
        nonlocal reads
        if name == c.scope.profile_name:
            reads += 1
            if reads == 2:
                api.objects[name]["metadata"]["resourceVersion"] = "changed"

    api.on_get = change
    assert c.reconcile_once()["reason"] == "InputsChangedDuringRead"
    assert not calls


@pytest.mark.parametrize("source_name", ["profile_name", "bindings_name"])
def test_restart_refuses_same_name_input_uid_replacement(setup, source_name):
    c, api, _, _, calls, _ = setup
    c.reconcile_once()
    name = getattr(c.scope, source_name)
    api.objects[name]["metadata"]["uid"] = "replacement"
    if source_name == "profile_name":
        update_intent(setup, lambda i: i["profileRef"].update(uid="replacement"))
    restarted = Controller(api, c.scope, c.store.directory.parent, c.compile_files, c.core_pass, c.verify_boundary)
    assert restarted.reconcile_once()["reason"] == "InputIdentityReplaced"
    assert len(calls) == 1


def test_generation_cannot_roll_back_or_change_same_intent(setup):
    c, _, _, _, calls, _ = setup
    c.reconcile_once()
    update_intent(setup, lambda i: i.update(desiredState="Stopped"))
    assert c.reconcile_once()["reason"] == "StaleOrConflictingGeneration"
    assert len(calls) == 1
    update_intent(setup, lambda i: i.update(generation=2))
    c.reconcile_once()
    assert calls[-1][1] == {"generation": 2, "desired_state": "Stopped"}
    update_intent(setup, lambda i: i.update(generation=1))
    assert c.reconcile_once()["reason"] == "StaleOrConflictingGeneration"


def test_boundary_failure_is_sanitized_and_prevents_core(setup):
    c, api, _, _, calls, _ = setup
    c.verify_boundary = lambda _: (_ for _ in ()).throw(RuntimeError("secret-token-and-URL"))
    status = c.reconcile_once()
    assert status["reason"] == "BoundaryRejected"
    assert not calls and "secret-token" not in canonical(api.objects[c.scope.status_name])


def test_ambiguous_core_failure_retains_intent_and_does_not_publish_exception(setup):
    c, api, *_ = setup
    c.core_pass = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("private-request-body"))
    assert c.reconcile_once()["reason"] == "CoreFailure"
    assert c.store.load()["intent"]["generation"] == 1
    assert "private-request-body" not in canonical(api.objects[c.scope.status_name])


def test_foreign_status_is_not_adopted_and_blocks_core(setup):
    c, api, _, _, calls, _ = setup
    api.configmap(c.scope.status_name, {"owned": "someone else"})
    result = c.reconcile_once()
    assert result["reason"] == "StatusOwnershipMismatch" and result["statusPublished"] is False
    assert not calls and not api.writes


def test_status_conflicts_are_bounded_and_never_write_desired_maps(setup):
    c, api, *_ = setup
    original = copy.deepcopy({n: api.objects[n] for n in [c.scope.profile_name, c.scope.bindings_name]})
    api.conflicts = 4
    assert c.reconcile_once()["statusPublished"] is False
    assert len(api.writes) == 3
    assert all(api.objects[n] == obj for n, obj in original.items())
    c.reconcile_once()
    assert c.scope.status_name in api.objects


def test_status_update_uses_latest_cas_and_preserves_other_metadata(setup):
    c, api, *_ = setup
    c.reconcile_once()
    obj = api.objects[c.scope.status_name]
    obj["metadata"]["annotations"] = {"example.test/keep": "value"}
    update_intent(setup, lambda i: i.update(generation=2, desiredState="Stopped"))
    api.conflicts = 1
    c.reconcile_once()
    assert api.writes[-1][1] is not None
    assert api.objects[c.scope.status_name]["metadata"]["annotations"] == {"example.test/keep": "value"}


def test_process_lifetime_lock_blocks_second_writer_during_watch(setup):
    c, api, *_ = setup
    other = Controller(api, c.scope, c.store.directory.parent, c.compile_files, c.core_pass, c.verify_boundary)

    def watch():
        with pytest.raises(Busy):
            other.reconcile_once()
        return iter(())

    api.on_watch = watch
    c.run(max_cycles=2, sleep=lambda _: None, monotonic=lambda: 0)
    assert len(api.watches) == 1


def test_watch_410_relist_and_periodic_resync_are_bounded(setup):
    c, api, _, _, calls, _ = setup
    sleeps = []
    def expired():
        api.objects[c.scope.bindings_name]["metadata"]["resourceVersion"] = "fresh-list-version"
        raise ApiError(410)
    api.on_watch = expired
    c.run(max_cycles=3, sleep=sleeps.append, monotonic=lambda: 0)
    assert len(calls) == 3
    assert [w[1] for w in api.watches] == ["12", "fresh-list-version"]
    assert sleeps == [30, 30]


def test_watch_event_requeues_changed_admin_intent_without_sleep(setup):
    c, api, _, _, calls, _ = setup
    def update():
        update_intent(setup, lambda i: i.update(generation=2, desiredState="Stopped"))
        return iter([{"type": "MODIFIED", "object": api.objects[c.scope.bindings_name]}])
    api.on_watch = update
    c.run(max_cycles=2, sleep=lambda _: pytest.fail("event should requeue"), monotonic=lambda: 0)
    assert calls[-1][1] == {"generation": 2, "desired_state": "Stopped"}


def test_api_outage_has_bounded_backoff_and_no_core_mutations(setup):
    c, api, _, _, calls, _ = setup
    api.get = lambda _: (_ for _ in ()).throw(ApiError(503))
    assert [c.reconcile_once()["retryAfterSeconds"] for _ in range(7)] == [2, 4, 8, 16, 30, 30, 30]
    assert not calls


@pytest.mark.parametrize("code,phase", [("UNAVAILABLE", "Retry"), ("PERMISSION_DENIED", "Blocked")])
def test_core_rpc_failure_classification(setup, code, phase):
    c, *_ = setup
    c.core_pass = lambda *a, **k: (_ for _ in ()).throw(RpcError(code))
    assert c.reconcile_once()["phase"] == phase


@pytest.fixture
def https_client(setup, tmp_path, monkeypatch):
    c = setup[0]
    token = tmp_path / "token"
    token.write_text("token-one")
    requests = []
    monkeypatch.setattr("saw_kubernetes.controller.ssl.create_default_context", lambda **_: "verified-context")
    def opener(request, **kwargs):
        requests.append((request, kwargs))
        return io.BytesIO(b'{"kind":"ConfigMap"}')
    client = ConfigMapClient("https://api.example.test:6443", c.scope, "/test/ca", token, opener=opener)
    return client, token, requests


def test_https_reads_rotated_projected_token_for_every_request(https_client):
    client, token, requests = https_client
    client.get(client.scope.profile_name)
    token.write_text("token-two")
    client.get(client.scope.bindings_name)
    assert [r.headers["Authorization"] for r, _ in requests] == ["Bearer token-one", "Bearer token-two"]
    assert all(kwargs["context"] == "verified-context" and kwargs["timeout"] <= 45 for _, kwargs in requests)
    assert _NoRedirect().redirect_request(None, None, 302, None, None, "https://elsewhere") is None


def test_https_client_names_and_writes_are_allowlisted(https_client):
    client, _, requests = https_client
    with pytest.raises(ContractError, match="allowlist"):
        client.get("other-configmap")
    with pytest.raises(ContractError, match="status ConfigMap"):
        client.write_status({"metadata": {"namespace": client.scope.namespace, "name": client.scope.bindings_name}})
    assert not requests


def test_https_errors_and_oversized_responses_do_not_expose_content(https_client):
    client, _, _ = https_client
    client.opener = lambda *a, **kw: (_ for _ in ()).throw(
        HTTPError("https://secret-url", 403, "private-details", {}, io.BytesIO(b"credentials")))
    with pytest.raises(ApiError) as error:
        client.get(client.scope.profile_name)
    assert str(error.value) == "Kubernetes API failure (403)"
    client.opener = lambda *a, **kw: io.BytesIO(b"x" * (MAX_BODY + 1))
    with pytest.raises(ApiError):
        client.get(client.scope.profile_name)


def test_https_watch_uses_named_field_selector_and_reports_expired_version(https_client):
    client, _, requests = https_client
    def expired(request, **kwargs):
        requests.append((request, kwargs))
        return io.BytesIO(b'{"type":"ERROR","object":{"code":410,"message":"private"}}\n')
    client.opener = expired
    with pytest.raises(ApiError) as error:
        list(client.watch(client.scope.bindings_name, "old", timeout_seconds=5))
    assert error.value.code == 410 and "private" not in str(error.value)
    assert "fieldSelector=metadata.name%3D" + client.scope.bindings_name in requests[0][0].full_url
    assert requests[0][1]["timeout"] == 10
    with pytest.raises(ContractError):
        list(client.watch(client.scope.profile_name, "old"))


@pytest.mark.parametrize("error_object", [None, [], "private-error-details"])
def test_malformed_watch_error_object_is_a_sanitized_api_failure(https_client, error_object):
    client, _, _ = https_client
    body = json.dumps({"type": "ERROR", "object": error_object}).encode() + b"\n"
    client.opener = lambda *a, **kw: io.BytesIO(body)
    with pytest.raises(ApiError) as error:
        list(client.watch(client.scope.bindings_name, "old", timeout_seconds=5))
    assert error.value.code == 0
    assert str(error.value) == "Kubernetes API failure (0)"


@pytest.mark.parametrize("change", [
    lambda i: i.update(generation=True),
    lambda i: i.update(schemaVersion=True),
    lambda i: i["bindings"].update(namespace="foreign"),
    lambda i: i["profileRef"].update(name="other"),
    lambda i: i.update(unreviewed="value"),
])
def test_invalid_admin_input_never_reaches_compiler_or_core(setup, change):
    c, _, _, compiled, calls, _ = setup
    update_intent(setup, change)
    assert c.reconcile_once()["reason"] == "InvalidInputs"
    assert not compiled and not calls


def test_plan_pin_fences_old_compiler_before_mutation(setup):
    c, _, _, _, calls, verified = setup
    update_intent(setup, lambda i: i["profileRef"].update(planSHA256="a"*64))
    c.compile_files = lambda files, bindings: {"revision": "b"*64}
    assert c.reconcile_once()["reason"] == "CompiledPlanMismatch"
    assert not calls and not verified
    c.compile_files = lambda files, bindings: {"revision": "a"*64}
    assert c.reconcile_once()["phase"] == "GenericReady"


def test_model_update_waits_for_confirmed_stop_and_recovers_after_restart(setup):
    controller, api, _, _, _, _ = setup
    calls = []
    phases = iter(["GenericReady", "Pending", "Stopped", "GenericReady", "GenericReady"])

    def core(plan, *, generation, desired_state):
        calls.append((generation, desired_state))
        return {"phase": next(phases)}

    controller.core_pass = core
    update_intent(setup, lambda i: i.update(restartGeneration=0))
    assert controller.reconcile_once()["phase"] == "GenericReady"
    update_intent(setup, lambda i: i.update(generation=2, restartGeneration=2))
    assert controller.reconcile_once()["phase"] == "Pending"
    assert not controller.store.load().get("restartGeneration")
    assert controller.reconcile_once()["phase"] == "Pending"
    resumed = Controller(api, controller.scope, controller.store.directory.parent,
                         controller.compile_files, core, controller.verify_boundary)
    assert resumed.reconcile_once()["phase"] == "GenericReady"
    update_intent(setup, lambda i: i.update(generation=3))
    assert resumed.reconcile_once()["phase"] == "GenericReady"
    assert calls == [(2, "Running"), (3, "Stopped"), (3, "Stopped"), (4, "Running"), (6, "Running")]
