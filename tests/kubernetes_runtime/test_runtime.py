import copy
import json
import uuid

import pytest
import yaml

from saw_kubernetes import ContractError, Reconciler, RpcError, compile_profile, compile_profile_files
from saw_kubernetes.adapters import GrpcGateway, KubernetesResourceVerifier, OcReader
from saw_kubernetes.compiler import MANAGED, OWNER, canonical, digest
from saw_kubernetes.reconcile import Busy, StateStore


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "profile"
    ws = root / "default"
    ws.mkdir(parents=True)
    docs = {
        "workspace.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Workspace",
                           "metadata": {"name": "default"}},
        "providers.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Providers",
                           "spec": {"providers": []}},
        "sandbox.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Sandboxes",
                         "spec": {"sandboxes": [{"name": "toolbox", "type": "generic",
                             "image": "registry.example/sandbox@sha256:" + "a" * 64,
                             "providers": []}]}},
    }
    for name, content in docs.items():
        (ws / name).write_text(yaml.safe_dump(content))
    config = {"ownerID": "b032b2e4-2cd5-47a7-8ef8-ac73e15700b1", "namespace": "saw-alice",
              "namespaceUID": "namespace-uid", "ownerSubject": "alice-sub", "mode": "container",
              "gatewayVersion": "0.1.2-rhaiv.6", "approvedCredentialFreeProviders": ["tools"],
              "bindings": {"default/toolbox": {"workspace": {
                  "claimName": "workspace-toolbox", "uid": "pvc-uid", "readOnly": False}}}}
    return root, config


def mutate(source, filename, fn):
    path = source[0] / "default" / filename
    doc = yaml.safe_load(path.read_text())
    fn(doc)
    path.write_text(yaml.safe_dump(doc))


def sandbox(source, fn):
    mutate(source, "sandbox.yaml", lambda d: fn(d["spec"]["sandboxes"][0]))


def test_compiler_is_deterministic_and_uses_stock_driver_envelope(source):
    root, config = source
    first = compile_profile(root, config)
    assert first == compile_profile(root, json.loads(json.dumps(config, sort_keys=True)))
    sb = first["workspaces"][0]["sandboxes"][0]
    assert sb["spec"]["command"] == ["sh", "-c", "sleep infinity"]
    driver = sb["spec"]["template"]["driver_config"]["kubernetes"]
    assert driver["volumes"][0]["name"] == "saw-workspace"
    assert driver["volumes"][0]["persistent_volume_claim"] == {
        "claim_name": "workspace-toolbox", "read_only": False}
    assert driver["containers"]["agent"]["volume_mounts"] == [
        {"name": "saw-workspace", "mount_path": "/sandbox/workspace", "read_only": False}]
    assert first["claims"] == [{"name": "workspace-toolbox", "uid": "pvc-uid", "workspace": "default"}]


def test_mount_count_respects_governance_envelope(source):
    binding = source[1]["bindings"]["default/toolbox"]
    binding["mounts"] = [{"claimName": f"data-{i}", "uid": f"uid-{i}",
                          "readOnly": True, "mountPath": f"/data/model-{i}"}
                         for i in range(17)]
    with pytest.raises(ContractError, match="at most 16"):
        compile_profile(*source)
    binding["mounts"].pop()
    assert len(compile_profile(*source)["claims"]) == 17


def flat_profile(source):
    return {f"profiles__developer__default__{path.name}": path.read_text()
            for path in (source[0] / "default").iterdir()}


def test_configmap_frontend_and_directory_frontend_have_identical_plans(source):
    assert compile_profile_files(flat_profile(source), source[1]) == compile_profile(*source)


def test_profiles_cannot_claim_the_same_workspace_across_configmap_directories(source):
    files = flat_profile(source)
    files.update({key.replace("developer", "another"): value for key, value in list(files.items())})
    with pytest.raises(ContractError, match="shared SAW"):
        compile_profile_files(files, source[1])


@pytest.mark.parametrize("setting", [
    {"model": "model-that-would-be-ignored"}, {"agent": "custom-agent"},
    {"env": {"PROJECT": {"value": "example"}}},
    {"ui": {"route": False}}, {"harnessRequired": True},
])
def test_shared_valid_fields_still_require_backend_capability(source, setting):
    sandbox(source, lambda sb: sb.update(setting))
    with pytest.raises(ContractError, match="capability"):
        compile_profile(*source)


def test_invalid_yaml_does_not_echo_input_contents(source):
    files = flat_profile(source)
    files["profiles__developer__default__sandbox.yaml"] = "secret-input: [NEVER-ECHO,"
    with pytest.raises(ContractError) as exc:
        compile_profile_files(files, source[1])
    assert "NEVER-ECHO" not in str(exc.value)


@pytest.mark.parametrize("kind", ["workspace", "sandbox", "provider"])
def test_dns_name_must_match_the_whole_string(source, kind):
    if kind == "workspace":
        mutate(source, "workspace.yaml", lambda d: d["metadata"].update(name="default\n"))
    elif kind == "sandbox":
        sandbox(source, lambda sb: sb.update(name="toolbox\n"))
    else:
        mutate(source, "providers.yaml", lambda d: d["spec"]["providers"].append(
            {"name": "tools\n", "type": "tools\n", "credentialFree": True}))
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_profile_source_cannot_redirect_to_another_file(source, tmp_path):
    path = source[0] / "default" / "sandbox.yaml"
    moved = tmp_path / "outside.yaml"
    path.rename(moved)
    path.symlink_to(moved)
    with pytest.raises(ContractError, match="symlinks"):
        compile_profile(*source)


@pytest.mark.parametrize("extra", [
    {"type": "openclaw"}, {"type": "nemoclaw"}, {"harnessRef": {"name": "harness"}},
    {"env": {"TOKEN": {"secret": "inference"}}}, {"driver_config": {"hostPath": "/"}},
    {"serviceAccountName": "admin"}, {"ui": {"route": True}}, {"inference": {"providerRef": "nvidia"}},
    {"image": "registry.example/sandbox:latest"}, {"enabled": "false"},
])
def test_unported_or_privileged_profile_fails_before_rpc(source, extra):
    sandbox(source, lambda sb: sb.update(extra))
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_credential_provider_not_silently_treated_as_keyless(source):
    mutate(source, "providers.yaml", lambda d: d["spec"]["providers"].append(
        {"name": "nvidia", "type": "nvidia", "credentialSecret": "inference"}))
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_governed_credential_free_provider_compiles(source):
    mutate(source, "providers.yaml", lambda d: d["spec"]["providers"].append(
        {"name": "tools", "type": "tools", "credentialFree": True}))
    sandbox(source, lambda sb: sb.update(providers=["tools"]))
    plan = compile_profile(*source)
    assert plan["workspaces"][0]["providers"][0]["type"] == "tools"
    assert "credentials" not in canonical(plan)


@pytest.mark.parametrize("path", ["/", "/etc", "/sandbox/harness", "/data/../etc", "/data//files", "/data/", "/data/\x00"])
def test_unapproved_mount_paths_rejected(source, path):
    source[1]["bindings"]["default/toolbox"]["mounts"] = [
        {"claimName": "data", "uid": "data-uid", "readOnly": False, "mountPath": path}]
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_rw_and_ro_mount_flags_both_reach_driver(source):
    source[1]["bindings"]["default/toolbox"]["mounts"] = [
        {"claimName": "data", "uid": "data-uid", "readOnly": True, "mountPath": "/data"}]
    driver = compile_profile(*source)["workspaces"][0]["sandboxes"][0]["spec"]["template"]["driver_config"]["kubernetes"]
    assert driver["volumes"][1]["persistent_volume_claim"]["read_only"] is True
    assert driver["containers"]["agent"]["volume_mounts"][1]["read_only"] is True


def test_native_gc_workspace_is_never_implicitly_created(source):
    source[1]["bindings"] = {}
    with pytest.raises(ContractError, match="retained workspace PVC"):
        compile_profile(*source)


class FakeGateway:
    """In-memory stock RPC semantics; no claim to be live runtime validation."""

    def __init__(self):
        self.calls = []
        self.workspaces = {"default": {"metadata": {"name": "default", "id": "ws-1"},
                                       "status": {"phase": "WORKSPACE_PHASE_ACTIVE"}}}
        self.members, self.providers, self.sandboxes = {}, {}, {}
        self.fail_after_create = False
        self.sandbox_receipts = {}

    def call(self, method, request):
        self.calls.append((method, copy.deepcopy(request)))
        ws = request.get("workspace_scope", {}).get("workspace")
        key = (ws, request.get("name"))
        if method == "GetGatewayInfo":
            return {"gateway_version": "0.1.2-rhaiv.6", "compute_drivers": [{"name": "kubernetes"}]}
        if method == "GetProviderProfile":
            return {"profile": {"id": request["id"], "source": "interceptor/governance"}}
        if method == "GetWorkspace":
            if request["name"] not in self.workspaces:
                raise RpcError("NOT_FOUND")
            return {"workspace": copy.deepcopy(self.workspaces[request["name"]])}
        if method == "CreateWorkspace":
            self.workspaces[request["name"]] = {"metadata": {"name": request["name"], "id": str(uuid.uuid4()), "labels": request["labels"]},
                                               "status": {"phase": "WORKSPACE_PHASE_ACTIVE"}}
            return {"workspace": self.workspaces[request["name"]]}
        if method == "ListWorkspaceMembers":
            return {"members": self.members.get(ws, [])}
        if method == "AddWorkspaceMember":
            self.members.setdefault(ws, []).append({"principal_subject": request["principal_subject"], "role": request["role"]})
            return {}
        if method == "GetProvider":
            if key not in self.providers:
                raise RpcError("NOT_FOUND")
            return {"provider": copy.deepcopy(self.providers[key])}
        if method == "CreateProvider":
            obj = copy.deepcopy(request["provider"])
            obj["metadata"].update(workspace=ws, id=str(uuid.uuid4()))
            self.providers[(ws, obj["metadata"]["name"])] = obj
            return {"provider": obj}
        if method == "GetSandbox":
            if key not in self.sandboxes:
                raise RpcError("NOT_FOUND")
            return {"sandbox": copy.deepcopy(self.sandboxes[key])}
        if method == "CreateSandbox":
            rid = request["request_id"]
            if rid in self.sandbox_receipts:
                return {"sandbox": copy.deepcopy(self.sandbox_receipts[rid])}
            obj = {"metadata": {"name": request["name"], "workspace": ws, "id": str(uuid.uuid4()),
                                "labels": request["labels"], "annotations": request["annotations"]},
                   "spec": copy.deepcopy(request["spec"]), "status": {"phase": "SANDBOX_PHASE_PROVISIONING"}}
            self.sandboxes[key] = obj
            self.sandbox_receipts[rid] = copy.deepcopy(obj)
            if self.fail_after_create:
                self.fail_after_create = False
                raise RpcError("DEADLINE_EXCEEDED")
            return {"sandbox": obj}
        if method in {"StartSandbox", "StopSandbox"}:
            self.sandboxes[key]["status"]["phase"] = "SANDBOX_PHASE_STARTING" if method == "StartSandbox" else "SANDBOX_PHASE_STOPPING"
            return {"sandbox": self.sandboxes[key]}
        raise AssertionError(method)


@pytest.fixture
def runtime(source, tmp_path):
    plan = compile_profile(*source)
    gateway = FakeGateway()
    checks = []
    verifier = lambda p: checks.append(p["revision"])
    reconciler = Reconciler(gateway, tmp_path / "state", verifier)
    return plan, gateway, reconciler, checks


def ready(runtime):
    plan, gateway, reconciler, _ = runtime
    for _ in range(5):
        result = reconciler.reconcile(plan, generation=1)
        for sb in gateway.sandboxes.values():
            sb["status"]["phase"] = "SANDBOX_PHASE_READY"
        if result["phase"] == "GenericReady":
            return
    raise AssertionError("did not converge")


def test_reconcile_is_idempotent_and_checks_readiness(runtime):
    plan, gateway, reconciler, checks = runtime
    ready(runtime)
    before = [c for c in gateway.calls if c[0].startswith(("Create", "Add"))]
    assert reconciler.reconcile(plan, generation=1)["phase"] == "GenericReady"
    assert [c for c in gateway.calls if c[0].startswith(("Create", "Add"))] == before
    assert len(checks) >= 4
    assert not any(c[0].startswith("Delete") for c in gateway.calls)


def test_ambiguous_create_and_process_restart_do_not_duplicate(runtime):
    plan, gateway, reconciler, _ = runtime
    reconciler.reconcile(plan, generation=1)  # membership
    gateway.fail_after_create = True
    assert reconciler.reconcile(plan, generation=1)["phase"] == "Retry"
    restarted = Reconciler(gateway, reconciler.store.directory, lambda p: None)
    assert restarted.reconcile(plan, generation=1)["phase"] == "Pending"
    calls = [r["request_id"] for method, r in gateway.calls if method == "CreateSandbox"]
    assert len(calls) == 2 and len(set(calls)) == 1 and len(gateway.sandboxes) == 1


def test_stop_immediately_after_create_uses_durable_receipt(runtime):
    plan, gateway, reconciler, _ = runtime
    while not gateway.sandboxes:
        assert reconciler.reconcile(plan, generation=1)["phase"] == "Pending"
    sb = gateway.sandboxes[("default", "toolbox")]
    assert reconciler.store.load()["objectIDs"]["sandbox/default/toolbox"] == sb["metadata"]["id"]
    sb["status"]["phase"] = "SANDBOX_PHASE_READY"
    assert reconciler.reconcile(plan, generation=2, desired_state="Stopped")["phase"] == "Pending"
    assert gateway.calls[-1][0] == "StopSandbox"


def test_intent_generations_make_repeated_stop_start_unambiguous(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    sb = gateway.sandboxes[("default", "toolbox")]
    for generation, target in [(2, "Stopped"), (3, "Running"), (4, "Stopped"), (5, "Running")]:
        assert reconciler.reconcile(plan, generation=generation, desired_state=target)["phase"] == "Pending"
        assert reconciler.reconcile(plan, generation=generation, desired_state=target)["phase"] == "Pending"
        sb["status"]["phase"] = "SANDBOX_PHASE_STOPPED" if target == "Stopped" else "SANDBOX_PHASE_READY"
        assert reconciler.reconcile(plan, generation=generation, desired_state=target)["phase"] in {"Stopped", "GenericReady"}
    mutations = [r["request_id"] for m, r in gateway.calls if m in {"StartSandbox", "StopSandbox"}]
    assert len(mutations) == len(set(mutations)) == 4
    with pytest.raises(ContractError, match="stale"):
        reconciler.reconcile(plan, generation=2, desired_state="Stopped")


def test_retained_identity_detects_same_name_replacement(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    gateway.sandboxes[("default", "toolbox")]["metadata"]["id"] = "replacement-id"
    with pytest.raises(ContractError, match="same-name replacement"):
        reconciler.reconcile(plan, generation=1)


def test_foreign_object_is_not_adopted(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    gateway.sandboxes[("default", "toolbox")]["metadata"]["labels"][OWNER] = "someone-else"
    with pytest.raises(ContractError, match="another installation"):
        reconciler.reconcile(plan, generation=1)


def test_resource_verification_failure_prevents_all_rpc(runtime):
    plan, gateway, reconciler, _ = runtime
    def revoked(_):
        raise ContractError("approval revoked")
    reconciler.verify_resources = revoked
    with pytest.raises(ContractError, match="revoked"):
        reconciler.reconcile(plan, generation=1)
    assert not gateway.calls


def test_lock_prevents_second_reconciler(runtime):
    plan, _, reconciler, _ = runtime
    with reconciler.store.locked():
        with pytest.raises(Busy):
            Reconciler(reconciler.rpc, reconciler.store.directory, lambda p: None).reconcile(plan, generation=1)


def test_tampered_plan_and_owner_changes_rejected(runtime):
    plan, _, reconciler, _ = runtime
    ready(runtime)
    changed = copy.deepcopy(plan)
    changed["ownerSubject"] = "mallory"
    with pytest.raises(ContractError, match="modified compiled plan"):
        reconciler.reconcile(changed, generation=2)
    changed["revision"] = digest({k: v for k, v in changed.items() if k != "revision"})
    with pytest.raises(ContractError, match="immutable"):
        reconciler.reconcile(changed, generation=2)


def test_stopped_new_intent_does_not_briefly_start_workload(runtime):
    plan, gateway, reconciler, _ = runtime
    for _ in range(3):
        assert reconciler.reconcile(plan, generation=1, desired_state="Stopped")["phase"] == "Stopped"
    assert not gateway.sandboxes
    assert not any(method.startswith(("Create", "Add", "Start", "Stop")) for method, _ in gateway.calls)


def test_shutdown_after_attachment_revocation_only_stops_owned_objects(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    def revoked(_):
        raise ContractError("attachment revoked")
    checked = []
    reconciler.verify_resources = revoked
    reconciler.verify_shutdown = lambda p: checked.append(p["namespaceUID"])
    gateway.calls.clear()
    reconciler.reconcile(plan, generation=2, desired_state="Stopped")
    assert checked == [plan["namespaceUID"]]
    assert {m for m, _ in gateway.calls} <= {"GetGatewayInfo", "GetWorkspace", "GetSandbox", "StopSandbox"}
    assert any(m == "StopSandbox" for m, _ in gateway.calls)
    with pytest.raises(ContractError, match="revoked"):
        reconciler.reconcile(plan, generation=3, desired_state="Running")


@pytest.mark.parametrize("object_type", ["workspace", "sandbox"])
def test_shutdown_rejects_same_name_replacement(runtime, object_type):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    if object_type == "workspace":
        gateway.workspaces["default"]["metadata"]["id"] = "foreign-id"
    else:
        gateway.sandboxes[("default", "toolbox")]["metadata"]["id"] = "foreign-id"
    gateway.calls.clear()
    with pytest.raises(ContractError, match="replaced"):
        reconciler.reconcile(plan, generation=2, desired_state="Stopped")
    assert not any(m == "StopSandbox" for m, _ in gateway.calls)


def test_shutdown_without_recorded_ids_does_not_adopt_existing_sandbox(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    state = reconciler.store.load()
    state["objectIDs"] = {}
    reconciler.store.save(state)
    gateway.calls.clear()
    with pytest.raises(ContractError, match="unrecorded"):
        reconciler.reconcile(plan, generation=2, desired_state="Stopped")
    assert not any(m == "StopSandbox" for m, _ in gateway.calls)


def test_shutdown_also_covers_retained_objects_removed_from_desired_membership(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    removed = copy.deepcopy(plan)
    removed["workspaces"][0]["sandboxes"] = []
    removed["revision"] = digest({k: v for k, v in removed.items() if k != "revision"})
    gateway.calls.clear()
    reconciler.reconcile(removed, generation=2, desired_state="Stopped")
    assert any(m == "StopSandbox" and r["name"] == "toolbox" for m, r in gateway.calls)


def test_shutdown_does_not_skip_its_identity_verifier(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    def replaced(_):
        raise ContractError("namespace replaced")
    reconciler.verify_shutdown = replaced
    gateway.calls.clear()
    with pytest.raises(ContractError, match="namespace replaced"):
        reconciler.reconcile(plan, generation=2, desired_state="Stopped")
    assert not gateway.calls


@pytest.mark.parametrize("mode", ["kata", "confidential", "vm"])
def test_unsupported_backend_is_rejected_before_gateway_calls(source, mode):
    source[1]["mode"] = mode
    with pytest.raises(ContractError, match="only accepts container"):
        compile_profile(*source)


@pytest.fixture
def resources(runtime):
    plan = runtime[0]
    ns = {"metadata": {"uid": plan["namespaceUID"], "labels": {OWNER: plan["ownerID"]}}}
    pvc = {"metadata": {"uid": "pvc-uid", "labels": {OWNER: plan["ownerID"],
            "openshell.ai/sandbox-attachable": "true", "openshell.ai/sandbox-attachable-workspace": "default"},
            "annotations": {"argocd.argoproj.io/sync-options": "Prune=false,Delete=false"}},
           "spec": {"volumeMode": "Filesystem"}, "status": {"phase": "Pending"}}
    read = lambda kind, name, namespace=None: ns if kind == "namespace" else pvc
    return plan, ns, pvc, KubernetesResourceVerifier(read, lambda plan: None)


def test_pending_wffc_claim_is_admitted_without_deadlock(resources):
    plan, _, _, verifier = resources
    verifier(plan)


def test_shutdown_verifier_checks_namespace_without_reattaching_revoked_storage(resources):
    plan, ns, pvc, verifier = resources
    pvc["metadata"]["labels"]["openshell.ai/sandbox-attachable"] = "false"
    verifier.verify_boundary = lambda _: (_ for _ in ()).throw(ContractError("policy unavailable"))
    verifier.verify_shutdown(plan)
    ns["metadata"]["uid"] = "foreign"
    with pytest.raises(ContractError, match="replaced"):
        verifier.verify_shutdown(plan)


@pytest.mark.parametrize("mutation", [
    lambda p: p["metadata"].update(uid="replacement"),
    lambda p: p["metadata"].update(deletionTimestamp="now"),
    lambda p: p["metadata"].update(ownerReferences=[{"kind": "Sandbox"}]),
    lambda p: p["metadata"].update(annotations={}),
    lambda p: p["metadata"]["labels"].update({"openshell.ai/sandbox-attachable-workspace": "other"}),
    lambda p: p["spec"].update(volumeMode="Block"),
])
def test_replaced_unapproved_or_gc_owned_claim_refused(resources, mutation):
    plan, _, pvc, verifier = resources
    mutation(pvc)
    with pytest.raises(ContractError):
        verifier(plan)


def test_oc_reader_does_not_allow_secret_or_arbitrary_resource_access():
    with pytest.raises(ContractError, match="allowlist"):
        OcReader()("secret", "inference")


def test_provider_preflight_occurs_before_mutation(source, tmp_path):
    mutate(source, "providers.yaml", lambda d: d["spec"]["providers"].append(
        {"name": "tools", "type": "tools", "credentialFree": True}))
    sandbox(source, lambda sb: sb.update(providers=["tools"]))
    plan = compile_profile(*source)
    gateway = FakeGateway()
    original = gateway.call
    def request(method, body):
        if method == "GetProviderProfile":
            return {"profile": {"id": "tools", "source": "interceptor/governance", "credentials": [{"name": "key"}]}}
        return original(method, body)
    gateway.call = request
    with pytest.raises(ContractError, match="credential-free"):
        Reconciler(gateway, tmp_path / "state", lambda p: None).reconcile(plan, generation=1)
    assert not any(m.startswith(("Create", "Add")) for m, _ in gateway.calls)


def test_disappeared_sandbox_does_not_recreate_or_erase_workspace(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    del gateway.sandboxes[("default", "toolbox")]
    before = len([m for m, _ in gateway.calls if m == "CreateSandbox"])
    with pytest.raises(ContractError, match="refuse implicit recreation"):
        reconciler.reconcile(plan, generation=1)
    assert len([m for m, _ in gateway.calls if m == "CreateSandbox"]) == before


def test_spec_drift_never_triggers_delete_and_recreate(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    gateway.sandboxes[("default", "toolbox")]["spec"]["template"]["image"] = "unexpected"
    with pytest.raises(ContractError, match="migration"):
        reconciler.reconcile(plan, generation=1)
    assert not any(m.startswith("Delete") for m, _ in gateway.calls)


@pytest.mark.parametrize("extra", [
    {"environment": {"UNAPPROVED": "value"}},
    {"resource_requirements": {"gpu": {"count": 2}}},
    {"resource_requirements": {"gpu": {}}},  # Presence requests the default GPU count.
    {"log_level": "debug"},
    {"restart_policy": "SANDBOX_RESTART_POLICY_ALWAYS"},
    {"restart_policy": "SANDBOX_RESTART_POLICY_ON_FAILURE"},
    {"host_config": {"privileged": True}},
    {"future_unreviewed_field": "value"},
])
def test_unsupported_observed_spec_never_reports_ready_or_mutates(runtime, extra):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    gateway.sandboxes[("default", "toolbox")]["spec"].update(extra)
    before = len(gateway.calls)
    with pytest.raises(ContractError, match="configuration drift"):
        reconciler.reconcile(plan, generation=1)
    assert {method for method, _ in gateway.calls[before:]} <= {
        "GetGatewayInfo", "GetWorkspace", "ListWorkspaceMembers", "GetSandbox"}


def test_gateway_defaults_and_governed_policy_are_not_user_spec_drift(runtime):
    plan, gateway, reconciler, _ = runtime
    ready(runtime)
    spec = gateway.sandboxes[("default", "toolbox")]["spec"]
    spec.update(restart_policy="SANDBOX_RESTART_POLICY_NEVER",
                provider_attachment_epoch=str(uuid.uuid4()),
                policy={"version": 1}, environment={}, resource_requirements={}, log_level="")
    assert reconciler.reconcile(plan, generation=1)["phase"] == "GenericReady"
    # Provider attachment epochs are gateway-owned and can rotate independently.
    spec["provider_attachment_epoch"] = str(uuid.uuid4())
    assert reconciler.reconcile(plan, generation=1)["phase"] == "GenericReady"


@pytest.mark.parametrize("options", ["Prune=false", "Delete=false", "Prune=true,Delete=false",
                                    "Prune=false,Delete=false,Delete=true",
                                    "Prune=false,Delete=false,Prune=true"])
def test_retained_pvc_requires_prune_and_application_deletion_protection(resources, options):
    plan, _, pvc, verifier = resources
    pvc["metadata"]["annotations"]["argocd.argoproj.io/sync-options"] = options
    with pytest.raises(ContractError, match="prune and application-deletion protection"):
        verifier(plan)


def test_retained_pvc_options_allow_order_and_whitespace(resources):
    plan, _, pvc, verifier = resources
    pvc["metadata"]["annotations"]["argocd.argoproj.io/sync-options"] = "Delete=false, Prune=false"
    verifier(plan)


def test_transient_retries_have_bounded_backoff(runtime):
    plan, gateway, reconciler, _ = runtime
    def unavailable(*_):
        raise RpcError("UNAVAILABLE")
    gateway.call = unavailable
    delays = [reconciler.reconcile(plan, generation=1)["retry_after_seconds"] for _ in range(9)]
    assert delays == [2, 4, 8, 16, 32, 60, 60, 60, 60]


@pytest.mark.parametrize("endpoint", ["http://gateway:17670", "https://user:password@gateway",
    "https://gateway/path", "https://gateway?token=secret", "https://gateway:bad",
    "https://gateway:0", "https://gateway:\n443"])
def test_invalid_or_insecure_grpc_endpoint_fails_before_identity_read(endpoint):
    with pytest.raises(ContractError, match="gateway endpoint"):
        GrpcGateway(endpoint, "/does-not-exist", "/does-not-exist", "/does-not-exist")


def test_lost_sandbox_reply_cannot_create_on_stop_or_adopt_a_replacement(runtime):
    from saw_kubernetes.reconcile import MissingSandboxReceipt
    plan, gateway, core, _ = runtime
    core.reconcile(plan, generation=1)
    gateway.fail_after_create = True
    assert core.reconcile(plan, generation=1)["phase"] == "Retry"
    with pytest.raises(MissingSandboxReceipt):
        core.reconcile(plan, generation=2, desired_state="Stopped")
    assert sum(m == "CreateSandbox" for m, _ in gateway.calls) == 1
    gateway.sandboxes[("default", "toolbox")]["metadata"]["id"] = "replacement"
    with pytest.raises(ContractError, match="replacement"):
        core.reconcile(plan, generation=3)
    assert "sandbox/default/toolbox" not in core.store.load()["objectIDs"]


def test_frontend_attachment_check_preserves_standalone_boundary_requirement():
    reads = []
    boundary_calls = []
    plan = {"namespace":"saw-one", "namespaceUID":"uid", "ownerID":"owner", "claims":[], "runtimeClass":{"name":""}}
    def read(kind, name, namespace=None):
        reads.append((kind, name))
        return {"metadata":{"uid":"uid","labels":{OWNER:"owner"}}}
    verifier = KubernetesResourceVerifier(read, lambda p: boundary_calls.append(p))
    verifier.verify_attachments(plan)
    assert reads == [("namespace","saw-one")] and not boundary_calls
    verifier(plan)
    assert len(reads) == 2 and boundary_calls == [plan]
