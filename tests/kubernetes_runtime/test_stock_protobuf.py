"""Real pinned SDK serialization with an in-memory gRPC channel, no sockets.

Run via kubernetes-runtime/test-stock-protobuf.py; ordinary unit runs skip this
module when the generated stock SDK has not been provisioned.
"""

import copy
import os

import pytest

if os.environ.get("SAW_STOCK_SDK_TESTS") != "1":
    pytest.skip("run test-stock-protobuf.py for pinned SDK wire-contract coverage", allow_module_level=True)

import grpc
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.message_factory import GetMessageClass
from openshell._proto import openshell_pb2

from saw_kubernetes import ContractError, Reconciler, RpcError, compile_profile
from saw_kubernetes.adapters import GrpcGateway, RPC_METHODS
from .test_runtime import FakeGateway, mutate, sandbox, source


class WireError(grpc.RpcError):
    def __init__(self, name):
        self.name = name

    def code(self):
        return getattr(grpc.StatusCode, self.name)

    def details(self):
        return "sensitive arbitrary server detail must not escape"


class WireChannel:
    """Execute generated stub serializers and real request/response descriptors."""

    def __init__(self, backend):
        self.backend, self.calls, self.closed = backend, [], False

    def unary_unary(self, path, request_serializer, response_deserializer, **kwargs):
        name = path.rsplit("/", 1)[1]
        descriptor = openshell_pb2.DESCRIPTOR.services_by_name["OpenShell"].methods_by_name[name]
        request_type = GetMessageClass(descriptor.input_type)
        response_type = GetMessageClass(descriptor.output_type)

        def invoke(request, timeout):
            serialized = request_serializer(request)
            body = MessageToDict(request_type.FromString(serialized), preserving_proto_field_name=True)
            self.calls.append((name, copy.deepcopy(body), timeout, serialized))
            try:
                response = self.backend.call(name, body)
            except RpcError as exc:
                raise WireError(exc.code) from None
            message = ParseDict(response, response_type(), ignore_unknown_fields=False)
            return response_deserializer(message.SerializeToString())

        return invoke

    # The generated OpenShell service also defines streams; this reconciler's
    # allowlist does not use them, so attempts fail instead of silently stubbing.
    def unary_stream(self, *args, **kwargs):
        return lambda *_args, **_kwargs: pytest.fail("stream outside reconciler surface")

    stream_stream = unary_stream
    stream_unary = unary_stream

    def close(self):
        self.closed = True


@pytest.fixture
def transport(tmp_path, monkeypatch):
    backend = FakeGateway()
    channel = WireChannel(backend)
    supplied = {}

    def credentials(roots, key, certificate):
        supplied.update(roots=roots, key=key, certificate=certificate)
        return "mock-mtls-credentials"

    def connect(target, identity):
        supplied.update(target=target, identity=identity)
        return channel

    monkeypatch.setattr(grpc, "ssl_channel_credentials", credentials)
    monkeypatch.setattr(grpc, "secure_channel", connect)
    for filename, value in [("ca", "root"), ("cert", "client"), ("key", "private")]:
        (tmp_path / filename).write_text(value)
    adapter = GrpcGateway("https://gateway.saw.svc:17670", tmp_path / "ca", tmp_path / "cert",
                          tmp_path / "key", timeout=12)
    return adapter, backend, channel, supplied


def test_all_allowed_requests_are_stock_protobuf_methods():
    methods = openshell_pb2.DESCRIPTOR.services_by_name["OpenShell"].methods_by_name
    for name in RPC_METHODS:
        assert name in methods
        assert not methods[name].client_streaming and not methods[name].server_streaming
        assert getattr(openshell_pb2, name + "Request").DESCRIPTOR == methods[name].input_type


def test_generated_stub_uses_tls_inputs_and_deadline(transport):
    adapter, _, channel, supplied = transport
    result = adapter.call("GetGatewayInfo", {})
    assert result["gateway_version"] == "0.1.2-rhaiv.6"
    assert supplied == {"roots": b"root", "key": b"private", "certificate": b"client",
                        "target": "gateway.saw.svc:17670", "identity": "mock-mtls-credentials"}
    assert channel.calls[-1][:3] == ("GetGatewayInfo", {}, 12)
    adapter.close()
    assert channel.closed


def test_unknown_field_rejected_before_sending_and_errors_are_sanitized(transport):
    adapter, _, channel, _ = transport
    with pytest.raises(ContractError, match="protobuf API"):
        adapter.call("GetWorkspace", {"name": "default", "secret": "do-not-send"})
    assert channel.calls == []
    with pytest.raises(RpcError) as error:
        adapter.call("GetWorkspace", {"name": "absent"})
    assert str(error.value) == "NOT_FOUND"
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize("workspace", ["default", "research"])
def test_create_observe_stop_restart_roundtrips_real_stock_messages(source, transport, tmp_path, workspace):
    mutate(source, "providers.yaml", lambda d: d["spec"]["providers"].append(
        {"name": "tools", "type": "tools", "credentialFree": True}))
    sandbox(source, lambda sb: sb.update(providers=["tools"]))
    if workspace != "default":
        mutate(source, "workspace.yaml", lambda d: d["metadata"].update(name=workspace))
        (source[0] / "default").rename(source[0] / workspace)
        source[1]["bindings"][f"{workspace}/toolbox"] = source[1]["bindings"].pop("default/toolbox")
    plan = compile_profile(*source)
    adapter, backend, channel, _ = transport
    reconciler = Reconciler(adapter, tmp_path / "state", lambda _: None)
    for generation, desired, expected in [(1, "Running", "GenericReady"), (2, "Stopped", "Stopped"),
                                          (3, "Running", "GenericReady")]:
        for _ in range(12):
            status = reconciler.reconcile(plan, generation=generation, desired_state=desired)
            if status["phase"] == expected:
                break
            # Explicit fake driver progress, separate from gateway acceptance.
            for instance in backend.sandboxes.values():
                phase = instance["status"]["phase"]
                if phase in {"SANDBOX_PHASE_PROVISIONING", "SANDBOX_PHASE_STARTING"}:
                    instance["status"]["phase"] = "SANDBOX_PHASE_READY"
                elif phase == "SANDBOX_PHASE_STOPPING":
                    instance["status"]["phase"] = "SANDBOX_PHASE_STOPPED"
        assert status["phase"] == expected
    names = {name for name, *_ in channel.calls}
    assert {"CreateProvider", "CreateSandbox", "AddWorkspaceMember", "StartSandbox", "StopSandbox"} <= names
    assert ("CreateWorkspace" in names) == (workspace != "default")
    create = next(body for name, body, *_ in channel.calls if name == "CreateSandbox")
    assert create["spec"]["template"]["driver_config"]["kubernetes"]["volumes"][0][
        "persistent_volume_claim"]["read_only"] is False
    # Mutation IDs survive exact wire serialization, including retries.
    assert len(create["request_id"]) == 36
    assert backend.sandboxes[(workspace, "toolbox")]["status"]["phase"] == "SANDBOX_PHASE_READY"


def test_wire_deadline_after_create_is_observed_after_reconciler_restart(source, transport, tmp_path):
    plan = compile_profile(*source)
    adapter, backend, channel, _ = transport
    reconciler = Reconciler(adapter, tmp_path / "state", lambda _: None)
    reconciler.reconcile(plan, generation=1)
    backend.fail_after_create = True
    status = reconciler.reconcile(plan, generation=1)
    assert status["phase"] == "Retry" and status["reason"] == "DEADLINE_EXCEEDED"
    original_id = backend.sandboxes[("default", "toolbox")]["metadata"]["id"]
    restarted = Reconciler(adapter, tmp_path / "state", lambda _: None)
    assert restarted.reconcile(plan, generation=1)["phase"] == "Pending"
    creates = [body for name, body, *_ in channel.calls if name == "CreateSandbox"]
    assert len(creates) == 2 and creates[0]["request_id"] and creates[0] == creates[1]
    assert list(backend.sandbox_receipts) == [creates[0]["request_id"]]
    assert list(backend.sandboxes) == [("default", "toolbox")]
    assert backend.sandboxes[("default", "toolbox")]["metadata"]["id"] == original_id
    assert restarted.store.load()["objectIDs"]["sandbox/default/toolbox"] == original_id


@pytest.mark.parametrize("extra", [
    {"environment": {"UNAPPROVED": "value"}},
    {"resource_requirements": {"gpu": {}}},
    {"restart_policy": "SANDBOX_RESTART_POLICY_ALWAYS"},
])
def test_wire_normalized_defaults_accepted_but_unsupported_spec_drift_rejected(source, transport, tmp_path, extra):
    plan = compile_profile(*source)
    adapter, backend, _, _ = transport
    reconciler = Reconciler(adapter, tmp_path / "state", lambda _: None)
    reconciler.reconcile(plan, generation=1)  # membership
    reconciler.reconcile(plan, generation=1)  # create
    instance = backend.sandboxes[("default", "toolbox")]
    instance["status"]["phase"] = "SANDBOX_PHASE_READY"
    instance["spec"].update(restart_policy="SANDBOX_RESTART_POLICY_NEVER",
                           provider_attachment_epoch="00000000-0000-4000-8000-000000000001",
                           policy={"version": 1})
    assert reconciler.reconcile(plan, generation=1)["phase"] == "GenericReady"
    instance["spec"].update(extra)
    with pytest.raises(ContractError, match="configuration drift"):
        reconciler.reconcile(plan, generation=1)
