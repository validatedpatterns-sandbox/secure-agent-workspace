import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "charts/saw-portal-container/files/preflight.py"
spec = importlib.util.spec_from_file_location("saw_preflight", MODULE_PATH)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def runtime_class():
    obj = {
        "metadata": {
            "name": "approved-kata",
            "uid": "runtime-uid-1",
            "labels": {"openshell.ai/sandbox-attachable": "true"},
        },
        "handler": "kata",
        "scheduling": {"nodeSelector": {"workload": "kata"}},
        "overhead": {"podFixed": {"memory": "128Mi"}},
    }
    approval = {
        "name": obj["metadata"]["name"],
        "uid": obj["metadata"]["uid"],
        "sha256": preflight.runtime_placement_digest(obj),
    }
    return obj, approval


def test_runtime_approval_passes_for_the_same_uid_handler_and_placement():
    observed, approved = runtime_class()
    assert preflight.check_runtime_class(approved, observed)


@pytest.mark.parametrize(("change", "reason"), [
    ("missing", "RuntimeClassUnavailable"),
    ("name", "RuntimeClassNameMismatch"),
    ("uid", "RuntimeClassIdentityMismatch"),
    ("handler", "RuntimeClassHandlerMismatch"),
    ("placement", "RuntimeClassPlacementChanged"),
    ("label", "RuntimeClassNotAttachable"),
    ("scheduling", "RuntimeClassSchedulingInvalid"),
    ("approval", "RuntimeClassApprovalInvalid"),
])
def test_runtime_approval_reports_the_failed_boundary(change, reason):
    observed, approved = runtime_class()
    if change == "missing":
        observed = None
    elif change == "name":
        observed["metadata"]["name"] = "other-kata"
    elif change == "uid":
        observed["metadata"]["uid"] = "replacement-uid"
    elif change == "handler":
        observed["handler"] = "runc"
    elif change == "placement":
        observed["scheduling"]["nodeSelector"]["workload"] = "general"
    elif change == "label":
        observed["metadata"]["labels"]["openshell.ai/sandbox-attachable"] = "false"
    elif change == "scheduling":
        observed["scheduling"] = {}
    elif change == "approval":
        approved["sha256"] = "bad"
    with pytest.raises(preflight.PreflightError, match=reason):
        preflight.check_runtime_class(approved, observed)


def test_runtime_approval_missing_site_binding_has_a_fixed_reason():
    observed, _ = runtime_class()
    with pytest.raises(preflight.PreflightError, match="RuntimeClassApprovalMissing"):
        preflight.check_runtime_class(None, observed)


def test_validation_policy_hash_normalizes_registration_specific_names():
    registration = "0123456789abcdef"
    installation = "11111111-1111-4111-8111-111111111111"
    slots = ["default/worker", "tools/worker"]

    def spec(reg, install):
        relays = [preflight.hashlib.sha256((reg + "/" + slot).encode()).hexdigest()[:16]
                  for slot in slots]
        return {
            "controlNamespace": "saw-ctl-" + reg,
            "installation": install,
            "gatewaySlots": ["alice-" + relay[:8] for relay in relays],
            "gateRelays": ["gate-" + relay + "-claims" for relay in relays],
            "browserProofs": ["ui-" + relay + "-browser-proof" for relay in relays],
        }

    first = preflight.validation_policy_digest(
        spec(registration, installation), "alice", registration, installation, slots)
    next_registration = "fedcba9876543210"
    next_installation = "22222222-2222-4222-8222-222222222222"
    second = preflight.validation_policy_digest(
        spec(next_registration, next_installation), "alice", next_registration,
        next_installation, slots)
    assert first == second
    assert len(first) == 64


def test_boundary_reference_fails_closed_on_missing_or_changed_hash():
    observed = "a" * 64
    assert preflight.verify_boundary_hash({"validation": observed}, "validation", observed)
    with pytest.raises(preflight.PreflightError, match="BoundaryApprovalMissing"):
        preflight.verify_boundary_hash({}, "validation", observed)
    with pytest.raises(preflight.PreflightError, match="BoundaryApprovalChanged"):
        preflight.verify_boundary_hash({"validation": "b" * 64}, "validation", observed)


@pytest.mark.parametrize(("mode", "reference"), [
    ("container", {"validation": "a" * 64, "binding": "b" * 64}),
    ("kata", {"validation": "a" * 64, "binding": "b" * 64,
               "sandboxPlacement": "c" * 64, "sandboxPlacementBinding": "d" * 64}),
])
def test_boundary_reference_requires_all_hashes_for_the_selected_mode(mode, reference):
    assert preflight.verify_boundary_reference(reference, mode)


@pytest.mark.parametrize(("mode", "reference", "reason"), [
    ("kata", {"validation": "a" * 64}, "BoundaryApprovalMissing"),
    ("kata", {"validation": "a" * 64, "binding": "b" * 64,
               "sandboxPlacement": "not-a-hash", "sandboxPlacementBinding": "d" * 64},
     "BoundaryApprovalInvalid"),
])
def test_boundary_reference_rejects_incomplete_or_malformed_hashes(mode, reference, reason):
    with pytest.raises(preflight.PreflightError, match=reason):
        preflight.verify_boundary_reference(reference, mode)


def observations():
    return {key: True for key in preflight.COMMON_CHECKS + preflight.KATA_CHECKS}


def test_all_kata_preflight_facts_must_pass():
    facts = observations()
    assert len(preflight.check_observations("kata", facts)) == len(facts)


@pytest.mark.parametrize(("fact", "reason"), [
    ("argo", "ArgoAccessDenied"),
    ("agentSandbox", "AgentSandboxUnavailable"),
    ("storage", "StorageUnavailable"),
    ("providerEgress", "ProviderEgressRejected"),
    ("registry", "RegistryUnavailable"),
    ("osc", "SandboxedContainersUnavailable"),
    ("kataConfig", "KataConfigNotReady"),
    ("workers", "KataWorkersNotReady"),
])
def test_preflight_fails_closed_on_missing_prerequisites(fact, reason):
    facts = observations()
    facts[fact] = False
    with pytest.raises(preflight.PreflightError, match=reason):
        preflight.check_observations("kata", facts)


def test_non_kata_mode_does_not_require_kata_operator_facts():
    facts = {key: True for key in preflight.COMMON_CHECKS}
    assert preflight.check_observations("container", facts) == preflight.COMMON_CHECKS


def test_known_nontraversable_workload_needs_pinned_replacement():
    source = next(iter(preflight.NON_TRAVERSABLE_WORKLOAD_IMAGES))
    replacement = "registry.example.invalid/openclaw@sha256:" + "a" * 64
    catalog = {"approved": {"workspaces": [{"enabled": True, "sandboxes": [
        {"name": "notebook", "enabled": True, "image": source},
    ]}]}}
    with pytest.raises(preflight.PreflightError, match="WorkloadImageNotNamespaceAccessible"):
        preflight.verify_profile_image_access({}, "approved", catalog)
    site = {"profileImageOverrides": {"approved": {"notebook": replacement}}}
    assert preflight.verify_profile_image_access(site, "approved", catalog)
    site["profileImageOverrides"]["approved"]["notebook"] = "openclaw:latest"
    with pytest.raises(preflight.PreflightError, match="WorkloadImageApprovalInvalid"):
        preflight.verify_profile_image_access(site, "approved", catalog)


def test_disabled_workload_does_not_require_image_replacement():
    source = next(iter(preflight.NON_TRAVERSABLE_WORKLOAD_IMAGES))
    catalog = {"approved": {"workspaces": [{"enabled": True, "sandboxes": [
        {"name": "notebook", "enabled": False, "image": source},
    ]}]}}
    assert preflight.verify_profile_image_access({}, "approved", catalog)


def site_config():
    pin = "a" * 40
    image = "registry.example.invalid/worker@sha256:" + "b" * 64
    return {
        "providerAllowHosts": ["api.example.invalid"],
        "providerPolicy": {"allowHosts": ["api.example.invalid"]},
        "automaticEnrollment": {"revision": pin, "image": image},
        "stack": {
            "policy": {"revision": pin},
            "proxy": {"revision": pin, "values": {
                "image": image,
                "network": {"bootstrapEgress": [{"to": ["api.example.invalid"]}]},
            }},
            "gateway": {"revision": pin, "values": {
                "kubernetes": {"storage": {"className": "workspace-rwx"}, "image": image},
            }},
            "audit": {"revision": pin, "values": {"storageClass": "workspace-rwx", "image": image}},
            "identity": {"revision": pin, "values": {"secretStore": "vault-backend", "image": image}},
        },
    }


def test_site_configuration_requires_pinned_sources_and_scoped_egress():
    facts = preflight.configuration_facts(site_config())
    assert facts == {
        "network": True,
        "storage": True,
        "secrets": True,
        "registry": True,
        "providerEgress": True,
        "revisions": True,
    }
    changed = site_config()
    changed["providerPolicy"]["allowHosts"] = ["*"]
    changed["stack"]["gateway"]["revision"] = "main"
    changed["stack"]["audit"]["values"]["image"] = "image:latest"
    facts = preflight.configuration_facts(changed)
    assert facts["providerEgress"] is False
    assert facts["revisions"] is False
    assert facts["registry"] is False
    missing_component = site_config()
    del missing_component["stack"]["audit"]
    assert preflight.configuration_facts(missing_component)["revisions"] is False
    invalid_network = site_config()
    invalid_network["stack"]["proxy"]["values"]["network"]["bootstrapEgress"] = "all"
    assert preflight.configuration_facts(invalid_network)["network"] is False


def test_storage_preflight_rejects_missing_class_and_accepts_default_class():
    with pytest.raises(preflight.PreflightError, match="StorageUnavailable"):
        preflight.verify_storage_classes(site_config(), [])
    default_site = {"stack": {}}
    classes = [{"metadata": {"name": "default-rwx", "annotations": {
        "storageclass.kubernetes.io/is-default-class": "true",
    }}}]
    assert preflight.verify_storage_classes(default_site, classes) == ()


def test_secret_store_must_report_ready():
    site = site_config()
    with pytest.raises(preflight.PreflightError, match="SecretServicesUnavailable"):
        preflight.verify_secret_store(site, [{"metadata": {"name": "vault-backend"},
                                               "status": {"conditions": []}}])
    assert preflight.verify_secret_store(site, [{
        "metadata": {"name": "vault-backend"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }]) == "vault-backend"


@pytest.mark.parametrize(("health", "ready"), [
    ({"initialized": True, "sealed": False}, True),
    ({"initialized": False, "sealed": False}, False),
    ({"initialized": True, "sealed": True}, False),
])
def test_vault_health_rejects_uninitialized_or_sealed_service(health, ready):
    assert preflight.vault_health_ready(health) is ready


def test_portal_chart_uses_the_shared_preflight_source():
    portal_copy = ROOT / "charts/openshell-rhdh/files/preflight.py"
    assert portal_copy.read_bytes() == MODULE_PATH.read_bytes()


@pytest.mark.parametrize(("discovery", "available"), [
    ({"groupVersion": "admissionregistration.k8s.io/v1", "resources": [
        {"name": "validatingadmissionpolicies"},
        {"name": "validatingadmissionpolicybindings"},
    ]}, True),
    ({"groupVersion": "admissionregistration.k8s.io/v1", "resources": [
        {"name": "validatingadmissionpolicies"},
    ]}, False),
    ({"groupVersion": "admissionregistration.k8s.io/v1beta1", "resources": [
        {"name": "validatingadmissionpolicies"},
        {"name": "validatingadmissionpolicybindings"},
    ]}, False),
    ({"resources": []}, False),
])
def test_admission_api_availability_uses_discovery(discovery, available):
    assert preflight.api_resources_available(
        discovery, "admissionregistration.k8s.io/v1",
        ("validatingadmissionpolicies", "validatingadmissionpolicybindings"),
    ) is available


def test_kata_platform_requires_ready_cluster_kataconfig_workers_and_apis():
    observed, approved = runtime_class()
    site = {"kataRuntimeClass": approved}
    configs = [{"status": {"conditions": [{"type": "InProgress", "status": "False"}],
                            "kataNodes": {"nodeCount": 1, "readyNodeCount": 1,
                                          "installed": ["worker-a"]}}}]
    nodes = [{
        "metadata": {"name": "worker-a", "labels": {
            "kubernetes.io/arch": "amd64", "node-role.kubernetes.io/worker": "",
            "workload": "kata",
        }},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        "spec": {},
    }]
    api_readiness = {name: True for name in (
        "kataconfigs.kataconfiguration.openshift.io", "sandboxes.agents.x-k8s.io",
        "externalsecrets.external-secrets.io", "adminnetworkpolicies.policy.networking.k8s.io",
        "admissionregistration.k8s.io/v1",
    )}
    version = {"status": {"conditions": [{"type": "Available", "status": "True"}],
                          "desired": {"version": "4.22.22"}}}
    assert preflight.verify_kata_platform(site, observed, configs, nodes,
                                          api_readiness, version) == ("worker-a",)


def test_kata_platform_rejects_no_ready_node_in_approved_placement():
    observed, approved = runtime_class()
    nodes = [{
        "metadata": {"name": "worker-a", "labels": {
            "kubernetes.io/arch": "amd64", "node-role.kubernetes.io/worker": "",
            "workload": "general",
        }},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        "spec": {},
    }]
    version = {"status": {"conditions": [{"type": "Available", "status": "True"}],
                          "desired": {"version": "4.22.22"}}}
    with pytest.raises(preflight.PreflightError, match="KataWorkersNotReady"):
        preflight.verify_kata_platform(
            {"kataRuntimeClass": approved}, observed,
            [{"status": {"conditions": [{"type": "InProgress", "status": "False"}],
                          "kataNodes": {"nodeCount": 1, "readyNodeCount": 1,
                                        "installed": ["worker-a"]}}}],
            nodes,
            {name: True for name in (
                "kataconfigs.kataconfiguration.openshift.io", "sandboxes.agents.x-k8s.io",
                "externalsecrets.external-secrets.io", "adminnetworkpolicies.policy.networking.k8s.io",
                "admissionregistration.k8s.io/v1",
            )},
            version,
        )


@pytest.mark.parametrize(("node_count", "ready_count", "in_progress"), [
    (1, 0, "True"),
    (2, 1, "False"),
    (0, 0, "False"),
])
def test_kataconfig_must_finish_on_all_selected_workers(node_count, ready_count, in_progress):
    config = {"status": {
        "conditions": [{"type": "InProgress", "status": in_progress}],
        "kataNodes": {"nodeCount": node_count, "readyNodeCount": ready_count},
    }}
    assert preflight.kata_config_ready(config) is (node_count > 0 and ready_count == node_count
                                                    and in_progress == "False")


def test_cluster_version_must_be_available_and_at_least_422():
    available = {"status": {"conditions": [{"type": "Available", "status": "True"}],
                            "desired": {"version": "4.22.22"}}}
    assert preflight.verify_cluster_version(available) == "4.22.22"
    with pytest.raises(preflight.PreflightError, match="UnsupportedOpenShiftVersion"):
        preflight.verify_cluster_version({"status": {
            "conditions": [{"type": "Available", "status": "True"}],
            "desired": {"version": "4.21.12"},
        }})
    with pytest.raises(preflight.PreflightError, match="ClusterVersionUnavailable"):
        preflight.verify_cluster_version({"status": {"desired": {"version": "4.22.22"}}})
