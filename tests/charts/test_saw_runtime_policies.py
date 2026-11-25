"""Offline guardrails for native runtime policies; no cluster/CEL/CNI claim.

Helm rejects unsafe/missing inputs. The packet cases exercise the rendered
ordered ANP rules, including ports and peer scope, against a small reference
interpreter. Kubernetes CEL type checking and live OVN enforcement remain
required integration tests described in the chart README.
"""

import ipaddress
import shutil
from pathlib import Path

import pytest
import yaml
from helm_cache import run_helm

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/saw-runtime-policies"
HELM = shutil.which("helm")
APIS = (
    "policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy",
    "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy",
)
pytestmark = [pytest.mark.ci_external, pytest.mark.skipif(not HELM, reason="helm is not installed")]


def helm_template(*args, enabled=True, apis=APIS):
    command = [HELM, "template", "runtime-test", str(CHART)]
    if enabled:
        command += ["-f", str(CHART / "tests/container-values.yaml")]
    for api in apis:
        command += ["--api-versions", api]
    return run_helm(command + list(args), capture_output=True, text=True)


def render(*args, **kwargs):
    result = helm_template(*args, **kwargs)
    assert result.returncode == 0, result.stderr
    return {doc["kind"]: doc for doc in yaml.safe_load_all(result.stdout) if doc}


def rejected(tmp_path, values, message=None):
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(values))
    result = helm_template("-f", str(path))
    assert result.returncode != 0, values
    if message:
        assert message in result.stderr, result.stderr


def test_disabled_chart_requires_no_apis_and_creates_nothing():
    assert render(enabled=False, apis=()) == {}


@pytest.mark.parametrize("api", APIS)
def test_missing_native_api_fails_before_render(api):
    result = helm_template(apis=tuple(candidate for candidate in APIS if candidate != api))
    assert result.returncode != 0
    assert "API is required" in result.stderr


def test_only_native_policies_with_exact_namespace_and_supervisor_scope():
    docs = render()
    assert set(docs) == {"AdminNetworkPolicy", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
    anp, vap, binding = (docs[kind] for kind in (
        "AdminNetworkPolicy", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"))
    ns = {"matchLabels": {"kubernetes.io/metadata.name": "saw-alice"}}
    assert anp["spec"]["subject"] == {"pods": {
        "namespaceSelector": ns,
        "podSelector": {"matchLabels": {
            "openshell.ai/boundary-role": "supervisor",
            "openshell.ai/gateway-id": "saw-alice-gateway"}},
    }}
    assert "ingress" not in anp["spec"]
    assert anp["spec"]["priority"] == 70
    assert vap["spec"]["failurePolicy"] == "Fail"
    assert vap["spec"]["matchConstraints"]["namespaceSelector"] == ns
    assert vap["spec"]["matchConstraints"]["resourceRules"] == [{
        "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}]
    assert binding["spec"]["matchResources"]["namespaceSelector"] == ns
    assert binding["spec"]["policyName"] == vap["metadata"]["name"]
    assert binding["spec"]["validationActions"] == ["Deny"]
    for kind, doc in docs.items():
        assert "namespace" not in doc["metadata"]
        assert doc["metadata"]["annotations"]["argocd.argoproj.io/sync-options"] == "Prune=false"
        assert int(doc["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"]) < 0
        assert not any(key in doc["spec"] for key in ["mutate", "mutations", "generate"]), kind


def test_approved_traffic_passes_to_stock_network_policy_and_everything_else_denied():
    rules = render()["AdminNetworkPolicy"]["spec"]["egress"]
    assert all(rule["action"] == "Pass" and rule["ports"] for rule in rules[:-1])
    assert rules[-1] == {"name": "deny-other-egress", "action": "Deny",
                         "to": [{"networks": ["0.0.0.0/0", "::/0"]}]}
    assert all(rule["action"] != "Allow" for rule in rules)


def label_match(selector, labels):
    # Fixtures intentionally use exact matchLabels. This is a test interpreter,
    # not an implementation of the full Kubernetes LabelSelector language.
    assert set(selector) == {"matchLabels"}
    return all(labels.get(key) == value for key, value in selector["matchLabels"].items())


def peer_match(peer, ip, namespace, labels):
    if "networks" in peer:
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for cidr in peer["networks"])
    ns = {"kubernetes.io/metadata.name": namespace}
    if "namespaces" in peer:
        return label_match(peer["namespaces"], ns)
    return (label_match(peer["pods"]["namespaceSelector"], ns)
            and label_match(peer["pods"]["podSelector"], labels))


def packet_action(anp, *, ip, namespace="outside", labels=None, port=443, protocol="TCP"):
    for rule in anp["spec"]["egress"]:
        if "ports" in rule and not any(
            entry["portNumber"] == {"port": port, "protocol": protocol} for entry in rule["ports"]
        ):
            continue
        if any(peer_match(peer, ip, namespace, labels or {}) for peer in rule["to"]):
            return rule["action"]
    return None


@pytest.mark.parametrize("packet,expected", [
    ({"ip": "192.0.2.10"}, "Pass"),
    ({"ip": "2001:db8::10"}, "Pass"),
    ({"ip": "192.0.2.10", "port": 22}, "Deny"),
    ({"ip": "192.0.2.10", "protocol": "UDP"}, "Deny"),
    ({"ip": "192.0.2.11"}, "Deny"),
    ({"ip": "2001:db8::11"}, "Deny"),
    ({"ip": "10.2.0.3", "namespace": "saw-alice", "labels": {
        "openshell.ai/boundary-role": "workload"}, "port": 5500}, "Pass"),
    ({"ip": "10.2.0.3", "namespace": "saw-bob", "labels": {
        "openshell.ai/boundary-role": "workload"}, "port": 5500}, "Deny"),
    ({"ip": "10.2.0.3", "namespace": "saw-alice", "labels": {
        "openshell.ai/boundary-role": "supervisor"}, "port": 5500}, "Deny"),
    ({"ip": "10.2.0.3", "namespace": "saw-alice", "labels": {
        "openshell.ai/boundary-role": "workload"}, "port": 22}, "Deny"),
    ({"ip": "10.2.0.4", "namespace": "openshift-dns", "labels": {
        "dns.operator.openshift.io/daemonset-dns": "default"}, "port": 5353, "protocol": "UDP"}, "Pass"),
    ({"ip": "10.2.0.4", "namespace": "openshift-dns", "labels": {},
      "port": 5353, "protocol": "UDP"}, "Deny"),
])
def test_rendered_anp_destination_and_port_boundaries(packet, expected):
    assert packet_action(render()["AdminNetworkPolicy"], **packet) == expected


def expressions(docs):
    return [" ".join(entry["expression"].split())
            for entry in docs["ValidatingAdmissionPolicy"]["spec"]["validations"]]


def test_container_mode_requires_default_runtime_for_both_roles():
    checks = expressions(render())
    for role in ["workload", "supervisor"]:
        assert (f"variables.role != '{role}' || !has(object.spec.runtimeClassName) || "
                "object.spec.runtimeClassName == ''") in checks


def test_supervisor_accepts_stock_gateway_names_only():
    validations = render()["ValidatingAdmissionPolicy"]["spec"]["validations"]
    rule, = [item["expression"] for item in validations
             if item["message"] == "Supervisor executable, TLS projection and token must match the stock contract."]
    assert "'OPENSHELL_GATEWAY_TLS_SERVER_NAME'" in rule
    assert "'OPENSHELL_GATEWAY_NAME'" in rule
    assert "object.spec.containers[0].env.all(e, e.name in [" in rule
    assert "AWS_SECRET_ACCESS_KEY" not in rule


def supervisor_rule(*args):
    validations = render(*args)["ValidatingAdmissionPolicy"]["spec"]["validations"]
    rule, = [" ".join(item["expression"].split()) for item in validations
             if item["message"] == "Supervisor executable, TLS projection and token must match the stock contract."]
    return rule


def test_supervisor_may_carry_only_the_configured_ocsf_collector():
    assert "OPENSHELL_OTLP" not in supervisor_rule()
    rule = supervisor_rule("--set", "ocsfEndpoint=http://saw-ocsf-collector.openshell-agents.svc:4317")
    assert "'OPENSHELL_OTLP_OCSF_ENDPOINT'" in rule
    assert ("e.name != 'OPENSHELL_OTLP_OCSF_ENDPOINT' || "
            "e.value == \"http://saw-ocsf-collector.openshell-agents.svc:4317\"") in rule
    assert "OPENSHELL_OTLP_ENDPOINT'" not in rule  # traces stay off
    assert "OPENSHELL_OTLP_AGENT_ENDPOINT" not in rule


def test_supervisor_may_carry_only_the_configured_agent_trace_collector():
    collector = "http://saw-ocsf-collector.openshell-agents.svc:4317"
    rule = supervisor_rule("--set", "ocsfEndpoint=" + collector, "--set", "agentTraceEndpoint=" + collector)
    assert "'OPENSHELL_OTLP_AGENT_ENDPOINT'" in rule
    assert f"e.name != 'OPENSHELL_OTLP_AGENT_ENDPOINT' || e.value == \"{collector}\"" in rule
    assert "OPENSHELL_OTLP_AGENT_PROTOCOL" not in rule   # gRPC: the gateway sets no protocol


def test_supervisor_may_carry_a_numeric_attach_timeout():
    """OpenShell 0.1.10 passes a configured attach timeout (Kata: 900 s) to the
    supervisor; only a plain number of seconds is admitted."""
    rule = supervisor_rule()
    assert "'OPENSHELL_ATTACH_REQUEST_TIMEOUT_SECONDS'" in rule
    assert ("e.name != 'OPENSHELL_ATTACH_REQUEST_TIMEOUT_SECONDS' || "
            "(has(e.value) && e.value.matches('^[1-9][0-9]{0,4}$'))") in rule


def test_identity_fences_cover_creation_and_label_removal_on_update():
    vap = render()["ValidatingAdmissionPolicy"]["spec"]
    variables = {item["name"]: item["expression"] for item in vap["variables"]}
    assert "oldObject != null" in variables["previousRole"]
    assert "oldObject != null" in variables["previousSandboxAccount"]
    assert "variables.previousSandboxAccount" in variables["runtimePod"]
    assert "variables.previousRole in ['workload', 'supervisor']" in variables["runtimePod"]
    checks = expressions(render())
    assert any("variables.previousRole == variables.role" in check for check in checks)
    assert any('request.userInfo.username == "system:serviceaccount:saw-alice:saw-alice-gateway"'
               in check for check in checks)
    assert any("r.kind == 'Sandbox'" in check for check in checks)
    assert all("r.controller" not in check for check in checks if "r.kind == 'Sandbox'" in check)  # stock supervisor owner is non-controlling
    assert any("variables.sandboxAccount && variables.role in ['workload', 'supervisor']" in check for check in checks)


@pytest.mark.parametrize("namespace", ["", "default", "openshift-dns", "openshift", "kube-system", "kube-public", "kube-node-lease", "kube-custom", "ALL", "a" * 51])
def test_empty_global_or_system_namespace_is_rejected(tmp_path, namespace):
    rejected(tmp_path, {"targetNamespace": namespace}, "targetNamespace")


@pytest.mark.parametrize("values", [
    {"gatewayId": ""}, {"gatewayServiceAccount": ""}, {"sandboxServiceAccount": ""},
    {"network": {"priority": None}}, {"network": {"priority": -1}},
    {"network": {"priority": 100}}, {"network": {"priority": 1.5}},
    {"network": {"egress": []}}, {"mode": "confidential"},
    {"mode": "kata"}, {"mode": "kata", "kata": {"workloadRuntimeClassName": "bad/class"}},
    {"kata": {"workloadRuntimeClassName": "kata"}},
    {"kata": {"supervisorRuntimeClassName": "kata"}},
    {"kata": {"kyvernoMutationEnabled": True}},
])
def test_missing_or_unsupported_inputs_fail_closed(tmp_path, values):
    rejected(tmp_path, values)


@pytest.mark.parametrize("rule", [
    {"name": "bad", "to": [{}], "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]},
    {"name": "bad", "to": [{"namespaces": {}}], "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]},
    {"name": "bad", "to": [{"pods": {"namespaceSelector": {}, "podSelector": {}}}],
     "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]},
    {"name": "bad", "to": [{"networks": ["0.0.0.0/0"]}], "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]},
    {"name": "bad", "to": [{"networks": ["::/0"]}], "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]},
    {"name": "bad", "to": [{"networks": ["192.0.2.0/24"]}], "ports": []},
    {"name": "bad", "to": [{"networks": ["192.0.2.0/24"]}], "ports": [{"portNumber": {"protocol": "TCP", "port": 0}}]},
    {"name": "bad", "to": [{"networks": ["192.0.2.0/24"]}], "ports": [{"portNumber": {"protocol": "TCP", "port": 65536}}]},
    {"name": "bad", "to": [{"networks": ["192.0.2.0/24"]}], "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}], "action": "Allow"},
    {"name": "deny-other-egress", "to": [{"networks": ["192.0.2.0/24"]}], "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]},
])
def test_policy_cannot_be_widened_with_empty_selectors_or_caller_actions(tmp_path, rule):
    rejected(tmp_path, {"network": {"egress": [rule]}})


def test_duplicate_rule_names_are_rejected(tmp_path):
    rule = {"name": "same", "to": [{"networks": ["192.0.2.0/24"]}],
            "ports": [{"portNumber": {"protocol": "TCP", "port": 443}}]}
    rejected(tmp_path, {"network": {"egress": [rule, rule]}}, "must be unique")


def test_priority_zero_is_a_valid_explicit_allocation():
    assert render("--set", "network.priority=0")["AdminNetworkPolicy"]["spec"]["priority"] == 0


def test_gateway_proxy_identity_requires_pinned_statefulset_and_controller():
    checks = expressions(render())
    assert any("r.kind == 'StatefulSet'" in c and "r.controller" in c and
               'r.name == "saw-alice-gateway-gateway"' in c for c in checks)
    assert any("variables.previousGatewayClaim == variables.gatewayClaim" in c for c in checks)
    assert any("system:serviceaccount:kube-system:statefulset-controller" in c and
               "request.operation != 'CREATE'" in c for c in checks)


def test_kata_enforces_reviewed_runtime_at_sandbox_and_pod():
    result = helm_template("--set", "mode=kata", "--set", "workloadRuntimeClassName=saw-kata")
    assert result.returncode == 0, result.stderr
    policies = [d["spec"] for d in yaml.safe_load_all(result.stdout)
                if d and d["kind"] == "ValidatingAdmissionPolicy"]
    assert len(policies) == 2
    for policy in policies:
        assert policy["failurePolicy"] == "Fail"
        checks = [entry["expression"] for entry in policy["validations"]]
        resource = policy["matchConstraints"]["resourceRules"][0]["resources"][0]
        if resource == "sandboxes":
            assert any('podTemplate.spec.runtimeClassName == "saw-kata"' in check for check in checks)
        else:
            assert resource == "pods"
            assert any('object.spec.runtimeClassName == "saw-kata"' in check for check in checks)
            # The supervisor runs in a Kata VM of its own, never the default runtime.
            assert any("variables.role != 'supervisor' || (has(object.spec.runtimeClassName) && "
                       'object.spec.runtimeClassName == "saw-kata")' in check for check in checks)
            assert not any("variables.role != 'supervisor' || !has(object.spec.runtimeClassName)" in check
                           for check in checks)


@pytest.mark.parametrize("packet,expected", [
    ({"ip": "203.0.113.7"}, "Pass"),                       # a public provider API on 443
    ({"ip": "203.0.113.7", "port": 80}, "Deny"),
    ({"ip": "10.20.30.40"}, "Deny"),                       # private ranges stay closed
    ({"ip": "172.16.0.9"}, "Deny"),
    ({"ip": "192.168.1.1"}, "Deny"),
    ({"ip": "169.254.169.254"}, "Deny"),                   # cloud metadata
    ({"ip": "192.0.2.10"}, "Pass"),                        # explicit rules still apply first
])
def test_public_https_lets_supervisors_reach_providers_but_not_private_networks(packet, expected):
    anp = render("--set", "network.publicHTTPS=true")["AdminNetworkPolicy"]
    assert packet_action(anp, **packet) == expected


def test_public_https_is_off_by_default():
    assert packet_action(render()["AdminNetworkPolicy"], ip="203.0.113.7") == "Deny"
