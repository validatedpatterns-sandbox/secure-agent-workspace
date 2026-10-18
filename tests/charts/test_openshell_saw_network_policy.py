"""NetworkPolicy isolation and EgressFirewall port parity for each SAW."""

import ipaddress
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/openshell-saw"
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def helm_template(*args):
    return subprocess.run(
        [HELM, "template", "saw-test", str(CHART), "-n", "saw-alice",
         "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
         "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
         "--set", "sandboxName=saw-test", *args],
        capture_output=True, text=True,
    )


def render(*args):
    result = helm_template(*args)
    assert result.returncode == 0, result.stderr
    return {(doc["kind"], doc["metadata"]["name"]): doc
            for doc in yaml.safe_load_all(result.stdout) if doc}


def rejected(tmp_path, value, message):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump({"networkPolicy": value}))
    result = helm_template("-f", str(path))
    assert result.returncode != 0, value
    assert message in result.stderr, result.stderr


def policies(docs):
    return {name: doc for (kind, name), doc in docs.items() if kind == "NetworkPolicy"}


def by_port(rules, port, protocol="TCP"):
    return [rule for rule in rules if {"port": port, "protocol": protocol} in rule.get("ports", [])]


def only_peer(rule):
    assert len(rule["to"]) == 1
    return rule["to"][0]


def test_default_deny_and_policy_scopes():
    docs = render()
    ps = policies(docs)
    assert set(ps) == {"saw-default-deny", "saw-vm", "saw-credential-proxy",
                       "saw-cdi-import", "saw-cleanup-hook", "saw-credential-proxy-ca-hook"}
    for doc in ps.values():
        assert doc["apiVersion"] == "networking.k8s.io/v1"
        assert "namespace" not in doc["metadata"]
        if doc["metadata"]["name"] != "saw-credential-proxy-ca-hook":
            assert doc["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "-1"
            assert doc["metadata"]["labels"]["app.kubernetes.io/part-of"] == "openshell-cnv-fedora"
    assert ps["saw-default-deny"]["spec"] == {
        "podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
    vm_labels = docs[("VirtualMachine", "saw-test")]["spec"]["template"]["metadata"]["labels"]
    assert vm_labels["openshell.pattern/role"] == "gateway"
    assert ps["saw-vm"]["spec"]["podSelector"]["matchLabels"] == {
        "openshell.pattern/role": vm_labels["openshell.pattern/role"]}
    vm_ingress = ps["saw-vm"]["spec"]["ingress"]
    assert by_port(vm_ingress, 22) == [{"from": [{
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-cnv"}},
        "podSelector": {"matchLabels": {"kubevirt.io": "virt-api"}}}],
        "ports": [{"protocol": "TCP", "port": 22}]}]
    assert ps["saw-cdi-import"]["spec"]["podSelector"] == {
        "matchLabels": {"app": "containerized-data-importer"}}
    assert ps["saw-cleanup-hook"]["spec"]["podSelector"] == {
        "matchLabels": {"openshell.pattern/role": "cleanup"}}
    assert ps["saw-cleanup-hook"]["spec"]["policyTypes"] == ["Egress"]
    assert ps["saw-cleanup-hook"]["spec"]["egress"] == [
        {"to": [{"ipBlock": {"cidr": "172.30.0.1/32"}}],
         "ports": [{"protocol": "TCP", "port": 443}]},
        {"to": [{"ipBlock": {"cidr": "192.0.2.10/32"}}],
         "ports": [{"protocol": "TCP", "port": 6443}]},
    ]
    assert docs[("Pod", "saw-test-cleanup")]["metadata"]["labels"]["openshell.pattern/role"] == "cleanup"
    assert docs[("Pod", "saw-test-cleanup")]["spec"]["activeDeadlineSeconds"] == 240
    script = docs[("Pod", "saw-test-cleanup")]["spec"]["containers"][0]["command"][-1]
    assert "--connect-timeout 5 --max-time 20" in script
    assert "returned HTTP" in script and "|| true" not in script.split("for pvc in")[1]
    shell = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
    assert shell.returncode == 0, shell.stderr


def test_cleanup_api_firewall_exception_survives_network_policy_rollback():
    api_rule = {"type": "Allow", "to": {"cidrSelector": "192.0.2.10/32"},
        "ports": [{"protocol": "TCP", "port": 6443}]}
    def firewall_rules(*args):
        return render(*args)[("EgressFirewall", "default")]["spec"]["egress"]
    assert firewall_rules().count(api_rule) == 1
    assert api_rule in firewall_rules("--set", "networkPolicy.enabled=false")
    assert api_rule not in firewall_rules("--set", "cleanupOnDelete=false")
    fallback = firewall_rules("--set", "networkPolicy.enabled=false",
                              "--set-json", "cleanupApi.endpoints=[]")
    assert {"type": "Allow", "to": {"nodeSelector": {"matchLabels": {
        "node-role.kubernetes.io/control-plane": ""}}},
        "ports": [{"protocol": "TCP", "port": 6443}]} in fallback


def test_topology_is_required_for_standalone_chart(tmp_path):
    bare = subprocess.run([HELM, "template", "saw-test", str(CHART), "-n", "saw-alice",
                           "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml")],
                          capture_output=True, text=True)
    assert bare.returncode != 0
    assert "networkPolicy.clusterNetworkCIDRs must be a non-empty list" in bare.stderr
    for overlay, error in (
        ({"networkPolicy": {"clusterNetworkCIDRs": []}}, "clusterNetworkCIDRs"),
        ({"networkPolicy": {"serviceNetworkCIDRs": []}}, "serviceNetworkCIDRs"),
        ({"cleanupApi": {"serviceIP": ""}}, "cleanupApi.serviceIP is required"),
        ({"cleanupApi": {"endpoints": []}}, "cleanupApi.endpoints is required"),
        ({"cleanupApi": {"serviceIP": "not-an-ip"}}, "must be an IPv4 CIDR"),
        ({"cleanupApi": {"endpoints": [{"ip": "192.0.2.10", "port": 65536}]}},
         "invalid TCP port"),
    ):
        path = tmp_path / "topology.yaml"
        path.write_text(yaml.safe_dump(overlay))
        result = helm_template("-f", str(path))
        assert result.returncode != 0 and error in result.stderr, (overlay, result.stderr)
    assert not policies(render("--set", "networkPolicy.enabled=false",
                               "--set-json", "cleanupApi.endpoints=[]"))


def test_hosted_api_on_tcp_443_is_exactly_scoped(tmp_path):
    path = tmp_path / "hosted.yaml"
    path.write_text(yaml.safe_dump({"cleanupApi": {
        "serviceIP": "172.30.0.1", "endpoints": [{"ip": "198.51.100.20", "port": 443}]},
        "source": {"httpURL": "https://images.example.net/disk.qcow2"}}))
    docs = render("-f", str(path))
    firewall = docs[("EgressFirewall", "default")]["spec"]["egress"]
    assert {"type": "Allow", "to": {"cidrSelector": "198.51.100.20/32"},
            "ports": [{"protocol": "TCP", "port": 443}]} in firewall
    assert not any(rule["to"].get("nodeSelector", {}).get("matchLabels", {}).get(
        "node-role.kubernetes.io/control-plane") == "" for rule in firewall[1:])
    for name in ("saw-vm", "saw-cdi-import"):
        outside = next(rule for rule in policies(docs)[name]["spec"]["egress"]
                       if rule["to"][0].get("ipBlock", {}).get("cidr") == "0.0.0.0/0")
        assert "198.51.100.20/32" in outside["to"][0]["ipBlock"]["except"]
    assert {"to": [{"ipBlock": {"cidr": "198.51.100.20/32"}}],
            "ports": [{"protocol": "TCP", "port": 443}]} in policies(docs)["saw-cleanup-hook"]["spec"]["egress"]


def test_governance_selector_tracks_engine():
    expected = {"namespaceSelector": {"matchLabels": {
        "kubernetes.io/metadata.name": "openshell-agents"}},
        "podSelector": {"matchLabels": {
            "app.kubernetes.io/name": "apf",
            "app.kubernetes.io/instance": "governance-interceptor"}}}
    for flag in ("global.governance.engine=apf", "governance.engine=apf"):
        vm = policies(render("--set", flag))["saw-vm"]["spec"]
        assert only_peer(by_port(vm["egress"], 18081)[0]) == expected


@pytest.mark.parametrize("source,expected", [
    ({}, None),
    ({"httpURL": "http://images.example.net:8081/disk.qcow2"}, ("images.example.net", 8081)),
    ({"registryURL": "docker://images.example.net:5443/disk:1", "pullMethod": "node"}, None),
    ({"registryURL": "docker://images.example.net:5443/disk:1", "pullMethod": "pod"},
     ("images.example.net", 5443)),
    ({"dataSource": "openshell-gateway"}, None),
    ({"goldenImageURL": "https://images.example.net/disk.qcow2"}, ("images.example.net", 443)),
])
def test_cdi_outside_rule_follows_selected_disk_source(tmp_path, source, expected):
    path = tmp_path / "source.yaml"
    path.write_text(yaml.safe_dump({"source": source}))
    docs = render("-f", str(path))
    firewall = docs[("EgressFirewall", "default")]["spec"]["egress"]
    cdi = policies(docs)["saw-cdi-import"]["spec"]
    outside = [rule for rule in cdi["egress"]
               if rule["to"][0].get("ipBlock", {}).get("cidr") == "0.0.0.0/0"]
    if expected is None:
        assert not outside
    else:
        host, port = expected
        assert len(outside) == 1
        assert outside[0]["ports"] == [{"protocol": "TCP", "port": port}]
        assert {"type": "Allow", "to": {"dnsName": host},
                "ports": [{"protocol": "TCP", "port": port}]} in firewall


def test_vm_egress_is_exact_and_cdi_import_has_minimum_peers():
    ps = policies(render())
    vm = ps["saw-vm"]["spec"]
    assert vm["policyTypes"] == ["Ingress", "Egress"]
    egress = vm["egress"]
    assert by_port(egress, 5353, "UDP") == by_port(egress, 5353, "TCP")
    assert only_peer(by_port(egress, 5353, "UDP")[0]) == {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}}}
    assert only_peer(by_port(egress, 18081)[0]) == {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshell-agents"}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "governance-interceptor"}}}
    registry = {"namespaceSelector": {"matchLabels": {
        "kubernetes.io/metadata.name": "openshift-image-registry"}},
        "podSelector": {"matchLabels": {"docker-registry": "default"}}}
    assert only_peer(by_port(egress, 5000)[0]) == registry
    assert not by_port(egress, 8443)
    assert not by_port(egress, 8080)
    router = {"namespaceSelector": {"matchLabels": {
        "policy-group.network.openshift.io/ingress": ""}}, "podSelector": {}}
    assert any(router == only_peer(r) for r in by_port(egress, 443) if "ipBlock" not in only_peer(r))
    cdi = ps["saw-cdi-import"]["spec"]
    assert cdi["ingress"] == [{"from": [{"namespaceSelector": {"matchLabels": {
        "kubernetes.io/metadata.name": "openshift-cnv"}}}]}]
    assert only_peer(by_port(cdi["egress"], 5000)[0]) == registry
    assert by_port(cdi["egress"], 5353, "UDP")
    assert not any("ipBlock" in peer for rule in cdi["egress"] for peer in rule["to"])


def test_no_high_risk_allow_peers_or_ports():
    for spec in (policies(render())[name]["spec"] for name in ("saw-vm", "saw-cdi-import")):
        for direction, peer_key in (("egress", "to"), ("ingress", "from")):
            for rule in spec.get(direction, []):
                assert rule.get(peer_key), (direction, rule)
                assert all(peer for peer in rule[peer_key])
                assert all(port["port"] != 6443 for port in rule.get("ports", []))
                for peer in rule[peer_key]:
                    ns = peer.get("namespaceSelector", {}).get("matchLabels", {})
                    selected_ns = str(ns.get("kubernetes.io/metadata.name", ""))
                    assert not selected_ns.startswith("saw-") or selected_ns == "saw-keycloak"
                    assert peer.get("namespaceSelector") != {}
                    if "ipBlock" in peer:
                        block = peer["ipBlock"]
                        assert block["cidr"] == "0.0.0.0/0"
                        assert block["except"]
                        for excluded in ("10.128.0.0/14", "172.30.0.0/16", "169.254.0.0/16",
                                         "192.0.2.10/32"):
                            assert ipaddress.ip_network(excluded).subnet_of(
                                ipaddress.ip_network(block["cidr"]))
                            assert excluded in block["except"]
        assert not by_port(spec["egress"], 6443)
    cleanup = policies(render())["saw-cleanup-hook"]["spec"]["egress"]
    assert cleanup and all(rule.get("to") and rule.get("ports") for rule in cleanup)
    assert {peer["ipBlock"]["cidr"] for rule in cleanup for peer in rule["to"]} == {
        "172.30.0.1/32", "192.0.2.10/32"}


def test_route_ingress_ports_match_service_and_sandbox_ui(tmp_path):
    path = tmp_path / "ui.yaml"
    path.write_text(yaml.safe_dump({"sandboxUi": [
        {"workspace": "default", "sandbox": "notebook", "proxyPort": 4201, "forwardPort": 14201}]}))
    docs = render("-f", str(path))
    vm = policies(docs)["saw-vm"]["spec"]
    [router_rule] = by_port(vm["ingress"], 17670)
    assert router_rule["from"] == [{"namespaceSelector": {"matchLabels": {
        "policy-group.network.openshift.io/ingress": ""}}, "podSelector": {}}]
    ports = {p["port"] for p in router_rule["ports"]}
    service = docs[("Service", "saw-test-gateway")]["spec"]
    names = {p["name"]: p["port"] for p in service["ports"]}
    routes = [d for (kind, _), d in docs.items() if kind == "Route"]
    assert ports == {names[r["spec"]["port"]["targetPort"]] for r in routes}
    assert ports == {17670, 18789, 8080, 4201}
    assert 22 not in ports


def test_toggles_and_custom_namespaces():
    assert not policies(render("--set", "networkPolicy.enabled=false"))
    assert set(policies(render("--set", "egress.enabled=false"))) == {
        "saw-default-deny", "saw-vm", "saw-credential-proxy", "saw-cdi-import",
        "saw-cleanup-hook", "saw-credential-proxy-ca-hook"}
    assert "saw-cleanup-hook" not in policies(render("--set", "cleanupOnDelete=false"))
    assert ("Pod", "saw-test-cleanup") not in render("--set", "cleanupOnDelete=false")
    for flag, port in (("dns", 5353), ("governanceInterceptor", 18081),
                       ("internalRegistry", 5000)):
        vm = policies(render("--set", f"networkPolicy.allow.{flag}=false"))["saw-vm"]["spec"]
        assert not by_port(vm["egress"], port, "UDP" if port == 5353 else "TCP"), flag
    vm = policies(render("--set", "networkPolicy.allow.ingressController=false"))["saw-vm"]["spec"]
    assert len(vm["ingress"]) == 1 and by_port(vm["ingress"], 22)
    assert not any("namespaceSelector" in p and "policy-group.network.openshift.io/ingress" in
                   p["namespaceSelector"].get("matchLabels", {})
                   for rule in vm["egress"] for p in rule["to"])
    vm = policies(render("--set", "governance.enabled=false"))["saw-vm"]["spec"]
    assert not by_port(vm["egress"], 18081)
    vm = policies(render("--set", "governance.namespace=policy-system"))["saw-vm"]["spec"]
    assert only_peer(by_port(vm["egress"], 18081)[0])["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "policy-system"}
    vm = policies(render("--set-string", "oidc.issuerUrl=https://id.example.net/realms/x"))["saw-vm"]["spec"]
    assert not by_port(vm["egress"], 8443)


@pytest.mark.parametrize("value,message", [
    ({"clusterNetworkCIDRs": []}, "clusterNetworkCIDRs must be a non-empty list"),
    ({"serviceNetworkCIDRs": []}, "serviceNetworkCIDRs must be a non-empty list"),
    ({"clusterNetworkCIDRs": ["10.999.0.0/14"]}, "octet above 255"),
    ({"serviceNetworkCIDRs": ["172.30.0.0/33"]}, "invalid prefix"),
    ({"extraBlockedCIDRs": ["not-a-cidr"]}, "must be an IPv4 CIDR"),
    ({"extraEgress": {}}, "extraEgress must be a list"),
    ({"extraIngress": {}}, "extraIngress must be a list"),
    ({"extraEgress": [{}]}, "non-empty to list"),
    ({"extraIngress": [{"from": [{}]}]}, "empty allow-all peer"),
    ({"extraEgress": [{"to": [{"namespaceSelector": {}}]}]}, "empty namespaceSelector"),
    ({"extraEgress": [{"to": [{"namespaceSelector": {"matchLabels": {}}}]}]}, "empty namespaceSelector"),
    ({"extraIngress": [{"from": [{"namespaceSelector": {"matchExpressions": []}}]}]}, "empty namespaceSelector"),
    ({"extraEgress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]},
     "allow-all ipBlock without except"),
    ({"extraIngress": [{"from": [{"ipBlock": {"cidr": "::/0"}}]}]},
     "allow-all ipBlock without except"),
    ({"externalPorts": [65536]}, "invalid TCP port"),
])
def test_render_guards(tmp_path, value, message):
    rejected(tmp_path, value, message)


def test_extra_rules_and_cidrs_render(tmp_path):
    path = tmp_path / "safe.yaml"
    path.write_text(yaml.safe_dump({"networkPolicy": {
        "clusterNetworkCIDRs": ["10.232.0.0/14"],
        "serviceNetworkCIDRs": ["172.231.0.0/16"],
        "extraBlockedCIDRs": ["100.64.0.0/10"],
        "extraEgress": [{"to": [{"namespaceSelector": {"matchLabels": {
            "kubernetes.io/metadata.name": "models"}},
            "podSelector": {"matchLabels": {"app": "vllm"}}}],
            "ports": [{"port": 8000, "protocol": "TCP"}]}],
        "extraIngress": [{"from": [{"podSelector": {"matchLabels": {"app": "test"}}}],
                          "ports": [{"port": 8080, "protocol": "TCP"}]}],
        "externalPorts": [8443]}}))
    vm = policies(render("-f", str(path)))["saw-vm"]["spec"]
    assert by_port(vm["egress"], 8000)
    assert len(vm["ingress"]) == 3
    outside = next(r for r in vm["egress"] if "ipBlock" in r["to"][0])
    assert set(outside["to"][0]["ipBlock"]["except"]) == {
        "10.232.0.0/14", "172.231.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
        "192.0.2.10/32"}
    assert {p["port"] for p in outside["ports"]} == {443, 80, 8443}


@pytest.mark.parametrize("args", [
    (),
    ("--set-string", "oidc.issuerUrl=https://id.example.net:8443/realms/x"),
    ("--set-string", "source.httpURL=http://images.example.net:8081/disk.qcow2"),
    ("--set-string", "source.registryURL=docker://images.example.net:5443/disk:1",
     "--set", "source.pullMethod=pod"),
])
def test_firewall_ports_are_in_network_policy_outside_rule(args):
    docs = render(*args)
    firewall = docs[("EgressFirewall", "default")]["spec"]["egress"]
    firewall_ports = {p["port"] for rule in firewall if rule["type"] == "Allow"
                      and rule["to"].get("cidrSelector") != "192.0.2.10/32"
                      for p in rule["ports"]}
    vm = policies(docs)["saw-vm"]["spec"]
    outside = next(r for r in vm["egress"] if "ipBlock" in r["to"][0])
    np_ports = {p["port"] for p in outside["ports"]}
    assert firewall_ports <= np_ports, f"EgressFirewall ports {firewall_ports - np_ports} missing from networkPolicy outside rule"
