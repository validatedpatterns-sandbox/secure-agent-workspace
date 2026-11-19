#!/usr/bin/env python3
"""Render or check a public container egress overlay using cluster observations."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import yaml

SCRIPTS = Path(__file__).resolve().parent
DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
GATEWAY = ("stack", "gateway", "values")
BOOTSTRAP = ("stack", "proxy", "values", "network", "bootstrapEgress")
RELAY = ("automaticEnrollment", "relay")


class PlainDumper(yaml.SafeDumper):
    """Write shared rules out in full: reviewers read the overlay, not anchors."""
    def ignore_aliases(self, data):
        return True


def dump(data, stream=None):
    return yaml.dump(data, stream, Dumper=PlainDumper, sort_keys=False)
AUDIT = ("stack", "audit", "values")
GATEWAY_STORAGE = GATEWAY + ("kubernetes", "storage", "className")
# CSI provisioners that serve ReadWriteMany filesystems.
SHARED_FILESYSTEM_PROVISIONERS = (
    "openshift-storage.cephfs.csi.ceph.com", "cephfs.csi.ceph.com", "nfs.csi.k8s.io",
    "efs.csi.aws.com", "file.csi.azure.com", "filestore.csi.storage.gke.io",
    "csi.trident.netapp.io", "spectrumscale.csi.ibm.com", "k8s-sigs.io/nfs-subdir-external-provisioner")
# Keep in sync with SHARED in scripts/shared-storage.sh.


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise ValueError(f"{Path(args[0]).name} {args[1]} failed; check the cluster context, probe and trust configuration")
    return result.stdout.strip()


def path_value(obj, path, default=None):
    for key in path:
        if not isinstance(obj, dict):
            raise ValueError("expected a mapping at " + ".".join(path))
        if key not in obj:
            return default
        obj = obj[key]
    return obj


def put(obj, path, value):
    for key in path[:-1]:
        obj = obj.setdefault(key, {})
    obj[path[-1]] = value


def egress(base, path, extra):
    rules = path_value(base, path, [])
    if not isinstance(rules, list):
        raise ValueError("expected an egress list at " + ".".join(path))
    # Helm replaces lists. Carry forward operator-authored governance/proxy rules.
    return rules + [rule for rule in extra if rule not in rules]


def host_rule(address, port):
    ip = ipaddress.IPv4Address(address)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ValueError("unsafe IPv4 policy destination")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid policy port")
    return {"to": [{"ipBlock": {"cidr": f"{ip}/32"}}],
            "ports": [{"protocol": "TCP", "port": port}]}


def issuer_port(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or any(ch in url for ch in ("?", "#", "\\"))
            or any(ord(ch) < 33 or ord(ch) == 127 for ch in url) or parsed.port == 0):
        raise ValueError("expected an HTTPS issuer without userinfo, query or fragment")
    return parsed.port or 443


def discover_issuer(issuer, probe, container):
    ns, sep, pod = probe.partition("/")
    if not sep or not DNS_LABEL.fullmatch(ns) or not all(DNS_LABEL.fullmatch(x) for x in pod.split(".")):
        raise ValueError("probe must be an existing namespace/pod")
    if container and not DNS_LABEL.fullmatch(container):
        raise ValueError("invalid probe container")
    port = issuer_port(issuer)
    args = ["oc", "-n", ns, "exec", "pod/" + pod]
    if container:
        args += ["-c", container]
    script = (SCRIPTS / "oidc_topology_probe.py").read_text()
    answers = json.loads(command(*args, "--", "python3", "-c", script, issuer))
    if isinstance(answers, dict):
        reason = answers.get("error")
        messages = {"dns": "in-cluster issuer DNS failed", "tls": "issuer TLS verification failed",
                    "connection": "issuer HTTPS connection failed", "discovery": "invalid issuer address or discovery document"}
        raise ValueError(messages.get(reason, "invalid in-cluster probe response")
                         if isinstance(reason, str) else "invalid in-cluster probe response")
    if not isinstance(answers, list) or not answers or not all(isinstance(a, str) for a in answers):
        raise ValueError("invalid in-cluster DNS result")
    return [host_rule(ip, port) for ip in sorted(set(answers), key=ipaddress.IPv4Address)]


def appset_controller_labels(values):
    """Pod labels of the GitOps ApplicationSet controller the projector serves."""
    namespace = (path_value(values, ("global", "vpArgoNamespace"))
                 or path_value(values, ("argo", "namespace")) or "vp-gitops")
    if not isinstance(namespace, str) or not DNS_LABEL.fullmatch(namespace):
        raise ValueError("invalid Argo CD namespace")
    # Operator-managed instances label the pod app.kubernetes.io/name=<instance>-applicationset-controller;
    # some also set app.kubernetes.io/component=applicationset-controller.
    pods = json.loads(command("oc", "get", "pods", "-n", namespace, "-o", "json"))
    names = set()
    for pod in pods.get("items", []):
        meta = pod.get("metadata", {})
        labels = meta.get("labels", {})
        name = labels.get("app.kubernetes.io/name", "")
        if not meta.get("deletionTimestamp") and (name.endswith("-applicationset-controller") or
                labels.get("app.kubernetes.io/component") == "applicationset-controller"):
            names.add(name)
    if len(names) != 1 or not DNS_LABEL.fullmatch(next(iter(names))):
        raise ValueError(f"expected one ApplicationSet controller in {namespace}; "
                         "set projection.applicationSetControllerLabels in the base file")
    return {"app.kubernetes.io/name": names.pop()}


def storage_classes():
    """The cluster's default class (RWO volumes) and a shared-filesystem class (RWX)."""
    items = json.loads(command("oc", "get", "storageclass", "-o", "json")).get("items", [])
    def is_default(item):
        notes = item.get("metadata", {}).get("annotations", {})
        return "true" in (notes.get("storageclass.kubernetes.io/is-default-class"),
                          notes.get("storageclass.beta.kubernetes.io/is-default-class"))
    defaults = sorted(i["metadata"]["name"] for i in items if is_default(i))
    shared = sorted((not is_default(i), i["metadata"]["name"]) for i in items
                    if i.get("provisioner") in SHARED_FILESYSTEM_PROVISIONERS)
    return (defaults[0] if len(defaults) == 1 else None), (shared[0][1] if shared else None)


def storage_overlay(site, out, discover):
    """Fill only storage classes the base leaves empty; explicit choices win."""
    wanted = [(GATEWAY_STORAGE, 0), (AUDIT + ("storageClass",), 0), (AUDIT + ("exchangeStorageClass",), 1)]
    for path, kind in wanted:
        if path_value(site, path[:-1]) is None or path_value(site, path):
            continue
        name = discover()[kind]
        if not name:
            raise ValueError("no " + ("default" if kind == 0 else "shared-filesystem (ReadWriteMany)")
                             + " storage class found; set " + ".".join(path) + " in the base file")
        put(out, path, name)


def container_overlay(values, probe, container=None):
    topology = json.loads(command(sys.executable, str(SCRIPTS / "network-topology.py"), "print-json"))
    api = topology["cleanupApi"]
    destinations = {(api["serviceIP"], 443)} | {(e["ip"], e["port"]) for e in api["endpoints"]}
    api_rules = [host_rule(ip, port) for ip, port in sorted(destinations)]
    dns = json.loads(command("oc", "get", "service", "dns-default", "-n", "openshift-dns", "-o", "json"))["spec"]
    peers = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}},
             "podSelector": {"matchLabels": {"dns.operator.openshift.io/daemonset-dns": "default"}}}
    if dns.get("selector", {}).get("dns.operator.openshift.io/daemonset-dns") != "default":
        raise ValueError("unrecognized OpenShift DNS Service selector")
    dns_ip = host_rule(dns["clusterIP"], 53)["to"]
    service_ports = {p["name"]: p["protocol"] for p in dns.get("ports", [])
                     if p.get("port") == 53 and p.get("protocol") in ("TCP", "UDP")}
    if set(service_ports.values()) != {"TCP", "UDP"}:
        raise ValueError("expected OpenShift DNS on TCP and UDP port 53")
    slices = json.loads(command("oc", "get", "endpointslice", "-n", "openshift-dns", "-l",
                                "kubernetes.io/service-name=dns-default", "-o", "json"))
    backends = {(p["protocol"], p["port"]) for item in slices["items"] if item.get("addressType") == "IPv4"
                for p in item.get("ports", []) if p.get("name") in service_ports
                and p.get("protocol") == service_ports[p["name"]] and type(p.get("port")) is int
                and 0 < p["port"] <= 65535}
    if {protocol for protocol, port in backends} != {"TCP", "UDP"}:
        raise ValueError("incomplete DNS EndpointSlice ports")
    dns_ports = [{"protocol": protocol, "port": 53} for protocol in ("TCP", "UDP")]
    dns_rules = [{"to": dns_ip, "ports": dns_ports},
                 {"to": [peers], "ports": [{"protocol": p, "port": n} for p, n in sorted(backends)]}]
    common = api_rules + dns_rules
    domain = json.loads(command("oc", "get", "ingress.config.openshift.io", "cluster", "-o", "json"))["spec"]["domain"]
    if not domain.startswith("apps.") or path_value(values, ("global", "clusterDomain"), domain[5:]) != domain[5:]:
        raise ValueError("clusterDomain differs from the current cluster ingress domain")
    overlay = {}
    checked = {}
    found = []
    def discover():
        if not found:
            found.append(storage_classes())
        return found[0]
    for scope in [(), ("portal",)]:
        sites = path_value(values, scope + ("containerSites",), {})
        if not isinstance(sites, dict):
            raise ValueError("containerSites must be a mapping")
        # saw-users' shared containerDefaults get the same generated rules as a site.
        entries = [(scope + ("containerSites", owner), site) for owner, site in sites.items()
                   if not (scope == () and path_value(values, ("containerDefaults",)) and not
                           (path_value(site, GATEWAY) and path_value(site, RELAY)))]
        if not scope and path_value(values, ("containerDefaults",)):
            entries.insert(0, (("containerDefaults",), path_value(values, ("containerDefaults",))))
        for target, site in entries:
            if not isinstance(site, dict) or not path_value(site, GATEWAY) or not path_value(site, RELAY):
                raise ValueError("expected gateway and automatic enrollment relay site inputs")
            raw = [path_value(site, GATEWAY + ("oidc", "issuerUrl")), path_value(site, RELAY + ("issuer",))]
            issuers = {v.replace("@DOMAIN@", domain[5:]) for v in raw if isinstance(v, str) and v}
            if len(issuers) > 1 or any(v is not None and not isinstance(v, str) for v in raw):
                raise ValueError("gateway and relay must use the same issuer")
            if issuers:
                issuer = issuers.pop()
            else:
                namespace = path_value(site, RELAY + ("keycloakNamespace",))
                if not isinstance(namespace, str) or not DNS_LABEL.fullmatch(namespace):
                    raise ValueError("expected relay Keycloak namespace")
                host = command(str(SCRIPTS / "keycloak-host.sh"), namespace)
                issuer = f"https://{host}/realms/{os.environ.get('KEYCLOAK_REALM', 'openshell')}"
            if issuer not in checked:
                checked[issuer] = discover_issuer(issuer, probe, container)
            out = {}
            for path in [GATEWAY + ("oidc", "issuerUrl"), RELAY + ("issuer",)]:
                put(out, path, issuer)
            for path in [GATEWAY + ("kubernetes", "network", "gatewayEgress"), RELAY + ("egress",)]:
                put(out, path, egress(site, path, common + checked[issuer]))
            put(out, BOOTSTRAP, egress(site, BOOTSTRAP, common))
            storage_overlay(site, out, discover)
            put(overlay, target, out)
        if not scope and entries:
            put(overlay, ("projection", "egress"), egress(values, ("projection", "egress"), common))
            # An operator-chosen selector in the base file wins; Helm merges maps.
            if not path_value(values, ("projection", "applicationSetControllerLabels")):
                put(overlay, ("projection", "applicationSetControllerLabels"), appset_controller_labels(values))
    if not overlay:
        raise ValueError("no containerSites in site values")
    return overlay


def install_values(config, owner, overlay_file, probe, container, verify):
    """Consume only managed fields from this owner's reviewed overlay."""
    site_path = ("containerSites", owner)
    paths = [("projection", "egress")] + [site_path + path for path in [
        GATEWAY + ("oidc", "issuerUrl"), RELAY + ("issuer",),
        GATEWAY + ("kubernetes", "network", "gatewayEgress"), RELAY + ("egress",), BOOTSTRAP]]
    expected = None
    if verify:
        if not probe:
            raise ValueError("SAW_TOPOLOGY_PROBE is required to check live container topology")
        base = {"global": config.get("global", {}), "projection": config.get("projection", {}),
                "containerSites": {owner: path_value(config, site_path)}}
        expected = container_overlay(base, probe, container)
    path_on_disk = Path(overlay_file)
    if not path_on_disk.exists() and verify:
        if path_value(config, site_path + ("automaticEnrollment", "enabled")) is not False:
            raise ValueError("review the generated topology overlay before enabling enrollment")
        # Link a complete file without overwriting another concurrent install's review.
        with tempfile.NamedTemporaryFile(dir=path_on_disk.parent, mode="w") as tmp:
            dump(expected, tmp)
            tmp.flush()
            try:
                os.link(tmp.name, path_on_disk)
            except FileExistsError:
                pass
    try:
        approved = yaml.safe_load(path_on_disk.read_text())
    except yaml.YAMLError:
        raise ValueError("invalid YAML in container topology overlay") from None
    if not isinstance(approved, dict):
        raise ValueError("expected a reviewed container topology overlay")
    for path in paths:
        value = path_value(approved, path)
        if value is None or (verify and value != path_value(expected, path)):
            raise ValueError("missing or stale container topology at " + ".".join(path)
                             + "; regenerate from base inputs and review the changes")
    for path in paths:
        put(config, path, path_value(approved, path))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--values-file", default=os.environ.get("SAW_USERS_VALUES_FILE"), type=Path)
    p.add_argument("--probe", default=os.environ.get("SAW_TOPOLOGY_PROBE"), help="trusted namespace/pod with Python 3 and issuer CA trust")
    p.add_argument("--container", default=os.environ.get("SAW_TOPOLOGY_CONTAINER"))
    p.add_argument("--check", type=Path, help="compare a reviewed overlay with live observations")
    args = p.parse_args()
    if not args.values_file or not args.probe:
        p.error("supply the base values file and trusted probe namespace/pod")
    try:
        found = container_overlay(yaml.safe_load(args.values_file.read_text()), args.probe, args.container)
        if args.check:
            if yaml.safe_load(args.check.read_text()) != found:
                raise ValueError("container topology drift; regenerate the overlay from the base file and review the diff")
        else:
            sys.stdout.write(dump(found))
    except yaml.YAMLError:
        p.exit(1, "Container topology check failed: invalid YAML input\n")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        p.exit(1, f"Container topology check failed: {exc}\n")


if __name__ == "__main__":
    main()
