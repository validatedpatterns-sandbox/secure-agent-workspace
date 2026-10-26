#!/usr/bin/env python3
"""Discover OpenShift network topology or check staged saw-users values.

Quickstart writes a temporary Helm values overlay before any cluster write.
Pattern prereqs compare effective per-user values with the same live data.
"""

import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SAW_DEFAULTS = ROOT / "charts/openshell-saw/values.yaml"
USERS_DEFAULTS = ROOT / "charts/saw-users/values.yaml"


class TopologyError(Exception):
    pass


def oc_json(*args):
    result = subprocess.run(["oc", *args, "-o", "json"], capture_output=True, text=True)
    if result.returncode:
        raise TopologyError(f"oc {' '.join(args)} failed: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise TopologyError(f"oc {' '.join(args)} returned invalid JSON: {exc}") from exc


def ipv4_cidrs(entries, field):
    result = set()
    for entry in entries:
        value = entry.get("cidr") if isinstance(entry, dict) else entry
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError) as exc:
            raise TopologyError(f"invalid {field} CIDR {value!r}: {exc}") from exc
        if network.version == 4:
            result.add(str(network))
    if not result:
        raise TopologyError(f"the cluster reports no IPv4 {field} CIDR")
    return sorted(result, key=lambda cidr: (int(ipaddress.ip_network(cidr).network_address),
                                            ipaddress.ip_network(cidr).prefixlen))


def endpoint_pairs(entries):
    pairs = set()
    if not isinstance(entries, list):
        raise TopologyError("cleanupApi.endpoints must be a list of {ip, port} objects")
    for entry in entries:
        if not isinstance(entry, dict):
            raise TopologyError("cleanupApi.endpoints must contain {ip, port} objects")
        try:
            ip = ipaddress.IPv4Address(entry.get("ip"))
            port = entry.get("port")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("port must be an integer from 1 to 65535")
        except (TypeError, ValueError, ipaddress.AddressValueError) as exc:
            raise TopologyError(f"invalid cleanupApi endpoint {entry!r}: {exc}") from exc
        pairs.add((str(ip), port))
    return sorted(pairs, key=lambda pair: (int(ipaddress.IPv4Address(pair[0])), pair[1]))


def live_topology():
    network = oc_json("get", "network.config", "cluster").get("status") or {}
    pod_cidrs = ipv4_cidrs(network.get("clusterNetwork") or [], "pod")
    service_cidrs = ipv4_cidrs(network.get("serviceNetwork") or [], "Service")

    service = oc_json("get", "service", "kubernetes", "-n", "default").get("spec") or {}
    try:
        service_ip = str(ipaddress.IPv4Address(service.get("clusterIP")))
    except (TypeError, ValueError, ipaddress.AddressValueError) as exc:
        raise TopologyError("default/kubernetes needs an IPv4 ClusterIP") from exc
    if not any(p.get("port") == 443 and p.get("protocol", "TCP") == "TCP"
               for p in service.get("ports") or []):
        raise TopologyError("default/kubernetes needs a TCP 443 Service port")

    slices = oc_json("get", "endpointslice", "-n", "default", "-l",
                     "kubernetes.io/service-name=kubernetes")
    candidates = []
    for item in slices.get("items") or []:
        if item.get("addressType") != "IPv4":
            continue
        ports = [p.get("port") for p in item.get("ports") or []
                 if p.get("protocol", "TCP") == "TCP" and p.get("port")]
        for endpoint in item.get("endpoints") or []:
            if (endpoint.get("conditions") or {}).get("ready") is False:
                continue
            for ip in endpoint.get("addresses") or []:
                for port in ports:
                    candidates.append({"ip": ip, "port": port})
    pairs = endpoint_pairs(candidates)
    if not pairs:
        raise TopologyError("default/kubernetes has no ready IPv4 EndpointSlice backend")
    return {
        "networkPolicy": {"clusterNetworkCIDRs": pod_cidrs,
                          "serviceNetworkCIDRs": service_cidrs},
        "cleanupApi": {"serviceIP": service_ip,
                       "endpoints": [{"ip": ip, "port": port} for ip, port in pairs]},
    }


def read_yaml(path):
    try:
        value = yaml.safe_load(Path(path).read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise TopologyError(f"cannot read values file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TopologyError(f"values file {path} must contain a YAML object")
    return value


def merge(base, overlay):
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = value
    return result


def cidrs_match(configured, actual):
    try:
        networks = {str(ipaddress.IPv4Network(cidr, strict=True)) for cidr in configured}
    except (TypeError, ValueError, ipaddress.AddressValueError):
        return False
    return networks == set(actual)


def topology_snippet(live):
    return yaml.safe_dump({"defaults": {"openshellSaw": live}}, sort_keys=False).rstrip()


def discover(output, overlay_paths):
    live = live_topology()
    if overlay_paths:
        if isinstance(overlay_paths, (str, Path)):
            overlay_paths = [overlay_paths]
        for overlay_path in overlay_paths:
            overlay = read_yaml(overlay_path)
            for section, keys in (("networkPolicy", ("clusterNetworkCIDRs", "serviceNetworkCIDRs")),
                                  ("cleanupApi", ("serviceIP", "endpoints"))):
                supplied = overlay.get(section) or {}
                if not isinstance(supplied, dict):
                    raise TopologyError(f"{section} in {overlay_path} must be an object")
                for key in keys:
                    if key not in supplied:
                        continue
                    got = supplied[key]
                    expected = live[section][key]
                    if key == "endpoints":
                        same = endpoint_pairs(got) == endpoint_pairs(expected)
                    elif key.endswith("CIDRs"):
                        same = set(got) == set(expected) if isinstance(got, list) else False
                    else:
                        same = got == expected
                    if not same:
                        raise TopologyError(
                            f"{overlay_path} sets {section}.{key}={got!r}, but the cluster reports "
                            f"{expected!r}; remove or correct that override")
    Path(output).write_text(json.dumps(live, indent=2) + "\n")
    print("Discovered cluster pod/Service CIDRs and exact Kubernetes API endpoints.")


def control_plane_nodes_exist():
    nodes = oc_json("get", "nodes", "-l", "node-role.kubernetes.io/control-plane")
    return bool(nodes.get("items"))


def check_pattern(values_path):
    live = live_topology()
    defaults = read_yaml(USERS_DEFAULTS)
    site = read_yaml(values_path)
    users_values = merge(defaults, site)
    saw_defaults = read_yaml(SAW_DEFAULTS)
    bad = []
    enabled = []
    has_control_plane = None
    for user in users_values.get("users") or []:
        name = user.get("name", "<unnamed>")
        saw = merge(saw_defaults, users_values.get("defaults", {}).get("openshellSaw") or {})
        prune = user.get("pruneOnRemove", users_values.get("pruneOnRemove", False))
        saw["cleanupOnDelete"] = bool(prune)
        saw = merge(saw, user.get("values") or {})
        np = saw.get("networkPolicy") or {}
        api = saw.get("cleanupApi") or {}
        configured_pairs = endpoint_pairs(api.get("endpoints") or [])
        live_pairs = endpoint_pairs(live["cleanupApi"]["endpoints"])
        if np.get("enabled"):
            enabled.append(name)
            if not cidrs_match(np.get("clusterNetworkCIDRs"),
                               live["networkPolicy"]["clusterNetworkCIDRs"]):
                bad.append(f"saw-{name}: pod CIDRs differ from the live pod network")
            if not cidrs_match(np.get("serviceNetworkCIDRs"),
                               live["networkPolicy"]["serviceNetworkCIDRs"]):
                bad.append(f"saw-{name}: Service CIDRs differ from the live Service network")
            if api.get("serviceIP") != live["cleanupApi"]["serviceIP"]:
                bad.append(f"saw-{name}: cleanupApi.serviceIP differs from default/kubernetes")
            if configured_pairs != live_pairs:
                bad.append(f"saw-{name}: cleanupApi.endpoints differ from live EndpointSlices")
        elif saw.get("cleanupOnDelete"):
            if configured_pairs and configured_pairs != live_pairs:
                bad.append(f"saw-{name}: cleanupApi.endpoints differ from live EndpointSlices")
            elif not configured_pairs:
                if has_control_plane is None:
                    has_control_plane = control_plane_nodes_exist()
                if not has_control_plane:
                    bad.append(f"saw-{name}: hosted control plane cleanup needs cleanupApi.endpoints")
    if bad:
        raise TopologyError("Network topology preflight failed:\n- " + "\n- ".join(bad) +
                            "\nSet these values under defaults.openshellSaw in " + str(values_path) +
                            " (per-user values override defaults):\n" + topology_snippet(live))
    if enabled:
        print("Network topology verified for " + ", ".join(f"saw-{name}" for name in enabled))
    else:
        print("NetworkPolicy is staged off for every pattern user. Before enabling one, "
              "audit its in-cluster egress and add the live values:\n" + topology_snippet(live))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    discover_parser = sub.add_parser("discover")
    discover_parser.add_argument("--output", required=True)
    discover_parser.add_argument("--values-file", action="append", default=[])
    pattern_parser = sub.add_parser("check-pattern")
    pattern_parser.add_argument("--values-file", default=str(ROOT / "overrides/saw-users.yaml"))
    sub.add_parser("print-json")
    args = parser.parse_args()
    try:
        if args.action == "discover":
            discover(args.output, args.values_file)
        elif args.action == "print-json":
            print(json.dumps(live_topology()))
        else:
            check_pattern(args.values_file)
    except TopologyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
