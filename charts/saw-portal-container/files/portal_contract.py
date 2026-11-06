"""Reusable owner-specific approval of a previously reviewed OpenShift boundary.

Grant no permissions here. Enrollment runs with named, read-only API access.
The normal runtime verifier still pins object UIDs and the full, unmodified
resource hashes after each registration; this comparison is the prerequisite.
"""
import copy
import ipaddress
import json
import re
import ssl
from saw_kubernetes.boundary import BoundaryError, fingerprint, objects


def contract(config, get):
    ns, trusted, owner = config["namespace"], config["trustedNamespace"], config["ownerID"]
    if not re.fullmatch(r"saw-ctl-[0-9a-f]{16}", trusted):
        raise BoundaryError("InvalidControlNamespace")
    output = {}
    for key,(path,field) in objects(config).items():
        obj=get(path)
        value=copy.deepcopy(obj[field])
        if key.startswith("governance"):
            # Cluster installation is shared across registrations. Keep both UID and hash.
            output[key]={"uid":obj["metadata"]["uid"],"sha256":fingerprint(value)}
            continue
        if key=="publicCA":
            source=get(f"/api/v1/namespaces/{trusted}/configmaps/{config['gateway']}-proxy-ca")
            if obj.get("metadata",{}).get("labels",{}).get("saw.redhat.com/runtime-owner")!=owner or set(value)!={"ca.crt"} or value!=source.get("data") or source["metadata"].get("deletionTimestamp"):
                raise BoundaryError("UntrustedProxyCA")
            cert=value["ca.crt"]
            if not re.fullmatch(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*",cert):
                raise BoundaryError("InvalidProxyCA")
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=cert)
            except (ssl.SSLError,ValueError) as exc:
                raise BoundaryError("InvalidProxyCA") from exc
            output[key]="equals independent trusted proxy public CA"
            continue
        if key=="gatewayService":
            ips=value.get("clusterIPs")
            if (value.get("type")!="ClusterIP" or not isinstance(ips,list) or not ips or value.get("clusterIP")!=ips[0]
                    or [("IPv4" if ipaddress.ip_address(ip).version==4 else "IPv6") for ip in ips]!=value.get("ipFamilies")):
                raise BoundaryError("InvalidServiceAllocation")
            # Only API-assigned addresses vary. Exact ports, selectors, type,
            # ipFamilies, traffic policies and all remaining fields are pinned.
            del value["clusterIP"],value["clusterIPs"]
        if key=="gateway":
            annotations=value["template"]["metadata"].get("annotations",{})
            if not re.fullmatch("[0-9a-f]{64}",annotations.get("checksum/config","")):
                raise BoundaryError("MissingConfigRolloutMarker")
            # The config itself is approved under gatewayConfig.
            del annotations["checksum/config"]
        text=json.dumps(value,sort_keys=True,separators=(",",":"))
        if "@SAW_" in text:
            raise BoundaryError("ReservedApprovalMarker")
        # Only substitutions produced by this owner's template are accepted.
        # The runtime namespace, owner login and OIDC issuer remain literal.
        text=text.replace(trusted,"@SAW_CONTROL_NS@").replace(owner,"@SAW_INSTALLATION@")
        output[key]=fingerprint(json.loads(text))
    return output


def verify_contract(config, get, expected):
    observed=contract(config,get)
    for key in set(observed)|set(expected):
        if observed.get(key)!=expected.get(key):
            raise BoundaryError("UnapprovedRegistrationResource:"+key)
