"""Read the owner-bound public gateway CA from its workspace namespace."""
import re
import ssl


NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
OWNER = "saw.redhat.com/runtime-owner"
INVALID = "public gateway CA is missing, foreign or malformed"


def configmap_path(namespace, gateway):
    if any(not isinstance(value, str) or not NAME.fullmatch(value)
           for value in (namespace, gateway)):
        raise ValueError(INVALID)
    return f"/api/v1/namespaces/{namespace}/configmaps/{gateway}-gateway-ca"


def read_public_ca(namespace, gateway, owner_id, get):
    """Read one immutable public CA ConfigMap. Never accept an unowned map."""
    obj = get(configmap_path(namespace, gateway))
    if not isinstance(obj, dict):
        raise ValueError(INVALID)
    metadata, data = obj.get("metadata"), obj.get("data")
    if not isinstance(metadata, dict) or not isinstance(data, dict):
        raise ValueError(INVALID)
    labels = metadata.get("labels")
    ca = data.get("ca.crt")
    if (not isinstance(labels, dict) or obj.get("apiVersion") != "v1"
            or obj.get("kind") != "ConfigMap"
            or metadata.get("name") != gateway + "-gateway-ca"
            or metadata.get("namespace") != namespace
            or labels.get(OWNER) != owner_id
            or metadata.get("deletionTimestamp") or metadata.get("ownerReferences")
            or obj.get("immutable") is not True
            or set(data) != {"ca.crt"}
            or not isinstance(ca, str)
            or not re.fullmatch(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*", ca)):
        raise ValueError(INVALID)
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
    except (ssl.SSLError, ValueError):
        raise ValueError(INVALID) from None
    return ca
