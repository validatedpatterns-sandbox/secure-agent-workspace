"""Offline, non-secret platform manifests for the autonomous SAW blueprint.

Rendering is deliberately separate from enrollment authorization and apply. No
Kubernetes, Vault or registry client is used here. Tenant ownership, Vault roles,
source readiness and image provenance must be checked before deployment.
"""

import hashlib
import json
import re
from copy import deepcopy
from urllib.parse import urlsplit

import yaml

API_VERSION = "saw.redhat.com/v1alpha1"
MAX_DOCUMENT_BYTES = 512 * 1024
LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
KEY = r"[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*"


class ValidationError(ValueError):
    """An invalid non-secret authoring document (never echo input values)."""


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValidationError("YAML mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_document(text):
    """Read one bounded YAML/JSON document, rejecting duplicate keys/aliases."""
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValidationError("document exceeds 512 KiB")
    try:
        depth = 0
        for token in yaml.scan(text):
            if isinstance(token, yaml.AliasToken | yaml.AnchorToken):
                raise ValidationError("YAML anchors and aliases are not supported")
            if isinstance(token, yaml.BlockMappingStartToken | yaml.BlockSequenceStartToken
                          | yaml.FlowMappingStartToken | yaml.FlowSequenceStartToken):
                depth += 1
            elif isinstance(token, yaml.BlockEndToken | yaml.FlowMappingEndToken | yaml.FlowSequenceEndToken):
                depth -= 1
            if depth > 64:
                raise ValidationError("YAML nesting exceeds 64 levels")
        value = yaml.load(text, Loader=_UniqueLoader)
    except (yaml.YAMLError, RecursionError):
        raise ValidationError("invalid YAML document") from None
    if not isinstance(value, dict):
        raise ValidationError("document must be a mapping")
    return value


def fields(value, allowed, required, path):
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ValidationError(f"{path} must be a mapping")
    if set(value) - set(allowed):
        raise ValidationError(f"unexpected field in {path}")
    if set(required) - set(value):
        raise ValidationError(f"missing required field in {path}")
    return value


def string(value, path, pattern=None, limit=253):
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or (pattern and not re.fullmatch(pattern, value))):
        raise ValidationError(f"invalid {path}")
    return value


def name(value, path):
    return string(value, path, LABEL, 63)


def https_url(value, path):
    string(value, path, limit=2048)
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and not parsed.username
                 and not parsed.password and not parsed.query and not parsed.fragment)
        _ = parsed.port  # Access validates malformed/out-of-range port syntax.
    except ValueError:
        valid = False
    if not valid:
        raise ValidationError(f"{path} must be HTTPS without credentials/query/fragment")
    return value


def kv_path(value, path):
    return string(value, path, r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*")


def _header(document, kind):
    fields(document, {"apiVersion", "kind", "metadata", "spec"},
           {"apiVersion", "kind", "metadata", "spec"}, "document")
    if document["apiVersion"] != API_VERSION or document["kind"] != kind:
        raise ValidationError("unsupported document apiVersion/kind")
    fields(document["metadata"], {"name"}, {"name"}, "metadata")
    name(document["metadata"]["name"], "metadata.name")


def enrollment_identity(owner, saw_id):
    """The full identity hash excludes the mutable display username."""
    encoded = json.dumps([owner["issuer"], owner["subject"], saw_id],
                         separators=(",", ":"), ensure_ascii=False)
    # Match Go/Helm toRawJson, including the two JSONP-sensitive Unicode separators.
    encoded = encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_enrollment(document):
    _header(document, "SawEnrollment")
    spec = deepcopy(document["spec"])
    fields(spec, {"owner", "vault", "credentials", "image"},
           {"owner", "vault", "credentials", "image"}, "spec")
    owner = fields(spec["owner"], {"issuer", "subject", "username"},
                   {"issuer", "subject", "username"}, "owner")
    https_url(owner["issuer"], "owner.issuer")
    string(owner["subject"], "owner.subject", limit=512)
    name(owner["username"], "owner.username")
    vault = fields(spec["vault"],
                   {"server", "mount", "prefix", "authMount", "audience", "caConfigMap"},
                   {"server", "mount", "prefix", "authMount", "audience", "caConfigMap"},
                   "vault")
    https_url(vault["server"], "vault.server")
    for key in ("mount", "prefix", "authMount"):
        kv_path(vault[key], f"vault.{key}")
    string(vault["audience"], "vault.audience", KEY)
    name(vault["caConfigMap"], "vault.caConfigMap")
    credentials = spec["credentials"]
    if not isinstance(credentials, list) or not credentials or len(credentials) > 64:
        raise ValidationError("credentials must contain 1 to 64 provider definitions")
    seen = set()
    for item in credentials:
        fields(item, {"name", "remoteKey", "properties"},
               {"name", "remoteKey", "properties"}, "credential")
        credential = string(item["name"], "credential.name", LABEL, 40)
        if credential in seen:
            raise ValidationError("duplicate credential name")
        seen.add(credential)
        # Provider account identifier only: no tenant-controlled absolute paths.
        name(item["remoteKey"], "credential.remoteKey")
        props = item["properties"]
        if not isinstance(props, dict) or not props or len(props) > 32:
            raise ValidationError("credential.properties must contain 1 to 32 keys")
        for key, value in props.items():
            string(key, "credential target key", KEY)
            # Flat keys only: avoid provider-specific JSON selector syntax.
            string(value, "credential remote property", r"[a-zA-Z_][a-zA-Z0-9_]*")
    spec["credentials"] = sorted(credentials, key=lambda item: item["name"])
    image = fields(spec["image"], {"namespace", "dataSource", "diskSizeGi", "storageClass"},
                   {"namespace", "dataSource", "diskSizeGi"}, "image")
    for key in ("namespace", "dataSource"):
        name(image[key], f"image.{key}")
    if "storageClass" in image:
        name(image["storageClass"], "image.storageClass")
    size = image["diskSizeGi"]
    if type(size) is not int or not 1 <= size <= 16384:
        raise ValidationError("image.diskSizeGi must be an integer between 1 and 16384")
    identity = enrollment_identity(owner, document["metadata"]["name"])
    # Independent of username so a rename cannot silently allocate a new SAW.
    namespace = f"saw-{document['metadata']['name'][:33]}-{identity[:24]}"
    if namespace == image["namespace"]:
        raise ValidationError("tenant and image namespaces must be separate")
    return {"namespace": namespace, "identity": identity,
            "sawId": document["metadata"]["name"], **spec}


def _resource(api, kind, resource_name, namespace=None, **body):
    metadata = {"name": resource_name,
                "labels": {"app.kubernetes.io/managed-by": "saw-blueprint"}}
    if namespace:
        metadata["namespace"] = namespace
    return {"apiVersion": api, "kind": kind, "metadata": metadata, **body}


def render_enrollment(document, part="tenant"):
    """Render a single authority's manifest set, never applying anything.

    tenant: namespace/ESO. clone-access: SOURCE permissions for the named
    tenant provisioner. root: DV submitted AS that provisioner. vault: policy
    and role payloads for a platform admin to review/install in Vault.
    """
    cfg = validate_enrollment(document)
    ns, vault, owner, image = (cfg[key] for key in ("namespace", "vault", "owner", "image"))
    # A display-name rename must never select another tenant's Vault subtree.
    prefix = f"{vault['prefix']}/{cfg['identity']}/providers"
    if part == "vault":
        paths = sorted({f"{vault['mount']}/data/{prefix}/{c['remoteKey']}"
                        for c in cfg["credentials"]})
        return {"namespace": ns, "enrollmentIdentity": cfg["identity"],
                "policyName": ns,
                "policy": {"path": {p: {"capabilities": ["read"]} for p in paths}},
                "authMount": vault["authMount"], "roleName": ns,
                "role": {"bound_service_account_names": ["saw-vault-reader"],
                         "bound_service_account_namespaces": [ns],
                         "audience": vault["audience"], "token_policies": [ns],
                         "token_ttl": "5m", "token_max_ttl": "15m"}}
    if part == "clone-access":
        role_name = f"saw-clone-{cfg['identity'][:24]}"
        return [
            _resource("rbac.authorization.k8s.io/v1", "Role", role_name, image["namespace"],
                      rules=[{"apiGroups": ["cdi.kubevirt.io"], "resources": ["datasources"],
                              "resourceNames": [image["dataSource"]], "verbs": ["get"]},
                             {"apiGroups": ["cdi.kubevirt.io"],
                              "resources": ["datavolumes/source"], "verbs": ["create"]}]),
            _resource("rbac.authorization.k8s.io/v1", "RoleBinding", role_name, image["namespace"],
                      roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                               "name": role_name},
                      subjects=[{"kind": "ServiceAccount", "name": "saw-provisioner",
                                 "namespace": ns}]),
        ]
    if part == "root":
        storage = {"accessModes": ["ReadWriteOnce"],
                   "resources": {"requests": {"storage": f"{image['diskSizeGi']}Gi"}}}
        if "storageClass" in image:
            storage["storageClassName"] = image["storageClass"]
        return [_resource("cdi.kubevirt.io/v1beta1", "DataVolume", "saw-root", ns,
                          spec={"sourceRef": {"kind": "DataSource", "name": image["dataSource"],
                                              "namespace": image["namespace"]},
                                "storage": storage})]
    if part != "tenant":
        raise ValidationError("unsupported enrollment render part")
    namespace = _resource("v1", "Namespace", ns)
    namespace["metadata"]["annotations"] = {
        "saw.redhat.com/enrollment-identity": cfg["identity"],
        "saw.redhat.com/owner-subject": owner["subject"],
        "saw.redhat.com/owner-issuer": owner["issuer"],
        "saw.redhat.com/vault-user-path": prefix,
    }
    resources = [namespace]
    for sa in ("saw-vault-reader", "saw-provisioner"):
        resources.append(_resource("v1", "ServiceAccount", sa, ns,
                                   automountServiceAccountToken=False))
    resources.extend([
        _resource("networking.k8s.io/v1", "NetworkPolicy", "saw-default-deny", ns,
                  spec={"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}),
        _resource("rbac.authorization.k8s.io/v1", "Role", "saw-root-provisioner", ns,
                  rules=[{"apiGroups": ["cdi.kubevirt.io"], "resources": ["datavolumes"],
                          "verbs": ["create", "get", "list", "watch"]}]),
        _resource("rbac.authorization.k8s.io/v1", "RoleBinding", "saw-root-provisioner", ns,
                  roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                           "name": "saw-root-provisioner"},
                  subjects=[{"kind": "ServiceAccount", "name": "saw-provisioner",
                             "namespace": ns}]),
        _resource("external-secrets.io/v1", "SecretStore", "saw-user-vault", ns,
                  spec={"provider": {"vault": {
                      "server": vault["server"], "path": vault["mount"], "version": "v2",
                      "caProvider": {"type": "ConfigMap", "name": vault["caConfigMap"],
                                     "key": "ca.crt"},
                      "auth": {"kubernetes": {"mountPath": vault["authMount"], "role": ns,
                                              "serviceAccountRef": {
                                                  "name": "saw-vault-reader",
                                                  "audiences": [vault["audience"]]}}}}}}),
    ])
    for credential in cfg["credentials"]:
        # Extract exactly one Vault record, then select allowlisted fields locally.
        # This avoids mixing KV versions across multiple property fetches.
        template = {key: "{{ ." + prop + " }}"
                    for key, prop in sorted(credential["properties"].items())}
        resources.append(_resource(
            "external-secrets.io/v1", "ExternalSecret", f"saw-provider-{credential['name']}", ns,
            spec={"refreshPolicy": "Periodic", "refreshInterval": "1m",
                  "secretStoreRef": {"name": "saw-user-vault", "kind": "SecretStore"},
                  "target": {"name": f"saw-provider-{credential['name']}",
                             "creationPolicy": "Owner", "deletionPolicy": "Retain",
                             "template": {"engineVersion": "v2", "mergePolicy": "Replace",
                                          "type": "Opaque", "data": template}},
                  "dataFrom": [{"extract": {"key": f"{prefix}/{credential['remoteKey']}"}}]},
        ))
    return resources


def render_image(document):
    """An immutable-identity import plan; source readiness is a separate gate."""
    _header(document, "SawGoldenImage")
    spec = fields(document["spec"],
                  {"namespace", "registryURL", "registrySecret", "caConfigMap",
                   "diskSizeGi", "storageClass"},
                  {"namespace", "registryURL", "diskSizeGi"}, "image spec")
    ns = name(spec["namespace"], "image namespace")
    url = string(spec["registryURL"], "registryURL", limit=2048)
    if not re.fullmatch(r"docker://[a-zA-Z0-9.-]+(?::[0-9]+)?/"
                        r"[a-z0-9._/-]+@sha256:[0-9a-f]{64}", url):
        raise ValidationError("registryURL must be an OCI reference pinned by sha256 digest")
    if type(spec["diskSizeGi"]) is not int or not 1 <= spec["diskSizeGi"] <= 16384:
        raise ValidationError("diskSizeGi must be an integer between 1 and 16384")
    for key in ("registrySecret", "caConfigMap", "storageClass"):
        if key in spec:
            name(spec[key], f"image.{key}")
    # Bind source location, digest and storage profile into resource identity.
    identity = hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False).encode()).hexdigest()
    resource_name = f"{document['metadata']['name'][:25]}-{identity[:24]}"
    registry = {"url": url, "pullMethod": "pod"}
    if "registrySecret" in spec:
        registry["secretRef"] = spec["registrySecret"]
    if "caConfigMap" in spec:
        registry["certConfigMap"] = spec["caConfigMap"]
    storage = {"accessModes": ["ReadWriteOnce"],
               "resources": {"requests": {"storage": f"{spec['diskSizeGi']}Gi"}}}
    if "storageClass" in spec:
        storage["storageClassName"] = spec["storageClass"]
    dv = _resource("cdi.kubevirt.io/v1beta1", "DataVolume", resource_name, ns,
                   spec={"source": {"registry": registry}, "storage": storage})
    dv["metadata"]["annotations"] = {
        "saw.redhat.com/import-identity": identity,
        "saw.redhat.com/source-digest": url.rsplit("@", 1)[1],
        "cdi.kubevirt.io/storage.bind.immediate.requested": "true",
    }
    source = _resource("cdi.kubevirt.io/v1beta1", "DataSource", resource_name, ns,
                       spec={"source": {"pvc": {"name": resource_name, "namespace": ns}}})
    source["metadata"]["annotations"] = {"saw.redhat.com/import-identity": identity}
    return [_resource("v1", "Namespace", ns), dv, source]
