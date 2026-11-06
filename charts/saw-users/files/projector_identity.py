"""Create-once bearer identity for the internal ApplicationSet plugin.

Only the two configured Secret names are read. Both projections are immutable;
namespace identities and ownership are checked before an existing value is used.
"""
import base64
import hashlib
import json
import secrets
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class IdentityError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Api:
    def __init__(self):
        self.root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        self.opener = build_opener(NoRedirect(), HTTPSHandler(
            context=ssl.create_default_context(cafile=str(self.root / "ca.crt"))))

    def call(self, method, path, body=None):
        raw = json.dumps(body).encode() if body is not None else None
        token = (self.root / "token").read_text().strip()
        req = Request("https://kubernetes.default.svc"+path, data=raw, method=method,
                      headers={"Content-Type": "application/json", "Authorization": "Bearer "+token})
        try:
            with self.opener.open(req, timeout=20) as response:
                value = response.read(1024*1024+1)
            if len(value) > 1024*1024:
                raise IdentityError("oversized identity response")
            return json.loads(value)
        except HTTPError as exc:
            status = exc.code
            exc.close()
            if (method == "GET" and status == 404) or (method == "POST" and status == 409):
                return None
            raise IdentityError("identity API request failed") from None


def provision(config, api):
    if set(config) != {"namespace", "argoNamespace", "name", "owner"}:
        raise IdentityError("invalid identity configuration")
    for value in config.values():
        if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", value):
            raise IdentityError("invalid identity name")
    if config["namespace"] == config["argoNamespace"]:
        raise IdentityError("projector must have a dedicated namespace")
    namespaces = [config["namespace"], config["argoNamespace"]]
    identities = {}
    for ns in namespaces:
        obj = api.call("GET", "/api/v1/namespaces/"+ns) or {}
        meta = obj.get("metadata", {})
        if not meta.get("uid") or meta.get("deletionTimestamp"):
            raise IdentityError("identity namespace is not ready")
        identities[ns] = meta["uid"]
    owners = {}
    for ns, group, kind, plural in [(config["namespace"], "apps/v1", "Deployment", "deployments"),
                                    (config["argoNamespace"], "argoproj.io/v1alpha1", "ApplicationSet", "applicationsets")]:
        obj = api.call("GET", f"/apis/{group}/namespaces/{ns}/{plural}/{config['name']}") or {}
        meta = obj.get("metadata", {})
        if (not meta.get("uid") or meta.get("deletionTimestamp")
                or meta.get("labels", {}).get("saw.redhat.com/projector-owner") != config["owner"]):
            raise IdentityError("plugin identity owner is not ready")
        owners[ns] = [{"apiVersion": group, "kind": kind, "name": config["name"], "uid": meta["uid"]}]
    revision = hashlib.sha256(json.dumps({"config": config, "namespaces": identities, "owners": owners}, sort_keys=True).encode()).hexdigest()
    paths = [f"/api/v1/namespaces/{ns}/secrets/{config['name']}" for ns in namespaces]

    def checked(obj, ns):
        meta = (obj or {}).get("metadata", {})
        data = (obj or {}).get("data", {})
        if (meta.get("deletionTimestamp") or meta.get("ownerReferences") != owners[ns]
                or meta.get("labels", {}).get("saw.redhat.com/projector-owner") != config["owner"]
                or meta.get("annotations", {}).get("saw.redhat.com/identity-sha256") != revision
                or obj.get("immutable") is not True or obj.get("type") != "Opaque"
                or set(data) != {"token"}):
            raise IdentityError("existing plugin identity is foreign or changed")
        try:
            decoded = base64.b64decode(data["token"], validate=True).decode("ascii")
        except (ValueError, UnicodeError):
            raise IdentityError("invalid plugin identity") from None
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", decoded):
            raise IdentityError("invalid plugin token")
        return data

    first = api.call("GET", paths[0])
    if first is None:
        if any(api.call("GET", path) for path in paths[1:]):
            raise IdentityError("orphaned plugin identity; refusing automatic replacement")
        token = base64.b64encode(secrets.token_urlsafe(32).encode()).decode()
        data = {"token": token}
    else:
        data = checked(first, namespaces[0])
    for ns, path in zip(namespaces, paths):
        expected = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": True,
                    "metadata": {"name": config["name"], "namespace": ns, "ownerReferences": owners[ns],
                                 "labels": {"saw.redhat.com/projector-owner": config["owner"],
                                            "app.kubernetes.io/part-of": "argocd"},
                                 "annotations": {"saw.redhat.com/identity-sha256": revision}},
                    "data": data}
        if api.call("GET", path) is None:
            api.call("POST", f"/api/v1/namespaces/{ns}/secrets", expected)
        observed = checked(api.call("GET", path), ns)
        if ns == namespaces[0]:
            data = observed  # use the winner of a concurrent primary creation
        elif observed != data:
            raise IdentityError("plugin identity projections differ")


if __name__ == "__main__":
    try:
        provision(json.loads(Path("/source/identity.json").read_text()), Api())
    except Exception:
        raise SystemExit("plugin identity initialization failed; no existing identity was replaced") from None
