"""Read-only ApplicationSet projection for installations without Developer Hub.

The same workspace.project_workspace function is used by the RHDH adapter.
Only named public enrollment publications are read from Kubernetes. Desired
workspace inputs come from the mounted, operator-owned configuration.
"""
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import workspace
import preflight

LIMIT = 4 * 1024 * 1024


class ProjectionError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Publications:
    def __init__(self, service_account):
        self.root = Path(service_account)
        self.opener = build_opener(NoRedirect(), HTTPSHandler(
            context=ssl.create_default_context(cafile=str(self.root / "ca.crt"))))

    def __call__(self, path):
        if not re.fullmatch(r"/api/v1/namespaces/saw-ctl-[a-f0-9]{16}/configmaps/[a-z0-9-]+", path):
            raise ProjectionError("publication is outside the workspace scope")
        return self.get(path, publication=True)

    def preflight_resource(self, path):
        fixed = {
            "/apis/config.openshift.io/v1/clusterversions/version",
            "/apis/kataconfiguration.openshift.io/v1/kataconfigs",
            "/api/v1/nodes",
            "/apis/admissionregistration.k8s.io/v1",
        }
        allowed = (path in fixed or re.fullmatch(
            r"/api/v1/namespaces/saw-[a-z0-9-]+", path) or re.fullmatch(
            r"/apis/node.k8s.io/v1/runtimeclasses/[a-z0-9-]+", path) or re.fullmatch(
            r"/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"
            r"(?:kataconfigs.kataconfiguration.openshift.io|sandboxes.agents.x-k8s.io|"
            r"externalsecrets.external-secrets.io|adminnetworkpolicies.policy.networking.k8s.io)", path) or re.fullmatch(
            r"/apis/admissionregistration.k8s.io/v1/"
            r"(?:validatingadmissionpolicies|validatingadmissionpolicybindings)/"
            r"saw-saw-[a-z0-9-]+-runtime(?:-kata)?", path))
        if not allowed:
            raise ProjectionError("preflight resource is outside the workspace scope")
        return self.get(path)

    def get(self, path, *, publication=False):
        token = (self.root / "token").read_text().strip()
        request = Request("https://kubernetes.default.svc" + path,
                          headers={"Authorization": "Bearer " + token})
        try:
            with self.opener.open(request, timeout=20) as response:
                body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ProjectionError("workspace API response exceeds the size limit")
            return json.loads(body)
        except HTTPError as exc:
            exc.close()
            if exc.code == 404 or publication and exc.code == 403:
                return {}
            raise ProjectionError("workspace API request failed") from None
        except (URLError, OSError, ValueError):
            raise ProjectionError("workspace API is unavailable or invalid") from None

    def previous(self, owner):
        ns = os.environ["ARGO_NAMESPACE"]
        appset = os.environ["PROJECTOR_NAME"]
        app = self.get(f"/apis/argoproj.io/v1alpha1/namespaces/{ns}/applications/{appset}-{owner['name']}")
        return workspace.previous_child(app, appset, owner)


def verify_gitops_preflight(owner, site, mode, read):
    """Stop ApplicationSet generation on a changed live Kata boundary."""
    automatic = site.get("automaticEnrollment", {})
    if not automatic or automatic.get("enabled") is False:
        return
    reference = automatic.get("reference")
    preflight.verify_boundary_reference(reference, mode)
    if mode == "kata":
        approval = site.get("kataRuntimeClass") or {}
        if not isinstance(approval, dict) or not approval.get("name"):
            raise preflight.PreflightError("RuntimeClassApprovalMissing")
        try:
            version = read("/apis/config.openshift.io/v1/clusterversions/version")
            runtime = read("/apis/node.k8s.io/v1/runtimeclasses/" + approval["name"])
            configs = read("/apis/kataconfiguration.openshift.io/v1/kataconfigs")
            nodes = read("/api/v1/nodes")
            readiness = {}
            for name in ("kataconfigs.kataconfiguration.openshift.io",
                         "sandboxes.agents.x-k8s.io",
                         "externalsecrets.external-secrets.io",
                         "adminnetworkpolicies.policy.networking.k8s.io"):
                readiness[name] = preflight.crd_established(read(
                    "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + name))
            readiness["admissionregistration.k8s.io/v1"] = preflight.api_resources_available(
                read("/apis/admissionregistration.k8s.io/v1"),
                "admissionregistration.k8s.io/v1",
                ("validatingadmissionpolicies", "validatingadmissionpolicybindings"))
            preflight.verify_kata_platform(site, runtime, (configs or {}).get("items"),
                                           (nodes or {}).get("items"), readiness, version)
        except preflight.PreflightError:
            raise
        except Exception:
            raise preflight.PreflightError("KataPlatformUnavailable") from None

    name = owner["name"]
    namespace_name = "saw-" + name
    try:
        namespace = read("/api/v1/namespaces/" + namespace_name)
    except Exception:
        raise preflight.PreflightError("BoundaryNamespaceUnavailable") from None
    if not namespace:
        return  # Enrollment verifies policies after the first namespace exists.
    metadata = namespace.get("metadata", {})
    labels = metadata.get("labels", {})
    if (metadata.get("deletionTimestamp") or labels.get("saw.redhat.com/runtime-owner") != owner["installationID"]
            or labels.get("saw.redhat.com/registration") != owner["registration"]):
        raise preflight.PreflightError("BoundaryApprovalIdentityMismatch")
    policy = "saw-" + namespace_name + "-runtime"
    resources = [("validation", "validatingadmissionpolicies", policy),
                 ("binding", "validatingadmissionpolicybindings", policy)]
    if mode == "kata":
        resources.extend((("sandboxPlacement", "validatingadmissionpolicies", policy + "-kata"),
                          ("sandboxPlacementBinding", "validatingadmissionpolicybindings", policy + "-kata")))
    for key, plural, resource_name in resources:
        try:
            obj = read("/apis/admissionregistration.k8s.io/v1/" + plural + "/" + resource_name)
        except Exception:
            raise preflight.PreflightError("BoundaryPolicyUnavailable") from None
        if not isinstance(obj, dict) or not isinstance(obj.get("spec"), dict):
            raise preflight.PreflightError("BoundaryPolicyUnavailable")
        digest = (preflight.validation_policy_digest(
            obj["spec"], name, owner["registration"], owner["installationID"],
            sorted(site["targets"])) if key == "validation" else preflight.fingerprint(obj["spec"]))
        try:
            preflight.verify_boundary_hash(reference, key, digest)
        except preflight.PreflightError as exc:
            raise preflight.PreflightError(exc.reason + ":" + key) from None
        if plural == "validatingadmissionpolicies":
            status = obj.get("status", {})
            type_checking = status.get("typeChecking", {}) if isinstance(status, dict) else {}
            if (not isinstance(type_checking, dict)
                    or status.get("observedGeneration") != obj.get("metadata", {}).get("generation")
                    or "typeChecking" not in status or type_checking.get("expressionWarnings")):
                raise preflight.PreflightError("AdmissionUnavailable:" + key)


def parameters(config, catalog, read):
    """Project the whole desired set atomically; errors never mean deletion."""
    if not isinstance(config, dict) or not isinstance(config.get("users"), list):
        raise ProjectionError("workspace configuration requires a users list")
    defaults = {k: v for k, v in config.items() if k not in ("users", "containerSites", "projection")}
    # Child charts render a fully projected workspace, not another generator.
    defaults["projection"] = {"enabled": False}
    # Container entries have a pre-resolved subject. VM owner resolution stays
    # with the root chart and must not create a second owner of its resources.
    defaults["ownerResolution"] = {**defaults.get("ownerResolution", {}), "enabled": False}
    result, seen = [], set()
    sites = config.get("containerSites", {})
    for owner in config["users"]:
        if not isinstance(owner, dict):
            raise ProjectionError("workspace entries must be mappings")
        name = owner.get("name", "")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,17}[a-z0-9])?", name) or name in seen:
            raise ProjectionError("workspace names must be unique DNS labels of at most 19 characters")
        seen.add(name)
        if owner.get("values", {}).get("deployment", {}).get("mode", "vm") not in {"container", "kata"}:
            raise ProjectionError("standalone container projection received another backend")
        site = sites.get(name)
        try:
            values = workspace.project_workspace(owner, defaults, site, catalog, read, getattr(read, "previous", None))
            live_read = getattr(read, "preflight_resource", None)
            if callable(live_read):
                mode = owner["values"]["deployment"]["mode"]
                verify_gitops_preflight(owner, values["containerSites"][name], mode, live_read)
        except preflight.PreflightError as exc:
            raise ProjectionError("workspace " + name + ": preflight failed: " + exc.reason) from None
        except workspace.WorkspaceError as exc:
            raise ProjectionError(str(exc)) from None
        except (KeyError, TypeError, ValueError):
            raise ProjectionError("workspace configuration or enrollment is invalid") from None
        # `values` is reserved by the ApplicationSet plugin protocol.
        result.append({"name": name, "revision": values.get("global", {}).get("targetRevision", ""),
                       "workspaceValues": json.dumps(values, sort_keys=True)})
    return result


def server(config_file, catalog_file, token_file, read, address):
    class Handler(http.server.BaseHTTPRequestHandler):
        def send(self, code, value):
            body = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.send(200 if self.path == "/healthz" else 404, {"status": "running"})

        def do_POST(self):
            if self.path != "/api/v1/getparams.execute":
                return self.send(404, {"error": "not found"})
            try:
                token = Path(token_file).read_text().strip()
            except OSError:
                return self.send(503, {"error": "plugin identity is unavailable"})
            if not token or not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                return self.send(403, {"error": "forbidden"})
            try:
                config = json.loads(Path(config_file).read_text())
                catalog = json.loads(Path(catalog_file).read_text())["profiles"]
                output = parameters(config, catalog, read)
            except ProjectionError as exc:
                return self.send(503, {"error": str(exc)})
            except (OSError, ValueError, KeyError, TypeError):
                # Returning an empty list on error would prune live workspaces.
                return self.send(503, {"error": "workspace projection is not ready"})
            self.send(200, {"output": {"parameters": output}})

        def log_message(self, fmt, *args):
            # Avoid logging request headers, inputs or publication values.
            print("workspace projection request completed", flush=True)

    return http.server.ThreadingHTTPServer(address, Handler)


if __name__ == "__main__":
    with server("/config/workspaces.json", "/source/profile-catalog.json", "/identity/token",
                Publications("/var/run/secrets/kubernetes.io/serviceaccount"),
                ("0.0.0.0", int(os.environ.get("PORT", "4355")))) as listener:
        listener.serve_forever()
