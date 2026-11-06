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
        token = (self.root / "token").read_text().strip()
        request = Request("https://kubernetes.default.svc" + path,
                          headers={"Authorization": "Bearer " + token})
        try:
            with self.opener.open(request, timeout=20) as response:
                body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ProjectionError("publication exceeds the size limit")
            return json.loads(body)
        except HTTPError as exc:
            code = exc.code
            exc.close()
            # The foundation grants a named reader after creating its namespace.
            if code in (403, 404):
                namespace = path.split("/")[4]
                probe = Request("https://kubernetes.default.svc/api/v1/namespaces/"+namespace,
                                headers={"Authorization": "Bearer "+token})
                try:
                    with self.opener.open(probe, timeout=20):
                        pass
                except HTTPError as missing:
                    status = missing.code
                    missing.close()
                    if status == 404:
                        return {}  # first projection, before foundation creation
                raise ProjectionError("existing foundation publication is unavailable")
            raise ProjectionError("publication API request failed") from None
        except (URLError, OSError, ValueError):
            raise ProjectionError("publication API is unavailable or invalid") from None


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
        if owner.get("values", {}).get("deployment", {}).get("mode", "vm") != "container":
            raise ProjectionError("standalone container projection received another backend")
        site = sites.get(name)
        if not site:
            raise ProjectionError("container site is missing")
        try:
            values = workspace.project_workspace(owner, defaults, site, catalog, read)
        except (workspace.WorkspaceError, KeyError, TypeError, ValueError):
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
            except (ProjectionError, OSError, ValueError, KeyError, TypeError):
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
