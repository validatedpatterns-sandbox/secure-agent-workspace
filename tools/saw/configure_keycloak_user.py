#!/usr/bin/env python3
"""Create or reconcile one bundled-Keycloak user and record its immutable subject."""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


def oc(*args: str) -> str:
    return subprocess.check_output(["oc", *args], text=True).strip()


def request(base: str, method: str, path: str, token: str, context: ssl.SSLContext, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base}{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=context) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None
        raise RuntimeError(f"Keycloak API {method} {path} returned HTTP {exc.code}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-values", type=Path, required=True)
    parser.add_argument("--namespace", default=os.environ.get("KEYCLOAK_NS", "keycloak"))
    parser.add_argument("--realm", default=os.environ.get("KEYCLOAK_REALM", "saw"))
    parser.add_argument("--url", default=os.environ.get("KEYCLOAK_URL"))
    parser.add_argument("--ca-bundle", type=Path,
                        default=os.environ.get("KEYCLOAK_CA_BUNDLE"),
                        help="CA bundle for Keycloak HTTPS; system trust is used by default")
    args = parser.parse_args()

    document = yaml.safe_load(args.user_values.read_text()) or {}
    user = document.get("sawUser", {})
    identity = user.get("user", {})
    username = identity.get("username", user.get("username", user.get("name")))
    if (not isinstance(username, str) or len(username) > 63 or
            not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", username)):
        parser.error("user file must define a lowercase Kubernetes-compatible username")

    resource = os.environ.get("KEYCLOAK_NAME", "openshell-keycloak")
    if subprocess.run(["oc", "get", "keycloak", resource, "-n", args.namespace], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        resource = oc("get", "keycloak", "-n", args.namespace, "-o", "jsonpath={.items[0].metadata.name}")
    base = args.url
    if not base:
        for field in (".status.externalURL", ".status.externalUrl", ".status.url"):
            base = oc("get", "keycloak", resource, "-n", args.namespace, "-o", f"jsonpath={{{field}}}")
            if base:
                break
    if not base:
        host = oc("get", "route", "-n", args.namespace, "-o", "jsonpath={.items[0].spec.host}")
        base = f"https://{host}" if host else ""
    if not base:
        parser.error("cannot discover Keycloak URL; set KEYCLOAK_URL")
    base = base.rstrip("/")
    if urllib.parse.urlsplit(base).scheme != "https":
        parser.error("Keycloak admin API must use HTTPS")
    try:
        context = ssl.create_default_context(cafile=str(args.ca_bundle) if args.ca_bundle else None)
    except (OSError, ssl.SSLError) as exc:
        parser.error(f"cannot load Keycloak CA bundle: {exc}")

    admin_user = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
    admin_password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD")
    if not admin_password:
        secret_names = os.environ.get("KEYCLOAK_ADMIN_SECRET", f"{resource}-initial-admin {resource}-admin keycloak-initial-admin keycloak-admin").split()
        for name in secret_names:
            try:
                admin_password = oc("get", "secret", name, "-n", args.namespace, "-o", "jsonpath={.data.password}")
                admin_password = subprocess.check_output(["base64", "-d"], input=admin_password, text=True).strip()
                admin_user_b64 = oc("get", "secret", name, "-n", args.namespace, "-o", "jsonpath={.data.username}")
                if admin_user_b64:
                    admin_user = subprocess.check_output(["base64", "-d"], input=admin_user_b64, text=True).strip()
                break
            except subprocess.CalledProcessError:
                continue
    if not admin_password:
        parser.error("Keycloak admin password unavailable")

    token_path = f"/realms/master/protocol/openid-connect/token"
    token_body = urllib.parse.urlencode({"client_id": "admin-cli", "grant_type": "password", "username": admin_user, "password": admin_password}).encode()
    token_req = urllib.request.Request(f"{base}{token_path}", data=token_body, method="POST")
    try:
        with urllib.request.urlopen(token_req, context=context) as response:
            token = json.loads(response.read())["access_token"]
    except Exception as exc:
        parser.error(f"Keycloak admin authentication failed: {exc}")

    query = urllib.parse.urlencode({"username": username, "exact": "true"})
    status, users = request(base, "GET", f"/admin/realms/{urllib.parse.quote(args.realm)}/users?{query}", token, context)
    if status != 200:
        parser.error("cannot list Keycloak users")
    matches = [item for item in users or [] if item.get("username") == username]
    if len(matches) > 1:
        parser.error(f"multiple Keycloak users match {username}")
    if not matches:
        status, _ = request(base, "POST", f"/admin/realms/{urllib.parse.quote(args.realm)}/users", token, context,
                            {"username": username, "enabled": True})
        if status not in (201, 204):
            parser.error(f"could not create Keycloak user {username}")
        status, users = request(base, "GET", f"/admin/realms/{urllib.parse.quote(args.realm)}/users?{query}", token, context)
        matches = [item for item in users or [] if item.get("username") == username]
        print(f"Created Keycloak user {username}.")
    if len(matches) != 1 or not matches[0].get("id"):
        parser.error(f"could not resolve exactly one Keycloak user {username}")
    keycloak_subject = matches[0]["id"]

    realm = urllib.parse.quote(args.realm)
    user_id = urllib.parse.quote(keycloak_subject)
    status, detail = request(base, "GET", f"/admin/realms/{realm}/users/{user_id}", token, context)
    if status != 200 or not isinstance(detail, dict) or not detail.get("enabled", False):
        parser.error(f"Keycloak user {username} is missing or disabled; enable it before enrollment")

    # The guest gateway requires this realm role for ordinary OIDC users.
    role_name = "openshell-user"
    status, role = request(base, "GET", f"/admin/realms/{realm}/roles/{role_name}", token, context)
    if status != 200 or not isinstance(role, dict) or not role.get("id"):
        parser.error(f"Keycloak realm {args.realm} does not define the {role_name} role")
    status, assigned = request(base, "GET",
                               f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                               token, context)
    if status != 200:
        parser.error(f"cannot inspect realm roles for {username}")
    if not any(item.get("id") == role["id"] for item in assigned or []):
        status, _ = request(base, "POST",
                            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                            token, context, [{"id": role["id"], "name": role_name}])
        if status not in (200, 201, 204):
            parser.error(f"could not assign the {role_name} role to {username}")

    # yq preserves the rest of the hand-authored file and only changes identity metadata.
    env = dict(os.environ, SUBJECT=keycloak_subject)
    subprocess.run(["yq", "-i", ".sawUser.user.subject = strenv(SUBJECT)", str(args.user_values)], check=True, env=env)
    print(f"Verified {role_name} access and recorded immutable subject for {username} in {args.user_values}.")


if __name__ == "__main__":
    main()
