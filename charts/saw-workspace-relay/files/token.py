"""Refresh the dedicated service-account token in the stock CLI's in-memory config."""
import base64
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def write(path, data):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data))
    temp.replace(path)


def refresh():
    cfg = json.loads(Path("/config/relay.json").read_text())
    issuer = cfg["issuer"]
    secret = Path("/credential/client-secret").read_text()
    request = Request(issuer + "/protocol/openid-connect/token", data=urlencode({
        "grant_type":"client_credentials", "client_id":cfg["clientID"], "client_secret":secret}).encode())
    with build_opener(NoRedirect()).open(request, timeout=12) as response:
        result = json.load(response)
    token = result["access_token"]
    part = token.split(".")[1]
    c = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    audiences = c["aud"] if isinstance(c["aud"],list) else [c["aud"]]
    if (c["sub"] != cfg["subject"] or c["iss"] != issuer or c["azp"] != cfg["clientID"]
            or set(audiences) != {cfg["audience"]}
            or set(c.get("realm_access",{}).get("roles",[])) != {"openshell-user"}
            or c.get("resource_access") or int(c["exp"]) - time.time() < 30):
        raise ValueError("unexpected relay claims")
    directory = Path("/session/openshell/gateways/relay")
    (directory/"mtls").mkdir(parents=True,exist_ok=True)
    (directory/"mtls/ca.crt").write_bytes(Path("/config/ca.crt").read_bytes())
    write(directory/"metadata.json", {"name":"relay","gateway_endpoint":cfg["gatewayEndpoint"],"is_remote":False,
          "gateway_port":0,"auth_mode":"oidc","oidc_issuer":issuer,"oidc_client_id":cfg["clientID"],
          "oidc_audience":cfg["audience"],"oidc_scopes":"openid"})
    write(directory/"oidc_token.json", {"access_token":token,"expires_at":int(c["exp"]),
          "issuer":issuer,"client_id":cfg["clientID"]})
    return max(10, int((int(c["exp"])-time.time())/2))


if __name__ == "__main__":
    os.umask(0o077)
    while True:
        try:
            delay = refresh()
        except Exception as e:
            print("Relay token exchange failed: " + type(e).__name__, file=sys.stderr, flush=True)
            if sys.argv[1] == "once":
                sys.exit(1)
            delay = 10
        if sys.argv[1] == "once":
            break
        time.sleep(delay)
