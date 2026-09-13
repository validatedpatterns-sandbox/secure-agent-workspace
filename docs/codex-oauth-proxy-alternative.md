# Alternative: OAuth2 Proxy for Codex WebSocket Auth

## Status: Proposed (not implemented)

The current Codex sandbox authentication uses a custom per-VM HMAC shared
secret with short-lived HS256 JWTs minted by the `saw-codex-api` service.
This document describes an alternative approach using `oauth2-proxy` that
would simplify the security model by reusing Keycloak OIDC tokens directly.

## Current Architecture

```
TUI (OIDC login) → API /sessions/{name}/connect
  → reads per-VM shared secret from K8s Secret
  → mints HS256 JWT (5 min TTL)
  → returns {ws_url, token}

codex --remote wss://... --remote-auth-token-env CODEX_TOKEN
  → codex app-server validates JWT (--ws-auth signed-bearer-token)
```

Components involved in auth:
- Per-VM shared secret (generated inside sandbox, stored in K8s Secret)
- JWT minting logic in `saw-codex-api/app.py`
- `codex-secret` K8s Secret per sandbox
- `codex app-server --ws-auth signed-bearer-token --ws-shared-secret-file`

## Proposed Architecture

```
TUI (OIDC login) → passes existing OIDC token directly

codex --remote wss://... --remote-auth-token-env CODEX_TOKEN
  → oauth2-proxy validates OIDC token against Keycloak JWKS
  → proxies to codex app-server on localhost (no auth)
```

### VM-level setup

```
oauth2-proxy (0.0.0.0:8089)
  │  Validates Authorization: Bearer <OIDC token>
  │  Checks against Keycloak JWKS endpoint
  ▼
codex app-server (127.0.0.1:8090, no --ws-auth)
  │  Loopback listener — no auth required
```

Both run as systemd user services on the VM. oauth2-proxy is already
used in SAW for the OpenShell Dashboard (port 8080), so the pattern
and configuration are established.

### oauth2-proxy configuration

```
--provider=oidc
--oidc-issuer-url=https://<keycloak>/realms/openshell
--client-id=openshell-cli
--upstream=ws://127.0.0.1:8090/
--http-address=0.0.0.0:8089
--skip-auth-regex=^/healthz$
--skip-auth-regex=^/readyz$
--pass-access-token=false
--cookie-secure=false
--email-domain=*
```

### TUI connect flow (simplified)

```python
# No API call needed — reuse existing OIDC token
token = auth.get_token(token_dir, client_id)
os.environ["CODEX_TOKEN"] = token
subprocess.run(["codex", "--remote", ws_url,
                "--remote-auth-token-env", "CODEX_TOKEN"])
```

## What gets eliminated

| Component | Current | With oauth2-proxy |
|-----------|---------|-------------------|
| Per-VM shared secret | Generated, stored in K8s Secret | Eliminated |
| JWT minting | API `/sessions/{name}/connect` | Eliminated |
| `codex-secret` K8s Secret | Created per sandbox | Eliminated |
| `get_codex_secret()` | Reads secret for minting | Eliminated |
| readyz check in connect | API checks before minting | Proxy handles availability |
| Custom crypto | HS256 signing code | Eliminated (standard OIDC) |
| Secret generation in apply_bom.py | `python3 -c 'import secrets; ...'` | Eliminated |

## What gets added

- oauth2-proxy systemd service in `apply_bom.py` `start_codex_app_server()`
- oauth2-proxy image pre-pulled or available on the VM
- Keycloak redirect URI registration (already done for dashboard)
- Codex app-server binds to `127.0.0.1:8090` instead of `0.0.0.0:8089`

## Security comparison

| Aspect | Current (custom JWT) | oauth2-proxy |
|--------|---------------------|-------------|
| Auth standard | Custom HS256 JWT | Standard OIDC (RS256) |
| Token lifetime | 5 minutes | Keycloak session (~10 hours) |
| Key management | Per-VM secret in K8s | Keycloak JWKS (no keys to manage) |
| Attack surface | Custom minting code | Battle-tested proxy |
| Token revocation | Not supported | Keycloak session revocation |
| Multi-user per VM | Not applicable (1 user per VM) | Same |

## Implementation effort

Low-medium. The oauth2-proxy pattern already exists in SAW for the
dashboard. The main work is:

1. Add oauth2-proxy systemd service in `start_codex_app_server()` (~20 lines)
2. Change codex app-server to bind `127.0.0.1:8090` with no `--ws-auth`
3. Update TUI `_fetch_and_connect()` to pass OIDC token directly
4. Remove secret generation, `/connect` endpoint JWT minting, K8s Secret creation
5. Update `codex-forward.service` to forward port 8089 (proxy) not 8090 (app-server)

## Why not implemented yet

The current approach works and is secure (per the security review).
The oauth2-proxy alternative is a simplification that reduces custom
crypto and aligns with the existing SAW auth patterns. It should be
considered for a future iteration when:

- The custom JWT minting becomes a maintenance burden
- Token revocation is needed
- The auth model needs to be audited by external reviewers (standard
  OIDC is easier to audit than custom JWT)
