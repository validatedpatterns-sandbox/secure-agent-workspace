"""Sandbox web UI routes: the in-VM half.

The openshell-saw chart renders `sandboxUi` (one entry per sandbox with
ui.route: true) into config.json. The installer lets the sandbox's OpenClaw
control UI accept the route's origin, and runs two user units per entry: an
`openshell forward service` to the sandbox's port 18789, and an oauth2-proxy
on the port the route reaches, which signs in with Keycloak and admits only
the workspace owner.
"""
import json

import pytest

from test_apply_profiles import creds, make_applier, profiles  # noqa: F401 (fixtures)

ISSUER = "https://keycloak.example.com/realms/openshell"
ENTRY = {"workspace": "default", "sandbox": "notebook", "host": "alice-default-notebook-ui.apps.example.com",
         "proxyPort": 4201, "forwardPort": 14201}
TRUSTED = {"enabled": True, "cidrs": ["127.0.0.1/32", "::1/128"], "deviceAutoApprove": True}
PROXY = {"allowedUsers": ["alice"], "image": "quay.io/oauth2-proxy/oauth2-proxy:v7.9.0",
         "clientId": "openshell-dashboard", "targetPort": 18789, "insecureSkipTlsVerify": False,
         "trustedProxy": TRUSTED}


def ui_config(**extra):
    return {"vmName": "alice", "oidcIssuer": ISSUER, "mtlsGateway": "saw-installer",
            "sandboxUi": [ENTRY], "sandboxUiProxy": PROXY, **extra}


def write_config(tmp_path, cfg):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    return path


# -- config validation -------------------------------------------------------------

def test_a_rendered_entry_is_accepted(ab, tmp_path):
    cfg = ab.load_config(write_config(tmp_path, ui_config()))
    assert cfg["sandboxUi"] == [ENTRY]


@pytest.mark.parametrize("change, message", [
    ({"host": "bad host; rm -rf /"}, "needs a route host"),
    ({"workspace": "Bad_WS"}, "must be DNS labels"),
    ({"proxyPort": 80}, "proxyPort must be a free port"),
    ({"forwardPort": 4201}, "forwardPort must be a free port"),
    ({"forwardPort": 60000}, r"forwardPort \+ 10000 must be a free port"),
])
def test_bad_entries_are_refused(ab, tmp_path, change, message):
    with pytest.raises(ab.InstallerError, match=message):
        ab.load_config(write_config(tmp_path, ui_config(sandboxUi=[{**ENTRY, **change}])))


def test_a_ui_route_needs_an_owner(ab, tmp_path):
    with pytest.raises(ab.InstallerError, match="allowedUsers must name the owner"):
        ab.load_config(write_config(tmp_path, ui_config(sandboxUiProxy={**PROXY, "allowedUsers": []})))


def test_no_ui_routes_need_no_proxy_settings(ab, tmp_path):
    cfg = ab.load_config(write_config(tmp_path, {"vmName": "alice"}))
    assert cfg["sandboxUi"] == []
    assert cfg["sandboxUiProxy"]["trustedProxy"] == {"enabled": False}


@pytest.mark.parametrize("trusted, message", [
    ({"enabled": "yes"}, "must be"),
    ({"enabled": True, "cidrs": []}, "list of CIDRs"),
    ({"enabled": True, "cidrs": ["127.0.0.1/32; rm -rf /"]}, "is not a CIDR"),
])
def test_bad_trusted_proxy_settings_are_refused(ab, tmp_path, trusted, message):
    with pytest.raises(ab.InstallerError, match=message):
        ab.load_config(write_config(tmp_path, ui_config(sandboxUiProxy={**PROXY, "trustedProxy": trusted})))


# -- the units -----------------------------------------------------------------------

def test_the_forward_reaches_the_sandbox_port(ab, tmp_path):
    units, _ = ab.sandbox_ui_units(ui_config(), tmp_path, "c" * 32, "saw-installer")
    forward = units["saw-ui-forward-default-notebook.service"]
    assert ("ExecStart=/usr/local/bin/openshell --gateway saw-installer forward service notebook "
            "--workspace default --target-port 18789 --local 127.0.0.1:24201") in forward
    assert "Restart=always" in forward


def test_a_relay_caps_the_connections_to_the_forward(ab, tmp_path):
    """Found live: OpenShell refuses more than 20 forward connections per
    sandbox, and the control UI's burst of requests went past that."""
    units, files = ab.sandbox_ui_units(ui_config(), tmp_path, "c" * 32, "saw-installer")
    relay = units["saw-ui-limit-default-notebook.service"]
    script = tmp_path / ".config" / "openshell" / "saw-ui-limit.py"
    assert f"ExecStart=/usr/bin/python3 {script} 14201 24201 16" in relay
    assert files[script] == ab.SANDBOX_UI_LIMIT_PY
    proxy = units["saw-ui-proxy-default-notebook.service"]
    assert "After=saw-ui-limit-default-notebook.service" in proxy
    env = files[tmp_path / ".config" / "openshell" / "saw-ui-default-notebook.env"]
    assert "OAUTH2_PROXY_UPSTREAMS=http://127.0.0.1:14201" in env


def _relay_module(ab):
    import types
    mod = types.ModuleType("saw_ui_limit")
    exec(compile(ab.SANDBOX_UI_LIMIT_PY, "saw_ui_limit.py", "exec"), mod.__dict__)
    return mod


@pytest.mark.parametrize("upstream_cap, relay_max", [(20, 10), (6, 10)])
def test_the_relay_queues_and_retries(ab, upstream_cap, relay_max):
    """40 requests at once against a forward that refuses connections past
    its cap (like OpenShell's 20): through the relay all of them succeed,
    queued (cap above the relay's limit) or retried (cap below it: the forward's
    20 are shared with the sandbox's other sessions)."""
    import asyncio
    relay = _relay_module(ab)

    async def scenario():
        state = {"open": 0, "max": 0, "refused": 0}

        async def upstream(reader, writer):
            state["open"] += 1
            state["max"] = max(state["max"], state["open"])
            try:
                if state["open"] > upstream_cap:
                    state["refused"] += 1
                    writer.close()
                    return
                await reader.readuntil(b"\r\n\r\n")
                await asyncio.sleep(0.05)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await writer.drain()
                writer.close()
            finally:
                state["open"] -= 1

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        up_port = up.sockets[0].getsockname()[1]
        front = await asyncio.start_server(relay.handler(up_port, relay.Slots(relay_max)), "127.0.0.1", 0)
        port = front.sockets[0].getsockname()[1]

        async def client():
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            try:
                data = await reader.read()
            except ConnectionResetError:
                data = b""
            writer.close()
            return data.split(b" ")[1] if data else b"none"

        results = await asyncio.wait_for(asyncio.gather(*[client() for _ in range(40)]), 60)
        up.close()
        front.close()
        return results, state

    results, state = asyncio.run(scenario())
    assert results == [b"200"] * 40
    assert state["max"] <= relay_max + 1


def _keepalive_upstream(asyncio):
    async def upstream(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                if b"upgrade: websocket" in head.lower():
                    writer.write(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                    await writer.drain()
                    while await reader.read(1024):
                        pass
                    return
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
    return upstream


def test_idle_keepalive_connections_give_way(ab):
    """Found live (fwdtest through the relay): keep-alive connections held
    open after their answer took every slot and the next request waited
    forever. An answered connection idle for IDLE_PREEMPT gives way to a
    waiting one; a WebSocket never does."""
    import asyncio
    relay = _relay_module(ab)
    relay.IDLE_PREEMPT = 0.3

    async def scenario():
        up = await asyncio.start_server(_keepalive_upstream(asyncio), "127.0.0.1", 0)
        front = await asyncio.start_server(relay.handler(up.sockets[0].getsockname()[1], relay.Slots(3)),
                                           "127.0.0.1", 0)
        port = front.sockets[0].getsockname()[1]

        async def request(keep):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"ok"), 5)
            if not keep:
                writer.close()
            return head, reader, writer

        ws_reader, ws_writer = await asyncio.open_connection("127.0.0.1", port)
        ws_writer.write(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        await ws_writer.drain()
        assert b"101" in await asyncio.wait_for(ws_reader.readuntil(b"\r\n\r\n"), 5)
        held = [await request(True) for _ in range(2)]        # all 3 slots taken
        start = asyncio.get_running_loop().time()
        head, _, _ = await asyncio.wait_for(request(False), 10)
        waited = asyncio.get_running_loop().time() - start
        # The WebSocket survived: it still accepts data.
        ws_writer.write(b"ping")
        await ws_writer.drain()
        assert not ws_reader.at_eof()
        for _, _, w in held:
            w.close()
        ws_writer.close()
        up.close()
        front.close()
        return head, waited

    head, waited = asyncio.run(scenario())
    assert head.startswith(b"HTTP/1.1 200")
    assert waited < 3


def test_a_get_with_no_answer_is_sent_again(ab):
    """Found live: through the forward a request sometimes got no answer at
    all and the browser saw a 504. A repeatable request is sent again on a
    new connection; the first answer wins."""
    import asyncio
    relay = _relay_module(ab)
    relay.ANSWER_WAIT = 0.2

    async def scenario():
        seen = []

        async def upstream(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            seen.append(1)
            if len(seen) == 1:
                await asyncio.sleep(30)        # the stalled one
                return
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        front = await asyncio.start_server(relay.handler(up.sockets[0].getsockname()[1], relay.Slots(4)),
                                           "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5)
        up.close()
        front.close()
        return data, len(seen)

    data, attempts = asyncio.run(scenario())
    assert data.startswith(b"HTTP/1.1 200") and attempts == 2


def test_only_repeatable_requests_are_sent_again(ab):
    relay = _relay_module(ab)
    assert relay.hedgeable(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert not relay.hedgeable(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nab")
    assert not relay.hedgeable(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
    assert not relay.hedgeable(b"GET / HTTP/1.1\r\nHost: x\r\n")      # headers not complete


def test_the_relay_passes_a_slow_request_body(ab):
    """A request still being sent gets no answer yet: after a short wait the
    relay stops holding it for a retry and relays it whole."""
    import asyncio
    relay = _relay_module(ab)
    relay.ANSWER_WAIT = 0.2

    async def scenario():
        async def upstream(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            length = int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0])
            body = await reader.readexactly(length)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            await writer.drain()
            writer.close()

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        front = await asyncio.start_server(relay.handler(up.sockets[0].getsockname()[1], relay.Slots(2)),
                                           "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
        writer.write(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n12345")
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.write(b"67890")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5)
        up.close()
        front.close()
        return data

    assert asyncio.run(scenario()).endswith(b"1234567890")


def test_the_proxy_admits_only_listed_users(ab, tmp_path):
    """Keycloak's preferred_username is matched against the users file; no
    email domain is allowed wholesale."""
    units, files = ab.sandbox_ui_units(ui_config(), tmp_path, "c" * 32, "saw-installer")
    env = files[tmp_path / ".config" / "openshell" / "saw-ui-default-notebook.env"]
    settings = dict(line.split("=", 1) for line in env.splitlines())
    assert settings["OAUTH2_PROXY_HTTP_ADDRESS"] == "0.0.0.0:4201"
    assert settings["OAUTH2_PROXY_UPSTREAMS"] == "http://127.0.0.1:14201"
    assert settings["OAUTH2_PROXY_OIDC_ISSUER_URL"] == ISSUER
    assert settings["OAUTH2_PROXY_REDIRECT_URL"] == \
        "https://alice-default-notebook-ui.apps.example.com/oauth2/callback"
    assert settings["OAUTH2_PROXY_OIDC_EMAIL_CLAIM"] == "preferred_username"
    # X-Forwarded-Email (= preferred_username), which OpenClaw reads.
    assert settings["OAUTH2_PROXY_PASS_USER_HEADERS"] == "true"
    assert settings["OAUTH2_PROXY_AUTHENTICATED_EMAILS_FILE"] == "/etc/saw/sandbox-ui-users"
    assert settings["OAUTH2_PROXY_CODE_CHALLENGE_METHOD"] == "S256"
    assert "OAUTH2_PROXY_EMAIL_DOMAINS" not in settings
    users = tmp_path / ".config" / "openshell" / "saw-ui-default-notebook.users"
    assert files[users] == "alice\n"
    proxy = units["saw-ui-proxy-default-notebook.service"]
    assert "--network host" in proxy and f"{users}:/etc/saw/sandbox-ui-users:ro,Z" in proxy


def test_setup_writes_and_restarts_the_units(ab, fake_env, tmp_path):
    ab.setup_sandbox_ui(ab.Shell(), ui_config(), tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    assert sorted(p.name for p in unit_dir.iterdir()) == [
        "saw-ui-forward-default-notebook.service", "saw-ui-limit-default-notebook.service",
        "saw-ui-proxy-default-notebook.service"]
    env = tmp_path / ".config" / "openshell" / "saw-ui-default-notebook.env"
    assert oct(env.stat().st_mode & 0o777) == "0o600"
    calls = [json.loads(line) for line in (fake_env.state / "systemctl.log").read_text().splitlines()]
    assert ["--user", "restart", "saw-ui-forward-default-notebook.service",
            "saw-ui-limit-default-notebook.service", "saw-ui-proxy-default-notebook.service"] in calls


def test_the_cookie_secret_is_shared_with_the_dashboard(ab, fake_env, tmp_path):
    secret = tmp_path / ".config" / "openshell" / "dashboard-cookie-secret"
    secret.parent.mkdir(parents=True)
    secret.write_text("d" * 32)
    ab.setup_sandbox_ui(ab.Shell(), ui_config(), tmp_path)
    env = (tmp_path / ".config" / "openshell" / "saw-ui-default-notebook.env").read_text()
    assert f"OAUTH2_PROXY_COOKIE_SECRET={'d' * 32}" in env


def test_a_removed_route_removes_its_units(ab, fake_env, tmp_path):
    ab.setup_sandbox_ui(ab.Shell(), ui_config(), tmp_path)
    ab.setup_sandbox_ui(ab.Shell(), ui_config(sandboxUi=[]), tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    assert list(unit_dir.iterdir()) == []
    calls = [json.loads(line) for line in (fake_env.state / "systemctl.log").read_text().splitlines()]
    assert ["--user", "disable", "--now", "saw-ui-proxy-default-notebook.service"] in calls


def test_without_keycloak_nothing_is_started(ab, fake_env, tmp_path, capsys):
    ab.setup_sandbox_ui(ab.Shell(), ui_config(oidcIssuer=""), tmp_path)
    assert "need oidcIssuer" in capsys.readouterr().out
    assert not (tmp_path / ".config" / "systemd").exists()


# -- OpenClaw: the route's origin and trusted-proxy auth -----------------------------

def test_the_sandbox_allows_its_route_origin(ab):
    cfg = ui_config(sandboxDashboardRoute="alice-dashboard.apps.example.com")
    assert ab.sandbox_ui_origins(cfg, "default", "notebook") == [
        "https://alice-dashboard.apps.example.com", "https://alice-default-notebook-ui.apps.example.com"]
    assert ab.sandbox_ui_origins(cfg, "cuda-dev", "cuda-sandbox") == [
        "https://alice-dashboard.apps.example.com"]


def test_start_openclaw_sets_the_origins(ab, fake_env, config, profiles, creds):
    config = {**config, "sandboxUi": [ENTRY], "sandboxUiProxy": PROXY}
    make_applier(ab, config, creds).apply(profiles)
    scripts = [c[-1] for c in fake_env.openshell_calls()
               if c[:2] == ["sandbox", "exec"] and c[3] == "notebook"]
    assert any("gateway.controlUi.allowedOrigins" in s and
               "https://alice-default-notebook-ui.apps.example.com" in s for s in scripts)
    run = next(s for s in scripts if "openclaw gateway run" in s)
    assert "--bind lan" in run, "the gateway listens on 0.0.0.0 in the sandbox"


def config_sets(script):
    """{path: value} of the script's `openclaw config set` lines (the first
    one per path: later ones are fallbacks)."""
    import shlex
    out = {}
    for line in script.splitlines():
        if line.startswith("openclaw config set "):
            _, _, _, path, value = shlex.split(line)[:5]
            out.setdefault(path, value)
    return out


def test_a_ui_sandbox_trusts_the_proxy(ab):
    """Behind the owner-only oauth2-proxy the Control UI needs no token: the
    gateway trusts the proxy's user header from loopback (where the forward
    arrives), for the users the proxy admits."""
    script = ab.openclaw_gateway_script(ui_config(), "default", "notebook", "OPENCLAW_HOME=/sandbox")
    sets = config_sets(script)
    assert json.loads(sets["gateway.auth.mode"]) == "trusted-proxy"
    assert json.loads(sets["gateway.trustedProxies"]) == ["127.0.0.1/32", "::1/128"]
    trusted = json.loads(sets["gateway.auth.trustedProxy"])
    # Found live: oauth2-proxy's X-Forwarded-User is the Keycloak subject (a
    # UUID); X-Forwarded-Email carries preferred_username (OIDC_EMAIL_CLAIM).
    assert trusted["userHeader"] == "x-forwarded-email"
    assert trusted["allowUsers"] == ["alice"]
    assert trusted["allowLoopback"] is True
    assert trusted["deviceAutoApprove"]["enabled"] is True
    lines = script.splitlines()
    assert lines.index(next(l for l in lines if "gateway.auth.mode" in l)) > \
        lines.index(next(l for l in lines if "gateway.auth.trustedProxy" in l)), "the mode comes last"


def run_gateway_script(tmp_path, script, refuse):
    """Runs the script with fake `openclaw` (refusing a trustedProxy value
    that contains `refuse`) and `node`; returns the config calls and the
    gateway's environment."""
    import os
    import subprocess
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    (bin_dir / "openclaw").write_text(f"""#!/bin/sh
echo "$*" >> {calls}
case "$*" in
  "config set gateway.auth.trustedProxy "*{refuse}*) echo "Invalid config: unrecognized key" >&2; exit 1;;
  "gateway run"*) env | grep -E "^OPENCLAW_GATEWAY_(TOKEN|PASSWORD)=" | cut -d= -f1 >> {calls};;
esac
""")
    (bin_dir / "node").write_text("#!/bin/sh\necho s3cret\n")
    for f in ("openclaw", "node"):
        (bin_dir / f).chmod(0o755)
    stop = next(l for l in script.splitlines() if l.startswith("for d in /proc/"))
    script = script.replace(stop, ":").replace("nohup ", "")
    subprocess.run(["sh", "-c", script], check=True, timeout=30,
                   env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"})
    import time
    time.sleep(0.5)
    return calls.read_text().splitlines()


def test_an_older_openclaw_gets_the_trusted_proxy_form_it_accepts(ab, tmp_path):
    """Found live: the NemoClaw image's OpenClaw 2026.7.1 refused the full
    trustedProxy value, the mode was set anyway and the gateway did not
    start (502). Smaller forms are tried; the mode follows a saved one."""
    script = ab.openclaw_gateway_script(ui_config(), "default", "notebook", "OPENCLAW_HOME=/sandbox")
    calls = run_gateway_script(tmp_path, script, refuse="deviceAutoApprove")
    sets = [c for c in calls if c.startswith("config set gateway.auth.trustedProxy")]
    assert len(sets) == 2 and "allowLoopback" in sets[1] and "deviceAutoApprove" not in sets[1]
    assert "config set gateway.auth.mode \"trusted-proxy\"" in calls
    assert calls[-1] == "OPENCLAW_GATEWAY_PASSWORD"


def test_an_openclaw_without_trusted_proxy_keeps_token_auth(ab, tmp_path):
    script = ab.openclaw_gateway_script(ui_config(), "default", "notebook", "OPENCLAW_HOME=/sandbox")
    calls = run_gateway_script(tmp_path, script, refuse="userHeader")
    assert len([c for c in calls if c.startswith("config set gateway.auth.trustedProxy")]) == 3
    assert "config set gateway.auth.mode \"trusted-proxy\"" not in calls
    assert "config set gateway.auth.mode \"token\"" in calls
    assert calls[-1] == "OPENCLAW_GATEWAY_TOKEN"


def test_the_cli_password_survives_config_set(ab):
    """Found live: `config set` removes gateway.auth.password in trusted-proxy
    mode (openclaw/openclaw#162216) and the CLI got "device-required". The
    password is written into the file after the last `config set`, and the
    gateway also gets it from its environment."""
    script = ab.openclaw_gateway_script(ui_config(), "default", "notebook", "OPENCLAW_HOME=/sandbox")
    lines = script.splitlines()
    write = next(i for i, l in enumerate(lines) if "c.gateway.auth.password" in l)
    last_set = max(i for i, l in enumerate(lines) if l.startswith("openclaw config set"))
    assert write > last_set
    assert lines[write].startswith('SAW_GATEWAY_SECRET="$secret" node -e')
    assert "gateway.auth.password" not in config_sets(script)
    assert 'OPENCLAW_GATEWAY_PASSWORD="$secret" nohup openclaw gateway run' in script


def test_the_password_writer_keeps_the_rest_of_the_config(ab, tmp_path):
    import shutil
    import subprocess
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"auth": {"mode": "trusted-proxy"}, "port": 18789}, "x": 1}))
    subprocess.run(["node", "-e", ab._WRITE_PASSWORD_JS, str(cfg)], check=True,
                   env={**__import__("os").environ, "SAW_GATEWAY_SECRET": "s" * 48})
    assert json.loads(cfg.read_text()) == {
        "gateway": {"auth": {"mode": "trusted-proxy", "password": "s" * 48}, "port": 18789}, "x": 1}
    read = subprocess.run(["node", "-e", ab._READ_SECRET_JS, str(cfg)], capture_output=True, text=True)
    assert read.stdout == "s" * 48


def test_other_sandboxes_keep_token_auth(ab):
    for cfg, ws, sb in [(ui_config(), "cuda-dev", "cuda-sandbox"),
                        (ui_config(sandboxUiProxy={**PROXY, "trustedProxy": {"enabled": False}}),
                         "default", "notebook")]:
        script = ab.openclaw_gateway_script(cfg, ws, sb, "OPENCLAW_HOME=/sandbox")
        sets = config_sets(script)
        assert json.loads(sets["gateway.auth.mode"]) == "token"
        assert "gateway.auth.trustedProxy" not in sets
        assert "openclaw config unset gateway.auth.trustedProxy" in script
        assert 'OPENCLAW_GATEWAY_TOKEN="$secret" nohup openclaw gateway run' in script


def test_the_gateway_secret_is_kept_and_stays_in_the_sandbox(ab):
    """Read from the config file, made only when there is none: a re-run does
    not log out the CLI or the UI, and the installer never sees the secret."""
    script = ab.openclaw_gateway_script(ui_config(), "default", "notebook", "OPENCLAW_HOME=/sandbox")
    assert "/sandbox/.openclaw/openclaw.json" in script
    assert '[ -n "$secret" ] || secret=$(node -e' in script
    assert "randomBytes" in script


def test_a_rerun_restarts_the_gateway(ab, tmp_path):
    """A running gateway is stopped first, so new settings apply; the stop
    loop skips shells (this script's own sh -c contains the pattern)."""
    import subprocess
    import sys
    script = ab.openclaw_gateway_script(ui_config(), "default", "notebook", "OPENCLAW_HOME=/sandbox")
    stop = next(l for l in script.splitlines() if l.startswith("for d in /proc/"))
    assert script.index(stop) < script.index("nohup openclaw gateway run")
    gateway = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)",
                                "openclaw", "gateway", "run"])
    try:
        done = subprocess.run(["sh", "-c", stop.replace("sleep 2", "sleep 0.2") + "; echo alive"],
                              capture_output=True, text=True, timeout=30)
        assert done.stdout.strip() == "alive"
        assert gateway.wait(timeout=10) != 0
    finally:
        gateway.kill()


def test_start_openclaw_runs_the_gateway_script(ab, fake_env, config, profiles, creds):
    config = {**config, "sandboxUi": [ENTRY], "sandboxUiProxy": PROXY}
    make_applier(ab, config, creds).apply(profiles)
    scripts = [c[-1] for c in fake_env.openshell_calls()
               if c[:2] == ["sandbox", "exec"] and c[3] == "notebook"]
    run = next(s for s in scripts if "openclaw gateway run" in s)
    assert "gateway.auth.mode '\"trusted-proxy\"'" in run


def test_the_gateway_does_not_use_nemoclaws_explicit_proxy(ab):
    """Found live: NemoClaw's image points OpenClaw at 10.200.0.1:3128
    (OpenShell 0.0.x's explicit proxy); OpenShell 0.1.x refuses it, so every
    LLM call failed. The script removes that setting before the gateway
    starts, in every mode."""
    for cfg, ws, sb in [(ui_config(), "default", "notebook"), (ui_config(), "cuda-dev", "cuda-sandbox")]:
        script = ab.openclaw_gateway_script(cfg, ws, sb, "OPENCLAW_HOME=/sandbox")
        assert "openclaw config unset proxy >/dev/null 2>&1 || true" in script
        assert script.index("openclaw config unset proxy") < script.index("openclaw gateway run")
