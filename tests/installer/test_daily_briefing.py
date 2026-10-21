"""The personal-assistant profile: Slack and Gmail providers whose access tokens
the gateway refreshes, and the daily-briefing harness bundle on the NemoClaw
sandbox."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from conftest import ROOT, harness_files, profile_files

BUNDLE = ROOT / "harness-bundles" / "daily-briefing"
REFRESH = {"client_id": "app-123.apps", "client_secret": "s3cr3t-CLIENT", "refresh_token": "1//r3fr3sh-TOKEN"}


@pytest.fixture
def briefing_secrets(secrets_dir):
    for secret in ("slack", "gmail"):
        (secrets_dir / secret).mkdir()
        (secrets_dir / secret / "provider").write_text(secret)
        for key, value in REFRESH.items():
            (secrets_dir / secret / key).write_text(f"{secret}-{value}\n")
    return secrets_dir


@pytest.fixture
def briefing(ab):
    return ab.parse_profiles(profile_files("personal-assistant"))


@pytest.fixture
def catalog(fake_env):
    (fake_env.state / "catalog.json").write_text(json.dumps({
        "nvidia": ["integrate.api.nvidia.com"], "brave": ["api.search.brave.com"],
        "web-search": ["api.tavily.com"], "slack": ["slack.com"], "gmail": ["gmail.googleapis.com"]}))


def applier(ab, config, creds, **extra):
    return ab.ProfileApplier(ab.Shell(), {**config, "allowDriverConfig": True, **extra}, creds,
                             harness={"bundles": ab.parse_harness_files(harness_files(("daily-briefing",)))})


def calls(fake_env, *prefix):
    return [c for c in fake_env.openshell_calls() if c[:len(prefix)] == list(prefix)]


# -- providers and refresh -----------------------------------------------------------

def test_refresh_material_reaches_the_gateway_through_the_environment(
        ab, fake_env, config, briefing, briefing_secrets, catalog, tmp_path):
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    ledger = tmp_path / "user" / "managed.json"
    applier(ab, config, creds, prune={"ledgerPath": str(ledger)}).apply(briefing)
    state = fake_env.openshell_state()
    for name, key in (("slack", "SLACK_BOT_TOKEN"), ("gmail", "GMAIL_ACCESS_TOKEN")):
        provider = state["providers"][f"personal-assistant/{name}"]
        assert provider["refresh"][key] == {
            "strategy": "oauth2-refresh-token",
            "material": {k: f"{name}-{v}" for k, v in REFRESH.items()}}
        assert provider["credential"].startswith(f"{key}=minted-"), "rotated right away"
    argv = json.dumps(fake_env.openshell_calls())
    for value in REFRESH.values():
        assert value not in argv, "refresh material never goes through argv"
    assert len(calls(fake_env, "provider", "refresh", "configure")) == 2
    assert json.loads((tmp_path / "user" / "refresh.json").read_text()).keys() == {
        "personal-assistant/slack", "personal-assistant/gmail"}


def test_unchanged_material_is_not_sent_again(ab, fake_env, config, briefing, briefing_secrets,
                                              catalog, tmp_path):
    """The gateway keeps a rotated refresh token (Slack rotates them); sending
    the Secret's original again would undo that. Nor is the minted token
    replaced by the bootstrap credential."""
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    prune = {"ledgerPath": str(tmp_path / "user" / "managed.json")}
    applier(ab, config, creds, prune=prune).apply(briefing)
    minted = fake_env.openshell_state()["providers"]["personal-assistant/gmail"]["credential"]
    applier(ab, config, creds, prune=prune).apply(briefing)
    assert len(calls(fake_env, "provider", "refresh", "configure")) == 2
    assert fake_env.openshell_state()["providers"]["personal-assistant/gmail"]["credential"] == minted
    assert not [c for c in calls(fake_env, "provider", "update") if c[2] in ("slack", "gmail")]
    # New material in the Secret: configured again.
    (briefing_secrets / "gmail" / "refresh_token").write_text("1//new-refresh\n")
    briefing = ab.parse_profiles(profile_files("personal-assistant"))
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    applier(ab, config, creds, prune=prune).apply(briefing)
    configured = calls(fake_env, "provider", "refresh", "configure")
    assert len(configured) == 3 and configured[-1][3] == "gmail"


def test_a_token_without_refresh_material_is_used_as_is(ab, briefing, briefing_secrets):
    for key in REFRESH:
        (briefing_secrets / "slack" / key).unlink()
    (briefing_secrets / "slack" / "bot_token").write_text("xoxb-STATIC\n")
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    pa = next(ws for ws in briefing[0].workspaces if ws.name == "personal-assistant")
    slack = next(p for p in pa.providers if p.name == "slack")
    assert creds["personal-assistant"]["slack"] == "xoxb-STATIC" and slack.refresh_strategy == ""
    gmail = next(p for p in pa.providers if p.name == "gmail")
    assert gmail.refresh_strategy == "oauth2-refresh-token"
    assert creds["personal-assistant"]["gmail"] == ab.REFRESH_BOOTSTRAP_CREDENTIAL


def test_material_without_the_client_secret_is_not_refreshed(ab, briefing, briefing_secrets):
    # The profiles require client_secret, so the gateway would refuse the
    # refresh: with a token the provider is static, without one it is refused.
    (briefing_secrets / "slack" / "client_secret").unlink()
    (briefing_secrets / "slack" / "bot_token").write_text("xoxb-STATIC\n")
    (briefing_secrets / "gmail" / "client_secret").unlink()
    with pytest.raises(ab.InstallerError, match="'gmail' needs refresh material"):
        ab.resolve_credentials(briefing, briefing_secrets)
    (briefing_secrets / "gmail" / "access_token").write_text("ya29.STATIC\n")
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    pa = next(ws for ws in briefing[0].workspaces if ws.name == "personal-assistant")
    assert {p.name: p.refresh_strategy for p in pa.providers if p.name != "nvidia"} == {
        "slack": "", "gmail": ""}
    assert creds["personal-assistant"]["slack"] == "xoxb-STATIC" and creds["personal-assistant"]["gmail"] == "ya29.STATIC"


def test_neither_material_nor_token_is_refused(ab, briefing, briefing_secrets):
    for key in REFRESH:
        (briefing_secrets / "gmail" / key).unlink()
    with pytest.raises(ab.InstallerError, match="'gmail' needs refresh material"):
        ab.resolve_credentials(briefing, briefing_secrets)


def test_an_unknown_refresh_strategy_is_refused(ab):
    files = profile_files("personal-assistant")
    key = next(k for k in files if k.endswith("personal-assistant__providers.yaml"))
    files[key] = files[key].replace("strategy: oauth2-refresh-token", "strategy: magic", 1)
    with pytest.raises(ab.InstallerError, match="unsupported refresh strategy 'magic'"):
        ab.validate_profiles(ab.parse_profiles(files))


# -- the bundle on the NemoClaw sandbox ---------------------------------------------

def test_the_nemoclaw_sandbox_is_created_with_the_bundle_mounted(
        ab, fake_env, config, briefing, briefing_secrets, catalog):
    """`nemoclaw onboard` cannot add the mount on podman, so the installer
    creates the sandbox itself, with the harness volume, and configures
    OpenClaw (the MCP servers come from the bundle's mcp.json)."""
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    applier(ab, config, creds).apply(briefing)
    assert not [c for c in fake_env.other_calls("nemoclaw") if c["args"][:1] == ["onboard"]]
    sb = fake_env.openshell_state()["sandboxes"]["personal-assistant/assistant"]
    mounts = sb["driverConfig"]["podman"]["mounts"]
    assert [(m["target"], m["read_only"]) for m in mounts] == [
        ("/sandbox/harness", True),
        ("/sandbox/.saw/trusted", True),
        ("/sandbox/.saw/audit", False)]
    assert set(sb["providers"]) == {"nvidia", "slack", "gmail"}
    scripts = "\n".join(c[-1] for c in calls(fake_env, "sandbox", "exec") if c[3] == "assistant")
    assert """openclaw config set plugins.load.paths '["/sandbox/harness", "/sandbox/.saw/trusted/plugin"]'""" in scripts


def test_the_bundle_is_enabled_with_capability_consent(
        ab, fake_env, config, briefing, briefing_secrets, catalog):
    """Found live on OpenClaw 2026.9.2: a bundle on plugins.load.paths stays
    disabled ("not in allowlist") until `plugins enable` adds it to NemoClaw's
    restrictive plugins.allow; older releases may not know the flag."""
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    applier(ab, config, creds).apply(briefing)
    scripts = "\n".join(c[-1] for c in calls(fake_env, "sandbox", "exec") if c[3] == "assistant")
    assert "openclaw plugins enable daily-briefing --accept-capabilities || " in scripts
    assert scripts.index("config set plugins.load.paths") < scripts.index("plugins enable")


def test_the_readers_are_declared_where_openclaw_expands_their_placeholders(
        ab, fake_env, config, briefing, briefing_secrets, catalog):
    """Found live: from the bundle's mcp.json the Slack reader got the literal
    text ${SLACK_BOT_TOKEN} (Slack: invalid_auth). Re-declared in
    openclaw.json, OpenClaw puts the provider's placeholder in."""
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    applier(ab, config, creds).apply(briefing)
    cfg = fake_env.openshell_state()["sandboxes"]["personal-assistant/assistant"]["openclawConfig"]
    slack, gmail = cfg["mcp.servers.slack-reader"], cfg["mcp.servers.gmail-reader"]
    assert slack["args"] == ["/sandbox/harness/mcp/slack-reader.mjs"]
    assert slack["env"]["SLACK_BOT_TOKEN"] == "${SLACK_BOT_TOKEN}"
    assert gmail["env"]["GMAIL_ACCESS_TOKEN"] == "${GMAIL_ACCESS_TOKEN}"
    assert slack["env"]["NODE_EXTRA_CA_CERTS"] == "${NODE_EXTRA_CA_CERTS}"


def test_openclaws_own_slack_channel_stays_off(
        ab, fake_env, config, briefing, briefing_secrets, catalog):
    """Found live: with the Slack provider attached, the gateway treats its
    slack channel as configured, tries to install @openclaw/slack from npm at
    startup (egress denied) and does not start. The provider is for the
    harness's governed reads, not for an OpenClaw chat channel."""
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    applier(ab, config, creds).apply(briefing)
    execs = [c[-1] for c in calls(fake_env, "sandbox", "exec") if c[3] == "assistant"]
    scripts = "\n".join(execs)
    assert "openclaw config set channels.slack.enabled false" in scripts
    assert "channels.gmail" not in scripts
    gateway = next(i for i, s in enumerate(execs) if "openclaw gateway run" in s)
    channel = next(i for i, s in enumerate(execs) if "channels.slack.enabled" in s)
    assert channel < gateway


def test_the_bundle_needs_the_slack_and_gmail_profiles(ab, fake_env, config, briefing,
                                                        briefing_secrets, catalog):
    (fake_env.state / "catalog.json").write_text(json.dumps({"nvidia": ["integrate.api.nvidia.com"]}))
    creds = ab.resolve_credentials(briefing, briefing_secrets)
    with pytest.raises(ab.InstallerError):
        applier(ab, config, creds).apply(briefing)
    assert "personal-assistant/assistant" not in (fake_env.openshell_state() or {}).get("sandboxes", {})


def test_an_attached_provider_restarts_the_gateway(ab):
    """The gateway keeps the environment it started with: a new provider's
    placeholder reaches the agent only after a restart."""
    a = ab.openclaw_gateway_script({}, "personal-assistant", "assistant", "OPENCLAW_HOME=/sandbox",
                                   providers=["nvidia"])
    b = ab.openclaw_gateway_script({}, "personal-assistant", "assistant", "OPENCLAW_HOME=/sandbox",
                                   providers=["nvidia", "slack", "gmail"])
    fingerprint = lambda s: next(l for l in s.splitlines() if "saw-gateway.sha256" in l and "!=" in l)  # noqa: E731
    assert fingerprint(a) != fingerprint(b)
    assert ab.openclaw_gateway_script({}, "w", "s", "X=1", providers=["b", "a"]) == \
        ab.openclaw_gateway_script({}, "w", "s", "X=1", providers=["a", "b"])


def test_the_bundle_is_valid_and_the_chart_copy_matches():
    out = subprocess.run(["python3", str(ROOT / "charts/openshell-saw/files/installer/apply_bom.py"),
                          "check-bundle", str(BUNDLE)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr

    def tree(path):
        return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*")
                if p.is_file() and not p.name.startswith(".")}
    assert tree(BUNDLE) == tree(ROOT / "charts" / "saw-bom" / "harness" / "daily-briefing")
    doc = yaml.safe_load((BUNDLE / "harness.yaml").read_text())
    assert {s["name"]: s["governanceProfile"] for s in doc["spec"]["mcpServers"]} == {
        "slack-reader": "slack", "gmail-reader": "gmail"}
    servers = json.loads((BUNDLE / "mcp.json").read_text())["mcpServers"]
    # The provider's placeholder, and the proxy CA (OpenClaw passes neither on).
    ca = {"NODE_EXTRA_CA_CERTS": "${NODE_EXTRA_CA_CERTS}"}
    assert servers["slack-reader"]["env"] == {"SLACK_BOT_TOKEN": "${SLACK_BOT_TOKEN}", **ca}
    assert servers["gmail-reader"]["env"] == {"GMAIL_ACCESS_TOKEN": "${GMAIL_ACCESS_TOKEN}", **ca}


# -- the MCP servers, against fake Slack and Gmail ----------------------------------

FAKE_APIS = r'''
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
const day = Math.floor(new Date(new Date().setHours(0, 0, 0, 0)).getTime() / 1000);
let slackTs = day + 60, mails = ["m1"];
const reply = (res, body) => { res.writeHead(200, {"content-type": "application/json"}); res.end(JSON.stringify(body)); };
const handler = (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.headers.authorization !== `Bearer ${url.pathname.startsWith("/slack") ? "slack-ph" : "gmail-ph"}`)
    return reply(res, {ok: false, error: "invalid_auth"});
  if (url.pathname === "/slack/conversations.list")
    return reply(res, {ok: true, channels: [{id: "C1", name: "eng", is_member: true}, {id: "C2", name: "random", is_member: false}]});
  if (url.pathname === "/slack/conversations.history") {
    const oldest = Number(url.searchParams.get("oldest"));
    const msgs = [{ts: String(slackTs), user: "U1", text: "Can you review the PR today?"}].filter((m) => Number(m.ts) > oldest);
    return reply(res, {ok: true, messages: msgs});
  }
  if (url.pathname === "/slack/users.info") return reply(res, {ok: true, user: {real_name: "Dana"}});
  if (url.pathname === "/gmail/messages") return reply(res, {messages: mails.map((id) => ({id}))});
  if (url.pathname.startsWith("/gmail/messages/"))
    return reply(res, {id: "m1", internalDate: String(day * 1000 + 5000), snippet: "Quarterly numbers attached",
      labelIds: ["UNREAD"], payload: {headers: [{name: "From", value: "cfo@example.com"}, {name: "Subject", value: "Q3"}]}});
  res.writeHead(404); res.end();
};
// FAKE_TLS_DIR: serve HTTPS with that directory's self-signed cert (the
// stand-in for the sandbox egress proxy, which re-signs TLS with its own CA).
const tls = process.env.FAKE_TLS_DIR;
(tls ? https.createServer({ key: readFileSync(`${tls}/key.pem`), cert: readFileSync(`${tls}/cert.pem`) }, handler)
     : http.createServer(handler))
  .listen(0, "127.0.0.1", function () { console.log(this.address().port); });
'''


def mcp_call(server, env, tool):
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool, "arguments": {}}}]
    proc = subprocess.Popen(["node", str(BUNDLE / "mcp" / server)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, env=env)
    for m in msgs:
        proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
    replies = {}
    while len(replies) < 3:
        line = proc.stdout.readline()
        if not line:
            break
        msg = json.loads(line)
        replies[msg["id"]] = msg
    proc.kill()
    return replies


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
def test_the_readers_return_only_new_messages(tmp_path):
    (tmp_path / "apis.mjs").write_text(FAKE_APIS)
    api = subprocess.Popen(["node", str(tmp_path / "apis.mjs")], stdout=subprocess.PIPE, text=True)
    try:
        port = api.stdout.readline().strip()
        import os
        env = {**os.environ, "BRIEFING_DIR": str(tmp_path / "briefing"),
               "SLACK_API_URL": f"http://127.0.0.1:{port}/slack", "SLACK_BOT_TOKEN": "slack-ph",
               "GMAIL_API_URL": f"http://127.0.0.1:{port}/gmail", "GMAIL_ACCESS_TOKEN": "gmail-ph"}
        first = mcp_call("slack-reader.mjs", env, "new_messages")
        assert [t["name"] for t in first[2]["result"]["tools"]] == ["new_messages", "channels"]
        result = json.loads(first[3]["result"]["content"][0]["text"])
        assert result["channels"] == ["#eng"] and result["new"] == 1
        assert result["items"][0] | {"time": None} == {
            "source": "slack", "channel": "#eng", "from": "Dana", "time": None,
            "text": "Can you review the PR today?", "replies": 0}
        again = json.loads(mcp_call("slack-reader.mjs", env, "new_messages")[3]["result"]["content"][0]["text"])
        assert again["new"] == 0, "only what arrived since the last call"
        mail = json.loads(mcp_call("gmail-reader.mjs", env, "new_messages")[3]["result"]["content"][0]["text"])
        assert mail["new"] == 1 and mail["items"][0]["subject"] == "Q3" and mail["items"][0]["unread"]
        assert json.loads(mcp_call("gmail-reader.mjs", env, "new_messages")[3]["result"]["content"][0]["text"])["new"] == 0
        items = Path(result["file"]).read_text().splitlines()
        assert [json.loads(i)["source"] for i in items] == ["slack", "gmail"]
        # A denial (here: a wrong token) comes back as a tool error, not a crash.
        bad = mcp_call("slack-reader.mjs", {**env, "SLACK_BOT_TOKEN": "other"}, "new_messages")[3]["result"]
        assert bad["isError"] and "invalid_auth" in bad["content"][0]["text"]
        missing = mcp_call("gmail-reader.mjs", {k: v for k, v in env.items() if k != "GMAIL_ACCESS_TOKEN"},
                           "new_messages")[3]["result"]
        assert missing["isError"] and "no gmail provider" in missing["content"][0]["text"]
    finally:
        api.kill()


@pytest.mark.skipif(not shutil.which("node") or not shutil.which("openssl"),
                    reason="node or openssl is not installed")
def test_the_readers_trust_the_proxy_ca_themselves(tmp_path):
    """Found live on OpenClaw 2026.9.2: NODE_EXTRA_CA_CERTS in mcp.json did not
    get the readers past the egress proxy's re-signed TLS
    (SELF_SIGNED_CERT_IN_CHAIN). The readers load the proxy CA file themselves
    (here pointed at a test CA with BRIEFING_PROXY_CA)."""
    import os
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(tmp_path / "key.pem"), "-out", str(tmp_path / "cert.pem")],
                   check=True, capture_output=True)
    (tmp_path / "apis.mjs").write_text(FAKE_APIS)
    api = subprocess.Popen(["node", str(tmp_path / "apis.mjs")], stdout=subprocess.PIPE, text=True,
                           env={**os.environ, "FAKE_TLS_DIR": str(tmp_path)})
    try:
        port = api.stdout.readline().strip()
        base = {k: v for k, v in os.environ.items() if k != "NODE_EXTRA_CA_CERTS"}
        env = {**base, "BRIEFING_DIR": str(tmp_path / "briefing"),
               "SLACK_API_URL": f"https://127.0.0.1:{port}/slack", "SLACK_BOT_TOKEN": "slack-ph"}
        untrusted = mcp_call("slack-reader.mjs", env, "new_messages")[3]["result"]
        assert untrusted["isError"] and "SELF_SIGNED" in untrusted["content"][0]["text"]
        trusted = mcp_call("slack-reader.mjs", {**env, "BRIEFING_PROXY_CA": str(tmp_path / "cert.pem")},
                           "new_messages")[3]["result"]
        assert not trusted.get("isError"), trusted
        assert json.loads(trusted["content"][0]["text"])["new"] == 1
    finally:
        api.kill()
