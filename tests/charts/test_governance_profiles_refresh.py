"""Slack and Gmail governance profiles: read-only, refreshable, reachable by node."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "charts" / "governance-policy" / "profiles"


@pytest.mark.parametrize("name, token_url, env", [
    ("slack", "https://slack.com/api/oauth.v2.access", "SLACK_BOT_TOKEN"),
    ("gmail", "https://oauth2.googleapis.com/token", "GMAIL_ACCESS_TOKEN")])
def test_the_gateway_can_refresh_the_token(name, token_url, env):
    doc = yaml.safe_load((PROFILES / f"{name}.yaml").read_text())
    [cred] = doc["credentials"]
    assert env in cred["env_vars"] and cred["auth_style"] == "bearer"
    refresh = cred["refresh"]
    assert refresh["strategy"] == "oauth2_refresh_token" and refresh["token_url"] == token_url
    material = {m["name"]: m for m in refresh["material"]}
    assert set(material) == {"client_id", "client_secret", "refresh_token"}
    assert material["client_secret"]["secret"] and material["refresh_token"]["secret"]
    assert 0 < refresh["refresh_before_seconds"] < refresh["max_lifetime_seconds"]


@pytest.mark.parametrize("name", ["slack", "gmail"])
def test_read_only_and_reachable_from_node(name):
    doc = yaml.safe_load((PROFILES / f"{name}.yaml").read_text())
    methods = {r["allow"]["method"] for e in doc["endpoints"] for r in e["rules"]}
    assert methods == {"GET"}
    assert {"/usr/bin/node-*", "/usr/local/bin/node"} <= set(doc["binaries"])


def _installer():
    import importlib.util
    path = ROOT / "charts" / "openshell-saw" / "files" / "installer" / "apply_bom.py"
    spec = importlib.util.spec_from_file_location("apply_bom_for_profiles", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("name", ["slack", "gmail"])
def test_installer_requires_what_the_profile_requires(name):
    # The gateway refuses `provider refresh configure` without the material
    # the profile marks required; the installer must not send less.
    doc = yaml.safe_load((PROFILES / f"{name}.yaml").read_text())
    [cred] = doc["credentials"]
    profile = {m["name"]: bool(m.get("required")) for m in cred["refresh"]["material"]}
    installer = _installer().REFRESH_MATERIAL["oauth2-refresh-token"]
    assert set(profile) == set(installer)
    assert {k for k, r in profile.items() if r} == {k for k, r in installer.items() if r}


@pytest.mark.parametrize("name, paths", [
    ("slack", ["/api/conversations.list", "/api/conversations.history", "/api/users.info"]),
    ("gmail", ["/gmail/v1/users/me/messages", "/gmail/v1/users/me/messages/18c2f0a1b2c3d4e5"])])
def test_the_briefing_readers_calls_are_allowed(name, paths):
    # OpenShell drops the query string and glob-matches the path; '*' stays
    # within one segment.
    import fnmatch
    import re
    doc = yaml.safe_load((PROFILES / f"{name}.yaml").read_text())
    rules = [r["allow"]["path"] for e in doc["endpoints"] for r in e["rules"]]
    readers = ROOT / "charts" / "saw-bom" / "harness" / "daily-briefing" / "mcp"
    source = (readers / f"{name}-reader.mjs").read_text()
    for path in paths:
        tail = path.rsplit("/", 1)[-1]
        assert tail in source or re.search(r"/messages/\$\{", source), path
        assert any(re.fullmatch(fnmatch.translate(rule).replace(".*", "[^/]*"), path)
                   for rule in rules), path
