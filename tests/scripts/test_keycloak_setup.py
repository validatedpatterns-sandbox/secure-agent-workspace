"""scripts/keycloak-check.sh and the existing-Keycloak paths of
scripts/deploy-keycloak.sh (make keycloak-check / make keycloak)."""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent
GOOD_REALM = {"pkce": True, "device": True, "clients": {"openshell-cli": {"public": True, "device": True}}}


@pytest.fixture
def kc(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("oc", "curl", "helm"):
        (bin_dir / tool).symlink_to(HERE / "fake_kc_env")
    state = tmp_path / "state"
    state.mkdir()

    class Env:
        def set(self, **st):
            base = {"keycloaks": ["keycloak"], "host": "sso.example.com", "realms": {}, "imports": {}}
            (state / "kc.json").write_text(json.dumps({**base, **st}))

        def state(self):
            return json.loads((state / "kc.json").read_text())

        def log(self):
            path = state / "calls.log"
            return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

        def calls(self, tool):
            path = state / "calls.log"
            return [c[1:] for c in map(json.loads, path.read_text().splitlines()) if c[0] == tool] if path.exists() else []

        def run(self, script, stdin=subprocess.DEVNULL, **env):
            e = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_STATE": str(state),
                 "KEYCLOAK_NS": "keycloak", **env}
            return subprocess.run(["bash", str(ROOT / "scripts" / script)], env=e, stdin=stdin,
                                  capture_output=True, text=True)
    return Env()


# -- keycloak-check.sh ----------------------------------------------------------

def test_check_passes_for_a_configured_realm(kc):
    kc.set(realms={"sso": GOOD_REALM}, imports={"sso": ["openshell-admin", "openshell-user"]})
    r = kc.run("keycloak-check.sh", KEYCLOAK_REALM="sso")
    assert r.returncode == 0, r.stdout
    assert "OIDC issuer: https://sso.example.com/realms/sso" in r.stdout


@pytest.mark.parametrize("realm, expect", [
    (None, "realm 'openshell' not found"),
    ({**GOOD_REALM, "clients": {}}, "client openshell-cli is missing or not public"),
    ({**GOOD_REALM, "clients": {"openshell-cli": {"public": False, "device": True}}}, "missing or not public"),
    ({**GOOD_REALM, "clients": {"openshell-cli": {"public": True, "device": False}}}, "does not allow the device flow"),
    ({**GOOD_REALM, "pkce": False}, "PKCE S256 not supported"),
])
def test_check_reports_what_is_missing(kc, realm, expect):
    kc.set(realms={"openshell": realm} if realm else {})
    r = kc.run("keycloak-check.sh")
    assert r.returncode == 1 and expect in r.stdout, r.stdout


def test_device_request_carries_a_pkce_challenge(kc):
    """Found live: the imported realm's client enforces PKCE, and Keycloak
    rejected a device request without a challenge (invalid_request)."""
    kc.set(realms={"openshell": GOOD_REALM}, imports={"openshell": ["openshell-admin", "openshell-user"]})
    r = kc.run("keycloak-check.sh")
    assert r.returncode == 0, r.stdout
    (device,) = [c for c in kc.calls("curl") if c[-1].endswith("/auth/device") or any(a.endswith("/auth/device") for a in c)]
    assert "code_challenge_method=S256" in device
    assert any(a.startswith("code_challenge=") and len(a) > 50 for a in device)


def test_check_shows_keycloaks_error_description(kc):
    kc.set(realms={"openshell": {**GOOD_REALM, "clients": {"openshell-cli": {"public": True, "device": False}}}})
    assert "unauthorized_client" in kc.run("keycloak-check.sh").stdout


def test_check_reports_missing_roles(kc):
    kc.set(realms={"openshell": GOOD_REALM}, imports={"openshell": ["openshell-user"]})
    r = kc.run("keycloak-check.sh")
    assert r.returncode == 1 and "realm role openshell-admin missing" in r.stdout


def test_roles_not_visible_is_a_warning_not_a_failure(kc):
    kc.set(realms={"openshell": GOOD_REALM})
    r = kc.run("keycloak-check.sh")
    assert r.returncode == 0 and "WARN  realm roles not verifiable" in r.stdout


def test_check_without_any_keycloak(kc):
    kc.set(keycloaks=[])
    r = kc.run("keycloak-check.sh", KEYCLOAK_NS="nowhere")
    assert r.returncode == 1 and "no Keycloak found in nowhere" in r.stdout


# -- deploy-keycloak.sh (make keycloak) -------------------------------------------

def test_existing_configured_keycloak_is_used_as_is(kc):
    kc.set(realms={"openshell": GOOD_REALM})
    r = kc.run("deploy-keycloak.sh")
    assert r.returncode == 0 and "Using the existing Keycloak; nothing to deploy." in r.stdout
    assert kc.calls("helm") == []


def test_unconfigured_existing_keycloak_needs_an_answer_when_not_interactive(kc):
    kc.set(realms={"sso": GOOD_REALM})
    r = kc.run("deploy-keycloak.sh")
    assert r.returncode == 1 and "USE_EXISTING_KEYCLOAK=yes" in r.stderr
    assert kc.calls("helm") == []


def test_declining_the_existing_keycloak_changes_nothing(kc):
    kc.set(realms={"sso": GOOD_REALM})
    r = kc.run("deploy-keycloak.sh", USE_EXISTING_KEYCLOAK="no")
    assert r.returncode == 1 and "Not using 'keycloak'" in r.stdout
    assert kc.calls("helm") == []


def test_accepting_imports_only_the_realm_into_the_existing_keycloak(kc):
    kc.set(realms={"sso": GOOD_REALM})
    r = kc.run("deploy-keycloak.sh", USE_EXISTING_KEYCLOAK="yes")
    assert r.returncode == 0, r.stdout + r.stderr
    (helm,) = kc.calls("helm")
    assert "keycloak.existing=keycloak" in helm and "keycloak.realm=openshell" in helm
    assert "openshell-keycloak" not in kc.state()["keycloaks"]      # no second server
    assert "OIDC issuer: https://sso.example.com/realms/openshell" in r.stdout


def test_an_existing_but_misconfigured_realm_is_not_overwritten(kc):
    kc.set(realms={"openshell": {**GOOD_REALM, "clients": {}}})
    r = kc.run("deploy-keycloak.sh", USE_EXISTING_KEYCLOAK="yes")
    assert r.returncode == 1 and "already exists on 'keycloak' but is not configured" in r.stderr
    assert kc.calls("helm") == []


def test_no_keycloak_deploys_one(kc):
    kc.set(keycloaks=[])
    r = kc.run("deploy-keycloak.sh")
    assert r.returncode == 0, r.stdout + r.stderr
    (helm,) = kc.calls("helm")
    assert "keycloak.existing" not in " ".join(helm) and "keycloak.realm=openshell" in helm
    # The test users' passwords are generated before the realm import reads them.
    log = kc.log()
    made = next(i for i, c in enumerate(log)
                if c[:5] == ["oc", "create", "secret", "generic", "openshell-keycloak-user-passwords"])
    assert made < next(i for i, c in enumerate(log) if c[0] == "helm")
    users = {a.split("=", 2)[1] for a in log[made] if a.startswith("--from-literal=")}
    assert users == {"developer", "admin", "alice", "bob"}
