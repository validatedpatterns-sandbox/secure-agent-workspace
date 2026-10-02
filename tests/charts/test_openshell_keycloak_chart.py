"""charts/openshell-keycloak: own Keycloak, or only the realm for an existing one."""
import secrets
import shutil
import string
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshell-keycloak"
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def helm(*args):
    return subprocess.run([HELM, "template", "openshell-keycloak", str(CHART), "-n", "keycloak", *args],
                          capture_output=True, text=True)


def render(*args):
    out = helm(*args)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def realm_of(docs):
    (realm,) = [d for d in docs if d["kind"] == "KeycloakRealmImport"]
    return realm


def test_default_deploys_keycloak_database_and_realm():
    docs = render()
    kinds = {d["kind"] for d in docs}
    assert {"Keycloak", "KeycloakRealmImport", "Deployment"} <= kinds
    (realm,) = [d for d in docs if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["keycloakCRName"] == "openshell-keycloak"


def test_existing_mode_imports_only_the_realm_into_that_keycloak():
    docs = render("--set", "keycloak.existing=keycloak", "--set", "keycloak.realm=openshell")
    assert [d["kind"] for d in docs] == ["KeycloakRealmImport"]
    spec = docs[0]["spec"]
    assert spec["keycloakCRName"] == "keycloak"
    assert spec["realm"]["realm"] == "openshell"
    clients = {c["clientId"]: c for c in spec["realm"]["clients"]}
    assert clients["openshell-cli"]["publicClient"] is True
    assert {"openshell-admin", "openshell-user"} <= {r["name"] for r in spec["realm"]["roles"]["realm"]}


def test_client_lists_are_never_null(tmp_path):
    """Found live (Helm 4, server-side apply): the dashboard client's empty
    redirectUris/webOrigins rendered as null and the CRD rejected the import."""
    with_uri = tmp_path / "with-uri.yaml"
    with_uri.write_text("keycloak:\n  existing: keycloak\n  clients:\n    dashboard:\n"
                        "      redirectUris: [https://a.example.com/oauth2/callback]\n")
    for args in ((), ("--set", "keycloak.existing=keycloak"), ("-f", str(with_uri))):
        (realm,) = [d for d in render(*args) if d["kind"] == "KeycloakRealmImport"]
        for client in realm["spec"]["realm"]["clients"]:
            for key in ("redirectUris", "webOrigins"):
                assert isinstance(client.get(key), list), (args, client["clientId"], key)
    (realm,) = render("-f", str(with_uri))
    dash = next(c for c in realm["spec"]["realm"]["clients"] if c["clientId"] == "openshell-dashboard")
    assert dash["redirectUris"] == ["https://a.example.com/oauth2/callback"]


def test_no_test_users_and_users_without_roles_render_valid_lists(tmp_path):
    values = tmp_path / "users.yaml"
    values.write_text("keycloak:\n  testUsers:\n    - username: nobody\n")
    (realm,) = [d for d in render("-f", str(values)) if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["realm"]["users"][0]["realmRoles"] == []
    empty = tmp_path / "empty.yaml"
    empty.write_text("keycloak:\n  testUsers: []\n")
    (realm,) = [d for d in render("-f", str(empty)) if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["realm"]["users"] == []


# -- passwords: generated, never guessable defaults ---------------------------------

def test_no_test_user_has_a_password_in_values():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["keycloak"]["testUsers"]
    assert not [u["username"] for u in values["keycloak"]["testUsers"] if "password" in u]


def test_passwords_come_from_the_secret_as_placeholders():
    spec = realm_of(render())["spec"]
    users = spec["realm"]["users"]
    for i, user in enumerate(users):
        value = user["credentials"][0]["value"]
        assert value == f"${{SAW_USER_PASSWORD_{i}}}"
        assert spec["placeholders"][f"SAW_USER_PASSWORD_{i}"] == {
            "secret": {"name": "openshell-keycloak-user-passwords", "key": user["username"]}}


def test_the_realm_enforces_strong_passwords_and_locks_out_guessing():
    realm = realm_of(render())["spec"]["realm"]
    policy = realm["passwordPolicy"]
    for rule in ("length(14)", "upperCase(1)", "lowerCase(1)", "digits(1)", "specialChars(1)",
                 "notUsername", "notEmail", "passwordHistory"):
        assert rule in policy
    assert realm["bruteForceProtected"] is True
    # Users are added by an admin (make keycloak-add-users), not self-registered.
    assert realm["registrationAllowed"] is False
    assert realm["permanentLockout"] is False
    assert realm["failureFactor"] == 5


@pytest.mark.parametrize("password", ["alice", "alicealicealice1A!", "short1A!", "nouppercase12345!",
                                      "NoSpecialChars12345"])
def test_a_weak_explicit_password_fails_the_render(tmp_path, password):
    values = tmp_path / "weak.yaml"
    values.write_text(yaml.safe_dump({"keycloak": {"testUsers": [{"username": "alice", "password": password}]}}))
    result = helm("-f", str(values))
    assert result.returncode != 0 and "password is too weak" in result.stderr


def strong_password():
    """A password that meets the realm policy, made at test time so the
    repository holds no password-like literal (secret scanners)."""
    pick = secrets.SystemRandom()
    chars = [pick.choice(string.ascii_uppercase), pick.choice(string.ascii_lowercase),
             pick.choice(string.digits), pick.choice("#!%*+=")]
    chars += [pick.choice(string.ascii_letters + string.digits) for _ in range(12)]
    pick.shuffle(chars)
    return "".join(chars)


def test_a_strong_explicit_password_is_used(tmp_path):
    password = strong_password()
    values = tmp_path / "strong.yaml"
    values.write_text(yaml.safe_dump({"keycloak": {"testUsers": [
        {"username": "carol", "password": password}]}}))
    spec = realm_of(render("-f", str(values)))["spec"]
    assert spec["realm"]["users"][0]["credentials"][0]["value"] == password
    assert "placeholders" not in spec


def test_the_pattern_reads_the_passwords_from_vault():
    docs = render("--set", "keycloak.userPasswords.externalSecret.enabled=true")
    (es,) = [d for d in docs if d["kind"] == "ExternalSecret"]
    assert es["spec"]["target"]["name"] == "openshell-keycloak-user-passwords"
    assert es["spec"]["dataFrom"] == [{"extract": {"key": "secret/data/hub/keycloak-users"}}]
    assert es["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "-1"
    assert not [d for d in render() if d["kind"] == "ExternalSecret"]


def test_values_secret_generates_every_test_users_password():
    users = {u["username"] for u in yaml.safe_load((CHART / "values.yaml").read_text())["keycloak"]["testUsers"]}
    template = yaml.safe_load((ROOT / "values-secret.yaml.template").read_text())
    (entry,) = [s for s in template["secrets"] if s["name"] == "keycloak-users"]
    assert {f["name"] for f in entry["fields"]} == users
    for field in entry["fields"]:
        assert field["onMissingValue"] == "generate"
        assert field["vaultPolicy"] == "validatedPatternDefaultPolicy"
