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
    assert not {"Keycloak", "StatefulSet", "Service", "PersistentVolumeClaim"} & {d["kind"] for d in docs}
    assert [d["kind"] for d in render("--set", "keycloak.existing=keycloak",
                                      "--set", "redirectRegistrar.enabled=false")] == ["KeycloakRealmImport"]
    spec = realm_of(docs)["spec"]
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
    realm = realm_of(render("-f", str(with_uri)))
    dash = next(c for c in realm["spec"]["realm"]["clients"] if c["clientId"] == "openshell-dashboard")
    assert dash["redirectUris"] == ["https://a.example.com/oauth2/callback"]


def test_no_test_users_and_users_without_roles_render_valid_lists(tmp_path):
    values = tmp_path / "users.yaml"
    values.write_text("keycloak:\n  users:\n    - username: nobody\n")
    (realm,) = [d for d in render("-f", str(values)) if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["realm"]["users"][0]["realmRoles"] == []
    empty = tmp_path / "empty.yaml"
    empty.write_text("keycloak:\n  users: []\n")
    (realm,) = [d for d in render("-f", str(empty)) if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["realm"]["users"] == []


# -- passwords: generated, never guessable defaults ---------------------------------

def test_no_demo_user_has_a_password_in_values():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["demo"]["users"]
    assert not [u["username"] for u in values["demo"]["users"] if "password" in u]


def test_passwords_come_from_the_secret_as_placeholders():
    spec = realm_of(render("--set", "demo.enabled=true"))["spec"]
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
    values.write_text(yaml.safe_dump({"keycloak": {"users": [{"username": "alice", "password": password}]}}))
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
    values.write_text(yaml.safe_dump({"keycloak": {"users": [
        {"username": "carol", "password": password}]}}))
    spec = realm_of(render("-f", str(values)))["spec"]
    assert spec["realm"]["users"][0]["credentials"][0]["value"] == password
    assert "placeholders" not in spec


def test_the_pattern_reads_the_passwords_from_vault():
    assert not [d for d in render("--set", "keycloak.userPasswords.externalSecret.enabled=true")
                if d["kind"] == "ExternalSecret"]
    docs = render("--set", "demo.enabled=true", "--set", "keycloak.userPasswords.externalSecret.enabled=true")
    (es,) = [d for d in docs if d["kind"] == "ExternalSecret"]
    assert es["spec"]["target"]["name"] == "openshell-keycloak-user-passwords"
    assert es["spec"]["dataFrom"] == [{"extract": {"key": "secret/data/hub/keycloak-users"}}]
    assert es["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] == "-1"
    assert not [d for d in render() if d["kind"] == "ExternalSecret"]


def test_values_secret_has_no_implicit_demo_passwords():
    template = yaml.safe_load((ROOT / "values-secret.yaml.template").read_text())
    assert not [s for s in template["secrets"] if s["name"] == "keycloak-users"]


def test_production_has_no_demo_users_or_password_placeholders():
    spec = realm_of(render("--set", "keycloak.userPasswords.externalSecret.enabled=true"))["spec"]
    assert spec["realm"]["users"] == []
    assert spec["realm"]["registrationAllowed"] is False
    assert "placeholders" not in spec


def test_demo_owners_have_no_platform_admin_role():
    users = {u["username"]: u for u in realm_of(render("--set", "demo.enabled=true"))["spec"]["realm"]["users"]}
    assert "openshell-admin" in users["admin"]["realmRoles"]
    for name in ("alice", "bob", "developer"):
        assert users[name]["realmRoles"] == ["openshell-user"]


def test_owner_resolver_has_read_only_cluster_role_and_separate_client():
    docs = render("--set", "ownerResolver.enabled=true")
    role = next(d for d in docs if d["kind"] == "ClusterRole" and
                d["metadata"]["name"].startswith("saw-owner-resolver"))
    assert role["rules"] == [
        {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["list"]},
        {"apiGroups": ["config.openshift.io"], "resources": ["ingresses"],
         "resourceNames": ["cluster"], "verbs": ["get"]},
    ]
    # Verified HTTPS to Keycloak, not the plaintext Service: the Route and the
    # CA that signs it, read-only and namespaced.
    namespaced = {(d["metadata"].get("namespace"), rule["resources"][0]): rule
                  for d in docs if d["kind"] == "Role"
                  and d["metadata"]["name"].startswith("saw-owner-resolver")
                  for rule in d["rules"]}
    assert namespaced[(None, "routes")]["verbs"] == ["list"]
    ca = namespaced[("openshift-config-managed", "configmaps")]
    assert ca["resourceNames"] == ["default-ingress-cert"] and ca["verbs"] == ["get"]
    deployment = next(d for d in docs if d["kind"] == "Deployment" and
                      d["metadata"]["name"] == "saw-owner-resolver")
    pod = deployment["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "saw-owner-resolver"
    assert {m["name"] for m in pod["containers"][0]["volumeMounts"]} == {"script", "run"}
    assert {m["name"] for m in pod["initContainers"][0]["volumeMounts"]} == {"script", "run", "admin"}


def test_the_registrar_is_on_by_default_and_can_be_turned_off():
    """On by default, in plain and existing-Keycloak mode alike. Off: nothing
    in Keycloak's namespace registers redirect URIs or holds cluster-wide
    access (an administrator runs scripts/keycloak-redirects.py)."""
    for args in ((), ("--set", "keycloak.existing=keycloak")):
        on = render(*args)
        assert [d["metadata"]["name"] for d in on if d["kind"] == "Deployment"
                and "redirect" in d["metadata"]["name"]] == ["saw-redirect-registrar"]
        off = render(*args, "--set", "redirectRegistrar.enabled=false")
        assert not [d for d in off if "redirect" in d["metadata"]["name"]]
        assert not [d for d in off if d["kind"] in ("ClusterRole", "ClusterRoleBinding")]


# -- the redirect registrar (redirectRegistrar, on by default) ----------------------------------------------------------

def registrar(docs):
    (dep,) = [d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "saw-redirect-registrar"]
    return dep["spec"]["template"]["spec"]


def env_of(container):
    return {e["name"]: e["value"] for e in container.get("env", [])}


def test_the_registrar_runs_in_keycloaks_namespace_with_its_own_client():
    pod = registrar(render("--set", "redirectRegistrar.enabled=true"))
    (init,), (main,) = pod["initContainers"], pod["containers"]
    assert env_of(init)["KC_URL"] == env_of(main)["KC_URL"] == ""
    assert env_of(main)["DASHBOARD_CLIENT_ID"] == "openshell-dashboard"
    assert env_of(main)["CLIENT_ID"] == env_of(init)["CLIENT_ID"] == "saw-redirect-registrar"
    assert env_of(main)["NAMESPACE_SELECTOR"] == "openshell.pattern/saw=true"
    assert env_of(main)["ROUTE_SELECTOR"] == "saw.redhat.com/oidc-redirect=true"


def test_only_the_init_container_sees_the_master_admin():
    pod = registrar(render("--set", "redirectRegistrar.enabled=true"))
    (admin,) = [v for v in pod["volumes"] if "secret" in v]
    assert admin["secret"]["secretName"] == "openshell-keycloak-initial-admin"
    (init,), (main,) = pod["initContainers"], pod["containers"]
    assert admin["name"] in {m["name"] for m in init["volumeMounts"]}
    assert admin["name"] not in {m["name"] for m in main["volumeMounts"]}
    assert not any("valueFrom" in e for c in (init, main) for e in c.get("env", []))
    # The registrar's own secret is handed over in memory, read-only.
    (run,) = [v for v in pod["volumes"] if v["name"] == "run"]
    assert run["emptyDir"]["medium"] == "Memory"
    assert next(m for m in main["volumeMounts"] if m["name"] == "run")["readOnly"] is True


def test_the_registrar_may_only_read_routes_and_namespaces():
    docs = render("--set", "redirectRegistrar.enabled=true")
    (role,) = [d for d in docs if d["kind"] == "ClusterRole"]
    verbs = {v for r in role["rules"] for v in r["verbs"]}
    assert verbs <= {"get", "list"}
    assert {res for r in role["rules"] for res in r["resources"]} == {"routes", "namespaces", "ingresses"}
    (binding,) = [d for d in docs if d["kind"] == "ClusterRoleBinding"]
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "saw-redirect-registrar",
                                    "namespace": "keycloak"}]
    (role,) = [d for d in docs if d["kind"] == "Role"]
    assert role["metadata"]["namespace"] == "openshift-config-managed"
    assert role["rules"][0]["resourceNames"] == ["default-ingress-cert"]


def test_an_existing_keycloak_is_reached_by_its_own_name():
    pod = registrar(render("--set", "redirectRegistrar.enabled=true", "--set", "keycloak.existing=sso"))
    assert env_of(pod["containers"][0])["KC_URL"] == ""
    assert env_of(pod["containers"][0])["KEYCLOAK_NAME"] == "sso"
    assert any(v.get("secret", {}).get("secretName") == "sso-initial-admin" for v in pod["volumes"])
    pod = registrar(render("--set", "redirectRegistrar.enabled=true", "--set", "keycloak.existing=sso", "--set", "redirectRegistrar.adminSecret=sso-admin",
                           "--set", "redirectRegistrar.keycloakUrl=https://sso.example.com"))
    assert env_of(pod["containers"][0])["KC_URL"] == "https://sso.example.com"
    assert any(v.get("secret", {}).get("secretName") == "sso-admin" for v in pod["volumes"])


def test_the_registrar_script_is_shipped_byte_for_byte():
    docs = render("--set", "redirectRegistrar.enabled=true")
    (cm,) = [d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "saw-redirect-registrar"]
    assert cm["data"]["redirect-registrar.py"] == (CHART / "files" / "redirect-registrar.py").read_text()


def test_registrar_never_defaults_to_cleartext_and_can_read_only_ingress_ca():
    docs = render()
    pod = registrar(docs)
    for container in pod["initContainers"] + pod["containers"]:
        assert not env_of(container)["KC_URL"].startswith("http://")
        assert env_of(container)["KEYCLOAK_NAME"] == "openshell-keycloak"
        assert env_of(container)["KEYCLOAK_NAMESPACE"] == "keycloak"
    (role,) = [d for d in docs if d["kind"] == "Role" and
               d["metadata"].get("namespace") == "openshift-config-managed"]
    assert role["rules"] == [{"apiGroups": [""], "resources": ["configmaps"],
                               "resourceNames": ["default-ingress-cert"], "verbs": ["get"]}]


def test_registrar_custom_ca_reaches_both_containers():
    docs = render("--set-string", "redirectRegistrar.caBundle=custom-ca")
    pod = registrar(docs)
    for container in pod["initContainers"] + pod["containers"]:
        assert env_of(container)["CA_FILE"] == "/scripts/ca-bundle.crt"
    (cm,) = [d for d in docs if d["kind"] == "ConfigMap"]
    assert cm["data"]["ca-bundle.crt"].strip() == "custom-ca"


def test_registrar_http_override_is_rejected():
    result = helm("--set", "redirectRegistrar.keycloakUrl=http://sso.example.com")
    assert result.returncode != 0
    assert "must use HTTPS" in result.stderr
