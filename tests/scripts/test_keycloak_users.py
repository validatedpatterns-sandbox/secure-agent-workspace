"""scripts/keycloak-users.sh: Keycloak users get random, strong passwords,
generated once and kept; an admin adds users (no self-registration)."""
import base64
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "keycloak-users.sh"

# A fake `oc` that keeps Secrets as JSON files in $FAKE_OC_STATE.
FAKE_OC = r'''#!/usr/bin/env python3
import base64, json, os, sys
from pathlib import Path
state = Path(os.environ["FAKE_OC_STATE"])
args = sys.argv[1:]
def path(name): return state / f"secret-{name}.json"
if args[:2] in (["get", "namespace"], ["create", "namespace"]):
    sys.exit(0)
if args[:2] == ["get", "namespaces"]:
    print(json.dumps({"items": [{"metadata": {"name": "saw-keycloak"}}]}))
    sys.exit(0)
if args[:2] == ["get", "keycloak"]:
    if "-o" in args and args[args.index("-o") + 1] == "json":
        print(json.dumps({"items": [{"metadata": {"name": "openshell-keycloak"},
                                     "status": {"externalURL": "https://sso.example.com"}}]}))
    else:
        print("https://sso.example.com", end="")
    sys.exit(0)
if args[:2] == ["get", "secret"]:
    p = path(args[2])
    if not p.exists():
        sys.exit(1)
    obj = json.loads(p.read_text())
    out = next((a for a in args if a.startswith("jsonpath=") or a.startswith("json")), "json")
    if "-o" in args and args[args.index("-o") + 1].startswith("jsonpath="):
        key = args[args.index("-o") + 1].split(".data.")[1].rstrip("}")
        print(obj["data"].get(key, ""), end="")
    else:
        print(json.dumps(obj))
    sys.exit(0)
if args[:3] == ["create", "secret", "generic"]:
    data = {}
    for a in args:
        if a.startswith("--from-literal="):
            k, v = a[len("--from-literal="):].split("=", 1)
            data[k] = base64.b64encode(v.encode()).decode()
    print(json.dumps({"kind": "Secret", "metadata": {"name": args[3]}, "data": data}))
    sys.exit(0)
if args[:2] == ["apply", "-f"]:
    obj = json.loads(sys.stdin.read())
    path(obj["metadata"]["name"]).write_text(json.dumps(obj))
    sys.exit(0)
sys.exit(f"fake oc: unexpected {args}")
'''


def run(tmp_path, *args):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    oc = bin_dir / "oc"
    oc.write_text(FAKE_OC)
    oc.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_OC_STATE=str(state),
               KEYCLOAK_CHART=str(ROOT / "charts" / "openshell-keycloak"))
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env)


def stored(tmp_path):
    obj = json.loads((tmp_path / "state" / "secret-openshell-keycloak-user-passwords.json").read_text())
    return {k: base64.b64decode(v).decode() for k, v in obj["data"].items()}


def test_ensure_generates_a_strong_password_per_user(tmp_path):
    result = run(tmp_path, "ensure")
    assert result.returncode == 0, result.stderr
    passwords = stored(tmp_path)
    assert set(passwords) == {"developer", "admin", "alice", "bob"}
    for user, pw in passwords.items():
        assert len(pw) >= 20 and user not in pw.lower()
        for cls in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[-_.!@#%^*+=]"):
            assert re.search(cls, pw), (user, cls)
        assert not re.search(r"[\s'\"$&`\\]", pw)
    assert len(set(passwords.values())) == 4


def test_ensure_keeps_existing_passwords(tmp_path):
    run(tmp_path, "ensure")
    first = stored(tmp_path)
    result = run(tmp_path, "ensure")
    assert "is complete" in result.stdout
    assert stored(tmp_path) == first


def test_ensure_fills_in_only_the_missing_users(tmp_path):
    run(tmp_path, "ensure")
    path = tmp_path / "state" / "secret-openshell-keycloak-user-passwords.json"
    obj = json.loads(path.read_text())
    alice = obj["data"]["alice"]
    del obj["data"]["bob"]
    path.write_text(json.dumps(obj))
    result = run(tmp_path, "ensure")
    assert "generated for bob" in result.stdout
    after = json.loads(path.read_text())["data"]
    assert after["alice"] == alice and after["bob"]


def test_show_lists_users_without_passwords(tmp_path):
    run(tmp_path, "ensure")
    result = run(tmp_path, "show")
    assert result.returncode == 0
    for user, password in stored(tmp_path).items():
        assert user in result.stdout
        assert password not in result.stdout


def test_show_without_a_secret_says_how_to_make_one(tmp_path):
    result = run(tmp_path, "show")
    assert result.returncode != 0 and "make keycloak-deploy" in result.stderr


FAKE_CURL = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_OC_STATE"] + "/curl.log", "a") as f:
    f.write(json.dumps(args) + "\n")
url = next(a for a in args if a.startswith("https://"))
if url.endswith("/protocol/openid-connect/token"):
    print(json.dumps({"access_token": "admin-token"}))
elif "/users?exact=true&username=" in url:
    user = url.rsplit("=", 1)[1]
    print(json.dumps([{"id": "id-" + user}] if user in ("alice", "admin") else []))
elif "%{http_code}" in args:
    print("204", end="")
"""


def test_harden_sets_the_policy_and_the_generated_passwords(tmp_path):
    run(tmp_path, "ensure")
    admin = {"username": base64.b64encode(b"kcadmin").decode(), "password": base64.b64encode(b"x").decode()}
    (tmp_path / "state" / "secret-openshell-keycloak-initial-admin.json").write_text(
        json.dumps({"data": admin}))
    curl = tmp_path / "bin" / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(0o755)
    result = run(tmp_path, "harden")
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in (tmp_path / "state" / "curl.log").read_text().splitlines()]
    realm = next(c for c in calls if c[-1] == "https://sso.example.com/admin/realms/openshell")
    settings = json.loads(realm[realm.index("-d") + 1])
    assert settings["bruteForceProtected"] is True
    assert settings["registrationAllowed"] is False
    assert "length(14)" in settings["passwordPolicy"] and "specialChars(1)" in settings["passwordPolicy"]
    passwords = stored(tmp_path)
    resets = {c[-1].split("/users/")[1].split("/")[0]: json.loads(c[c.index("-d") + 1])
              for c in calls if c[-1].endswith("/reset-password")}
    assert resets == {"id-admin": {"type": "password", "value": passwords["admin"], "temporary": False},
                      "id-alice": {"type": "password", "value": passwords["alice"], "temporary": False}}
    assert "bob: not in the realm, skipped" in result.stdout


# -- add-users: an admin adds users (no self-registration) ---------------------------

# A fake Keycloak admin API: users in $FAKE_OC_STATE/realm.json.
FAKE_KEYCLOAK_CURL = r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
state = Path(os.environ["FAKE_OC_STATE"])
realm_file = state / "realm.json"
realm = json.loads(realm_file.read_text()) if realm_file.exists() else {"users": {}}
args = sys.argv[1:]
with open(state / "curl.log", "a") as f:
    f.write(json.dumps(args) + "\n")
url = next(a for a in args if a.startswith("https://"))
method = args[args.index("-X") + 1] if "-X" in args else "GET"
body = json.loads(args[args.index("-d") + 1]) if "-d" in args and not url.endswith("/token") else None
code = "200"
out = ""
if url.endswith("/protocol/openid-connect/token"):
    out = json.dumps({"access_token": "admin-token"})
elif "/users?exact=true&username=" in url:
    name = url.rsplit("=", 1)[1]
    out = json.dumps([{"id": "id-" + name}] if name in realm["users"] else [])
elif url.endswith("/admin/realms/openshell/users") and method == "POST":
    if body["username"] in realm["users"]:
        code = "409"
    else:
        realm["users"][body["username"]] = {**body, "roles": []}
        code = "201"
elif "/roles/" in url:
    out = json.dumps({"id": "role-" + url.rsplit("/", 1)[1], "name": url.rsplit("/", 1)[1]})
elif url.endswith("/role-mappings/realm"):
    name = url.split("/users/id-")[1].split("/")[0]
    realm["users"][name]["roles"] = sorted(set(realm["users"][name]["roles"]) | {r["name"] for r in body})
    code = "204"
elif url.endswith("/reset-password"):
    name = url.split("/users/id-")[1].split("/")[0]
    realm["users"][name]["credentials"] = [body]
    code = "204"
realm_file.write_text(json.dumps(realm))
print(code if "%{http_code}" in args else out, end="")
"""


@pytest.fixture
def keycloak(tmp_path):
    run(tmp_path, "show")      # creates bin/ and state/
    admin = {"username": base64.b64encode(b"kcadmin").decode(), "password": base64.b64encode(b"x").decode()}
    (tmp_path / "state" / "secret-openshell-keycloak-initial-admin.json").write_text(json.dumps({"data": admin}))
    curl = tmp_path / "bin" / "curl"
    curl.write_text(FAKE_KEYCLOAK_CURL)
    curl.chmod(0o755)

    def realm():
        path = tmp_path / "state" / "realm.json"
        return json.loads(path.read_text())["users"] if path.exists() else {}
    return realm


def write_users(tmp_path, users):
    path = tmp_path / "users.yaml"
    path.write_text(yaml.safe_dump({"users": users}))
    return str(path)


def added(tmp_path):
    path = tmp_path / "state" / "secret-openshell-keycloak-users.json"
    return {k: base64.b64decode(v).decode() for k, v in json.loads(path.read_text())["data"].items()}


def test_add_users_creates_them_with_generated_passwords_and_roles(tmp_path, keycloak):
    result = run(tmp_path, "add-users", write_users(tmp_path, [
        {"name": "carol", "email": "carol@example.com", "profiles": ["data-science"]},
        {"username": "dave", "roles": ["openshell-user", "openshell-admin"], "temporaryPassword": True}]))
    assert result.returncode == 0, result.stdout + result.stderr
    users, passwords = keycloak(), added(tmp_path)
    assert set(users) == {"carol", "dave"} == set(passwords)
    carol, dave = users["carol"], users["dave"]
    assert carol["credentials"] == [{"type": "password", "value": passwords["carol"], "temporary": False}]
    assert carol["email"] == "carol@example.com" and carol["emailVerified"] is True
    assert dave["credentials"][0]["temporary"] is True
    # Found live: without an email Keycloak's user profile stopped the first
    # sign-in at "Update Account Information".
    assert dave["email"] == "dave@openshell.local" and dave["emailVerified"] is True
    assert carol["roles"] == ["openshell-user"] and dave["roles"] == ["openshell-admin", "openshell-user"]
    for pw in passwords.values():
        assert len(pw) >= 20 and pw not in result.stdout


def test_existing_users_are_skipped(tmp_path, keycloak):
    run(tmp_path, "add-users", write_users(tmp_path, [{"name": "carol"}]))
    first, before = added(tmp_path)["carol"], keycloak()["carol"]
    result = run(tmp_path, "add-users", write_users(tmp_path, [
        {"name": "carol", "roles": ["openshell-user", "openshell-admin"]}, {"name": "dave"}]))
    assert result.returncode == 0, result.stderr
    assert "carol: exists, skipped" in result.stdout and "dave: created" in result.stdout
    assert added(tmp_path)["carol"] == first and keycloak()["carol"] == before
    assert first not in result.stdout


def test_the_default_file_is_saw_users(tmp_path, keycloak):
    """The list that creates the workspaces creates the accounts too."""
    env = dict(os.environ, PATH=f"{tmp_path / 'bin'}:{os.environ['PATH']}",
               FAKE_OC_STATE=str(tmp_path / "state"))
    result = subprocess.run(["make", "-s", "-f", str(ROOT / "Makefile-quickstart"), "keycloak-add-users",
                             f"SCRIPTS_DIR={ROOT / 'scripts'}", f"KEYCLOAK_CHART={ROOT / 'charts/openshell-keycloak'}"],
                            capture_output=True, text=True, env=env, cwd=ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    names = {u["name"] for u in yaml.safe_load((ROOT / "overrides" / "saw-users.yaml").read_text())["users"]}
    assert set(keycloak()) == names


def test_password_reports_secret_location_without_value(tmp_path, keycloak):
    run(tmp_path, "ensure")
    run(tmp_path, "add-users", write_users(tmp_path, [{"name": "carol"}]))
    carol = run(tmp_path, "password", "carol")
    alice = run(tmp_path, "password", "alice")
    assert "Secret openshell-keycloak-users" in carol.stdout
    assert "Secret openshell-keycloak-user-passwords" in alice.stdout
    assert added(tmp_path)["carol"] not in carol.stdout
    assert stored(tmp_path)["alice"] not in alice.stdout
    missing = run(tmp_path, "password", "nobody")
    assert missing.returncode != 0 and "keycloak-reset-password KC_USER=nobody" in missing.stderr


def test_reset_password_sets_and_keeps_a_new_one_without_output(tmp_path, keycloak):
    run(tmp_path, "ensure")
    run(tmp_path, "add-users", write_users(tmp_path, [{"name": "carol"}, {"name": "dave"}]))
    before = added(tmp_path)
    result = run(tmp_path, "reset-password", "carol")
    assert result.returncode == 0, result.stderr
    after = added(tmp_path)
    assert after["carol"] != before["carol"] and after["dave"] == before["dave"]
    assert after["carol"] not in result.stdout
    assert "was reset in Secret" in result.stdout
    assert keycloak()["carol"]["credentials"][0] == {"type": "password", "value": after["carol"],
                                                     "temporary": False}
    assert "Secret openshell-keycloak-users" in run(tmp_path, "password", "carol").stdout


def test_a_reset_test_user_wins_over_the_imported_password(tmp_path, keycloak):
    """A test user's password comes from the realm import's Secret (in the
    pattern owned by External Secrets); a reset is kept separately and wins."""
    run(tmp_path, "ensure")
    realm = tmp_path / "state" / "realm.json"
    realm.write_text(json.dumps({"users": {"alice": {"username": "alice", "roles": []}}}))
    result = run(tmp_path, "reset-password", "alice")
    new = added(tmp_path)["alice"]
    assert new != stored(tmp_path)["alice"]
    assert new not in result.stdout
    assert "Secret openshell-keycloak-users" in run(tmp_path, "password", "alice").stdout
    shown = run(tmp_path, "show").stdout
    assert "alice" in shown and new not in shown


def test_reset_password_of_an_unknown_user_fails(tmp_path, keycloak):
    result = run(tmp_path, "reset-password", "nobody")
    assert result.returncode != 0 and "nobody is not in realm openshell" in result.stderr


@pytest.mark.parametrize("users, message", [
    ([{"name": "Carol"}], "lowercase DNS label"),
    ([{"name": "a-very-long-user-name-x"}], "at most 19"),
    ([{"name": "carol-bom"}], "-bom"),
    ([{"name": "carol"}, {"username": "carol"}], "listed twice"),
    ([{"name": "carol", "roles": ["realm-admin"]}], "unknown roles"),
    ([{"name": "carol", "email": "not-an-email"}], "not an address"),
    ([], "at least one user"),
])
def test_a_bad_users_file_changes_nothing(tmp_path, keycloak, users, message):
    result = run(tmp_path, "add-users", write_users(tmp_path, users))
    assert result.returncode != 0 and message in result.stderr
    assert keycloak() == {}
    assert not (tmp_path / "state" / "curl.log").exists(), "checked before logging in"


def test_show_lists_added_users_too(tmp_path, keycloak):
    run(tmp_path, "ensure")
    run(tmp_path, "add-users", write_users(tmp_path, [{"name": "carol"}]))
    shown = run(tmp_path, "show").stdout
    assert "carol" in shown and "alice" in shown
    assert added(tmp_path)["carol"] not in shown
