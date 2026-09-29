"""SAW-BOM profile parsing, validation and credential resolution."""

import pytest
import yaml

from conftest import profile_files


def ws_by_name(profiles):
    return {ws.name: ws for p in profiles for ws in p.workspaces}


# -- parsing ---------------------------------------------------------------

def test_shipped_profile_parses(ab, shipped_profile_files):
    profiles = ab.parse_profiles(shipped_profile_files)
    assert [p.name for p in profiles] == ["data-science"]
    workspaces = ws_by_name(profiles)
    assert set(workspaces) == {"default", "cuda-dev"}
    default = workspaces["default"]
    assert [(p.name, p.type, p.credential_secret) for p in default.providers] == [
        ("nvidia", "nvidia", "inference"), ("brave", "brave", "web-search")]
    assert default.providers[0].nemoclaw_provider == "build"
    notebook = next(s for s in default.sandboxes if s.name == "notebook")
    assert notebook.type == "openclaw" and notebook.enabled and notebook.providers == ["nvidia"]
    assert [s.name for s in default.sandboxes if not s.enabled] == ["cuda-sandbox", "toolbox"]


def test_shipped_profile_is_valid(ab, shipped_profile_files):
    ab.validate_profiles(ab.parse_profiles(shipped_profile_files))


def test_read_profile_files_ignores_other_files(ab, tmp_path, shipped_profile_files):
    for key, text in shipped_profile_files.items():
        (tmp_path / key).write_text(text)
    (tmp_path / "..data").mkdir()                 # kubelet-style projection dir
    (tmp_path / ".hidden").write_text("ignored")
    assert ab.read_profile_files(tmp_path) == shipped_profile_files


def test_unexpected_profile_file_is_an_error(ab, tmp_path):
    (tmp_path / "profiles_data-science_default_workspace.yaml").write_text("x: 1")
    with pytest.raises(ab.InstallerError, match="unexpected file in the profiles ConfigMap"):
        ab.read_profile_files(tmp_path)


def test_missing_profiles_dir_means_no_profiles(ab, tmp_path):
    assert ab.read_profile_files(tmp_path / "absent") == {}
    assert ab.parse_profiles({}) == []


def doc(kind, spec, metadata=None):
    return yaml.safe_dump({"apiVersion": "saw.redhat.com/v1alpha1", "kind": kind,
                           "metadata": metadata or {}, "spec": spec})


def make_files(ws="team", providers=None, sandboxes=None, ws_spec=None, profile="p"):
    prefix = f"profiles__{profile}__{ws}__"
    files = {prefix + "workspace.yaml": doc("Workspace", ws_spec or {}, {"name": ws})}
    if providers is not None:
        files[prefix + "providers.yaml"] = doc("Providers", {"providers": providers})
    if sandboxes is not None:
        files[prefix + "sandbox.yaml"] = doc("Sandboxes", {"sandboxes": sandboxes})
    return files


NVIDIA = {"name": "nvidia", "type": "nvidia", "credentialSecret": "inference",
          "credentialSecretKey": "api_key", "model": "m1"}


@pytest.mark.parametrize("files, message", [
    ({"profiles__p__team__notes.yaml": "x: 1"}, "unexpected profile file"),
    ({"profiles__p__workspace.yaml": "x: 1"}, "unexpected profile file name"),
    ({"profiles__p__team__providers.yaml": doc("Providers", {"providers": []})}, "no workspace.yaml"),
    ({"profiles__p__team__workspace.yaml": "a: [unclosed"}, "invalid YAML"),
])
def test_bad_profile_files(ab, files, message):
    with pytest.raises(ab.InstallerError, match=message):
        ab.parse_profiles(files)


def test_provider_without_type_is_rejected(ab):
    with pytest.raises(ab.InstallerError, match="needs name and type"):
        ab.parse_profiles(make_files(providers=[{"name": "x"}]))


# -- validation --------------------------------------------------------------

@pytest.mark.parametrize("files, message", [
    (make_files(ws="a-very-long-workspace-name"), "at most 19"),
    (make_files(ws="Bad_Name"), "DNS label"),
    (make_files(providers=[{**NVIDIA, "type": "made-up"}]), "unsupported type"),
    (make_files(providers=[{**NVIDIA, "credentialSecret": ""}]), "no credentialSecret"),
    (make_files(providers=[{**NVIDIA, "credentialSecret": "Bad/Name"}]), "invalid credentialSecret"),
    (make_files(providers=[{**NVIDIA, "credentialSecretKey": "a b"}]), "invalid credentialSecretKey"),
    (make_files(providers=[NVIDIA, NVIDIA]), "duplicate provider"),
    (make_files(providers=[NVIDIA], sandboxes=[{"name": "sb", "providers": ["missing"]}]),
     "provider 'missing' which is not an enabled provider"),
    (make_files(providers=[{**NVIDIA, "enabled": False}], sandboxes=[{"name": "sb", "providers": ["nvidia"]}]),
     "not an enabled provider"),
    (make_files(providers=[NVIDIA], sandboxes=[{"name": "a-very-long-sandbox-name"}]), "at most 19"),
    (make_files(providers=[NVIDIA], sandboxes=[{"name": "sb", "type": "docker"}]), "unsupported type"),
    (make_files(providers=[NVIDIA], sandboxes=[{"name": "sb"}, {"name": "sb"}]), "duplicate sandbox"),
    (make_files(providers=[], sandboxes=[{"name": "sb", "type": "openclaw"}]), "needs at least one provider"),
])
def test_invalid_profiles_are_rejected(ab, files, message):
    with pytest.raises(ab.InstallerError, match=message):
        ab.validate_profiles(ab.parse_profiles(files))


def test_all_errors_are_reported_together(ab):
    files = make_files(ws="Bad_Name", providers=[{**NVIDIA, "type": "made-up"}])
    with pytest.raises(ab.InstallerError) as err:
        ab.validate_profiles(ab.parse_profiles(files))
    assert "DNS label" in str(err.value) and "unsupported type" in str(err.value)


def test_same_workspace_in_two_profiles_is_rejected(ab):
    files = {**make_files(profile="one", providers=[NVIDIA]),
             **make_files(profile="two", providers=[NVIDIA])}
    with pytest.raises(ab.InstallerError, match="also defined by profile one"):
        ab.validate_profiles(ab.parse_profiles(files))


def test_disabled_workspace_and_items_are_not_validated(ab):
    files = make_files(ws="Bad_Name", ws_spec={"enabled": False},
                       providers=[{**NVIDIA, "type": "made-up"}])
    ab.validate_profiles(ab.parse_profiles(files))
    files = make_files(providers=[NVIDIA], sandboxes=[
        {"name": "off", "enabled": False, "type": "docker", "providers": ["missing"]}])
    ab.validate_profiles(ab.parse_profiles(files))


def test_nemoclaw_sandbox_needs_nemoclaw_in_bom(ab, bom, shipped_profile_files):
    profiles = ab.parse_profiles(shipped_profile_files)  # cuda-dev has a nemoclaw sandbox
    with pytest.raises(ab.InstallerError, match="no spec.nemoclaw.cliImage"):
        ab.check_profiles_against_bom(profiles, bom)
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/x/nemoclaw@sha256:" + "a" * 64}
    ab.check_profiles_against_bom(profiles, bom)


# -- credentials -----------------------------------------------------------

def test_credentials_resolve_from_mounted_secrets(ab, shipped_profile_files, secrets_dir):
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir)
    assert creds == {"default": {"nvidia": "nvapi-TEST-KEY-123", "brave": "brave-TEST-KEY-456"},
                     "cuda-dev": {"nvidia": "nvapi-TEST-KEY-123"}}


def test_missing_secret_is_an_error_naming_it(ab, shipped_profile_files, secrets_dir):
    for f in (secrets_dir / "web-search").iterdir():
        f.unlink()
    with pytest.raises(ab.InstallerError, match="Secret 'web-search' key 'api_key'"):
        ab.resolve_credentials(ab.parse_profiles(shipped_profile_files), secrets_dir)


def test_empty_secret_value_is_an_error(ab, shipped_profile_files, secrets_dir):
    (secrets_dir / "inference" / "api_key").write_text("  \n")
    with pytest.raises(ab.InstallerError, match="provider 'nvidia'"):
        ab.resolve_credentials(ab.parse_profiles(shipped_profile_files), secrets_dir)


def test_secret_for_another_provider_is_refused(ab, shipped_profile_files, secrets_dir):
    (secrets_dir / "inference" / "provider").write_text("gemini\n")
    with pytest.raises(ab.InstallerError, match="Secret 'inference' is for 'gemini'"):
        ab.resolve_credentials(ab.parse_profiles(shipped_profile_files), secrets_dir)


@pytest.mark.parametrize("configured", ["nvidia", "build", ""])
def test_provider_type_or_nemoclaw_alias_is_accepted(ab, configured):
    provider = ab.Provider(name="nvidia", type="nvidia", nemoclaw_provider="build",
                           credential_secret="inference")
    ab.check_provider_type(provider, configured)


def test_disabled_providers_need_no_credential(ab, tmp_path):
    files = make_files(providers=[{**NVIDIA, "enabled": False}])
    assert ab.resolve_credentials(ab.parse_profiles(files), tmp_path) == {}


def test_profile_helper_matches_chart_layout():
    keys = profile_files()
    assert "profiles__data-science__default__providers.yaml" in keys


def test_chart_default_bom_covers_the_default_profile(ab, chart_bom, shipped_profile_files):
    """The default saw-bom profile has a nemoclaw sandbox, so the chart's
    default BOM must include the NemoClaw CLI or a default install fails."""
    ab.check_profiles_against_bom(ab.parse_profiles(shipped_profile_files), ab.validate_bom(chart_bom))


@pytest.mark.parametrize("flag", ["runtimeCredentials", "externallyManaged"])
def test_dynamic_provider_needs_no_static_secret(ab, tmp_path, flag):
    profiles = ab.parse_profiles(make_files(providers=[{
        "name": "protected", "type": "saw-demo", flag: True}]))
    ab.validate_profiles(profiles)
    assert ab.resolve_credentials(profiles, tmp_path) == {}


@pytest.mark.parametrize("extra,message", [
    ({"externallyManaged": True}, "cannot be both"),
    ({"credentialSecret": "inference"}, "cannot use credentialSecret"),
    ({"runtimeCredentials": "true"}, "must be booleans"),
])
def test_dynamic_provider_rejects_ambiguous_credentials(ab, extra, message):
    profiles = ab.parse_profiles(make_files(providers=[{
        "name": "protected", "type": "saw-demo", "runtimeCredentials": True, **extra}]))
    with pytest.raises(ab.InstallerError, match=message):
        ab.validate_profiles(profiles)
