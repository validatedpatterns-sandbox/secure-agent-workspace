"""Credential-loss detection must understand the pinned agent's actual format."""
import base64
import importlib.util
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def identity(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("guest_identity", ROOT / "charts/openshell-saw/files/installer/identity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE", tmp_path)
    (tmp_path / "keys").mkdir()
    return module


@pytest.fixture(scope="module")
def material(tmp_path_factory):
    root = tmp_path_factory.mktemp("identity-cert")
    key, cert = root / "key.pem", root / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=test", "-days", "1"],
                   check=True, capture_output=True)
    der = subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-outform", "DER"],
                         check=True, capture_output=True).stdout
    expired = subprocess.run(["openssl", "x509", "-in", str(cert), "-signkey", str(key), "-days", "0"],
                             check=True, capture_output=True).stdout
    return cert.read_bytes(), der, expired


def populate(identity, cert, key):
    (identity.STATE / "agent-data.json").write_text(json.dumps({"svid": [base64.b64encode(cert).decode()]}))
    (identity.STATE / "keys/keys.json").write_text(json.dumps({"keys": {"agent-svid-A": base64.b64encode(key).decode()}}))


def test_current_agent_state_is_present_without_legacy_file(identity, material):
    populate(identity, *material[:2])
    assert not (identity.STATE / "agent_svid.der").exists()
    assert identity.credentials_present()


def test_expiry_alone_does_not_prove_state_loss(identity, material):
    cert, key, expired = material
    populate(identity, expired, key)
    assert identity.credentials_present()


def test_wiped_or_corrupt_state_is_missing(identity, material):
    assert not identity.credentials_present()
    populate(identity, *material[:2])
    (identity.STATE / "agent-data.json").write_text("not-json")
    assert not identity.credentials_present()
    populate(identity, material[0], b"corrupt key")
    assert not identity.credentials_present()


def test_permission_error_is_not_credential_loss(identity, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("denied")
    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(PermissionError):
        identity.credentials_present()


def test_selinux_module_is_enforcing_and_prebuilt():
    policy = ROOT / "charts/openshell-saw/files/selinux"
    te = (policy / "saw_spire.te").read_text()
    fc = (policy / "saw_spire.fc").read_text()
    source = (ROOT / "charts/openshell-saw/files/installer/identity.py").read_text()
    assert "allow container_t saw_spire_agent_t:unix_stream_socket connectto" in te
    assert "allow container_t saw_spire_runtime_t:dir mounton;" in te
    assert te.count("mounton") == 1
    assert "allow saw_spire_agent_t self:capability sys_ptrace;" in te
    assert "allow saw_spire_agent_t self:cap_userns sys_ptrace;" in te
    assert te.count("sys_ptrace") == 2
    assert not re.search(r"(?m)^permissive\s+\w+", te)
    assert "dac_override" not in te
    assert "saw_spire_agent_exec_t" in fc and "/usr/local/bin/spire-agent" in fc
    assert "saw_spire_var_lib_t" in fc and "saw_spire_runtime_t" in fc
    assert "selinux-policy-devel" not in source
    assert not re.search(r"(?m)^SELinuxContext=", source)
    assert "ExecStart=/usr/local/lib/saw/spire-agent-launch" not in source
    module = base64.b64decode((policy / "saw_spire.pp.b64").read_text())
    assert len(module) > 64
    assert b"saw_spire_agent_exec_t" in module
    assert b"permissive" not in module


def test_readiness_requires_installer_and_agent_health(identity):
    done = {"phase": "Done", "bom": "openshell"}
    assert identity.readiness_decision({"install": done, "apply": done}, False, False)
    assert identity.readiness_decision({"install": done, "apply": done}, True, True)
    assert not identity.readiness_decision({"install": done, "apply": done}, True, False)
    assert not identity.readiness_decision({"install": done, "apply": {"phase": "Failed", "bom": "openshell"}}, False, True)
    assert not identity.readiness_decision({"install": done, "apply": {"phase": "Done", "bom": "other"}}, False, True)
    assert "shutil.rmtree" not in identity.ready.__code__.co_names
    unit = identity.service_unit(False, "tcp", "cloud-user")
    assert "/usr/local/bin/spire-agent run -config /etc/spire/agent.conf" in unit
    assert "User=cloud-user" in unit and "Group=cloud-user" in unit
    assert "AmbientCapabilities=CAP_SYS_PTRACE" in unit
    assert "CapabilityBoundingSet=CAP_SYS_PTRACE" in unit
    assert "-joinTokenFile" not in unit
    enrolled = identity.service_unit(True, "tcp", "cloud-user")
    assert f"-joinTokenFile {identity.STATE / 'bootstrap-token'}" in enrolled
    assert "/run/saw/spire/token" not in enrolled


def test_bootstrap_copies_stay_private(identity, tmp_path, monkeypatch):
    iso = tmp_path / "iso"
    state = tmp_path / "state"
    iso.mkdir()
    state.mkdir()
    (iso / "bundle.pem").write_text("bundle\n")
    (iso / "token").write_text("token-value\n")
    monkeypatch.setattr(identity, "BOOTSTRAP", iso)
    monkeypatch.setattr(identity, "STATE", state)
    user = pwd.getpwuid(os.getuid())
    identity.publish_bootstrap(user, True)
    bundle = state / "bootstrap-bundle.pem"
    token = state / "bootstrap-token"
    assert bundle.read_text() == "bundle\n"
    assert token.read_text() == "token-value\n"
    assert (bundle.stat().st_mode & 0o777) == 0o400
    assert (token.stat().st_mode & 0o777) == 0o400
    assert bundle.stat().st_uid == user.pw_uid
    identity.publish_bootstrap(user, False)
    assert bundle.is_file()
    assert not token.exists()
