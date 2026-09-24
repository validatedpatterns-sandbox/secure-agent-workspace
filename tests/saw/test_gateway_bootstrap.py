"""Real file/PEM publication tests; simulated gateway/systemd, no Podman or cluster."""

import hashlib
import json
import os
import stat
import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    directory = tmp_path_factory.mktemp("synthetic-pki")
    # Real cryptographic parsing/key-pair checks without downloading a gateway.
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem"),
                    "-days", "2", "-subj", "/CN=SAW-OFFLINE-TEST-ONLY"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    return (directory / "key.pem").read_bytes(), (directory / "cert.pem").read_bytes()


@pytest.fixture
def boot(installer, monkeypatch, tmp_path, pki):
    root, client = tmp_path / "gateway", tmp_path / "client"
    monkeypatch.setattr(installer, "GUEST_GATEWAY_ROOT", root)
    monkeypatch.setattr(installer, "GUEST_CLIENT_CONFIG", client)
    settings_path = tmp_path / "guest.json"
    settings_path.write_text(json.dumps({"namespace": "saw-test", "instance": "test",
        "ownerSubject": "owner", "enrollmentIdentity": "a" * 64,
        "profileConfigMaps": [], "providerSecrets": {}}))
    settings_path.chmod(0o600)
    monkeypatch.setattr(installer, "GUEST_SETTINGS_PATH", settings_path)
    monkeypatch.setattr(installer, "GUEST_INSTALLED_BOM", ROOT / "examples/saw/installer-bom.yaml")
    monkeypatch.setattr(installer, "guest_runtime_account", lambda: SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir="/home/cloud-user"))
    monkeypatch.setattr(installer, "prepare_rootless_podman", lambda apply=False: True)
    monkeypatch.setattr(installer, "grant_gateway_runtime_access", lambda: None)
    state = SimpleNamespace(active=False, calls=[], probes=0, port_busy=False, unavailable=False,
                            root=root, client=client, snapshot={"enrollmentIdentity": "a" * 64},
                            identity={"enrollment": "a" * 64, "machineId": "b" * 32,
                                      "productUUID": "11111111-2222-3333-4444-555555555555"})
    monkeypatch.setattr(installer, "guest_boot_identity", lambda snapshot: dict(state.identity))
    monkeypatch.setattr(installer, "guest_gateway_service", lambda: state.active)

    def trust(path, private=False):
        # Simulate root ownership for unprivileged tests; exercise real lstat,
        # symlink, write-permission and private-mode checks within the fixture.
        for entry in (path, *path.parents):
            if not entry.is_relative_to(tmp_path):
                continue
            info = entry.lstat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                raise installer.InstallerError("UnsafeGatewayState")
        if private and path.stat().st_mode & 0o077:
            raise installer.InstallerError("UnsafeGatewayState")

    monkeypatch.setattr(installer, "trusted_guest_path", trust)
    monkeypatch.setattr(installer, "check_guest_client", lambda: trust(client, private=True))

    def command(arguments, output=False):
        state.calls.append(arguments)
        if arguments[1] == "generate-certs":
            target = Path(next(arg.split("=", 1)[1] for arg in arguments if arg.startswith("--output-dir=")))
            for relative in installer.GUEST_PKI_FILES:
                data = pki[0] if relative.endswith((".key", "signing.pem")) else pki[1]
                if relative == "jwt/kid":
                    data = b"test-key-id"
                installer.guest_write_private(target / relative, data)
        elif arguments[:2] == ["/usr/bin/systemctl", "start"]:
            assert arguments[2] == "saw-openshell-gateway.service"
            state.active = True
        else:
            raise AssertionError(arguments)

    def probe(arguments):
        assert arguments == ["workspace", "list"]
        state.probes += 1
        if state.unavailable:
            raise installer.InstallerError("OpenShellCommandFailed")
        return {}

    class Listener:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            assert address == ("127.0.0.1", 17670)
            if state.port_busy:
                raise OSError("PRIVATE-CANARY")

    monkeypatch.setattr(installer, "guest_boot_command", command)
    monkeypatch.setattr(installer, "guest_list", probe)
    monkeypatch.setattr(installer.socket, "socket", Listener)
    monkeypatch.setattr(installer.time, "sleep", lambda delay: None)
    return state


def test_first_boot_is_staged_then_published_once(installer, boot):
    assert installer.prepare_guest_gateway(boot.snapshot, "validate") is False
    assert not boot.calls and not boot.root.exists() and not boot.client.exists()
    assert installer.prepare_guest_gateway(boot.snapshot, "apply")
    first_pki = (boot.root / "tls/ca.key").read_bytes()
    record = json.loads((boot.root / "bootstrap.json").read_bytes())
    assert record["identity"] == boot.identity
    assert set(record["pki"]) == set(installer.GUEST_PKI_FILES)
    assert not list(boot.root.parent.glob(".saw-*"))
    for directory in (boot.root, boot.client):
        assert directory.stat().st_mode & 0o077 == 0
        for entry in directory.rglob("*"):
            assert entry.stat().st_mode & 0o077 == 0
    assert installer.prepare_guest_gateway(boot.snapshot, "validate")
    assert installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert installer.prepare_guest_gateway(boot.snapshot, "verify")
    assert (boot.root / "tls/ca.key").read_bytes() == first_pki
    assert len(boot.calls) == 2  # one certgen, one systemctl start


def test_service_restart_preserves_identity_and_uses_readiness_probe(installer, boot):
    installer.prepare_guest_gateway(boot.snapshot, "apply")
    record = (boot.root / "bootstrap.json").read_bytes()
    boot.active = False
    assert installer.prepare_guest_gateway(boot.snapshot, "validate") is False
    with pytest.raises(installer.InstallerError, match="GatewayNotReady"):
        installer.prepare_guest_gateway(boot.snapshot, "verify")
    installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert (boot.root / "bootstrap.json").read_bytes() == record
    assert len(boot.calls) == 3
    assert boot.probes >= 2


@pytest.mark.parametrize("field", ["enrollment", "machineId", "productUUID"])
def test_retained_state_is_never_adopted_by_another_vm_or_user(installer, boot, field):
    installer.prepare_guest_gateway(boot.snapshot, "apply")
    before = len(boot.calls)
    boot.identity[field] = "foreign"
    with pytest.raises(installer.InstallerError, match="GatewayIdentityMismatch"):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert len(boot.calls) == before


@pytest.mark.parametrize("fault", ["partial", "symlink", "pki", "config", "client", "permissions"])
def test_existing_corrupt_state_is_not_regenerated_or_overwritten(installer, boot, fault):
    installer.prepare_guest_gateway(boot.snapshot, "apply")
    target = boot.root / "tls/ca.key"
    if fault == "partial":
        target.unlink()
    elif fault == "symlink":
        target.unlink()
        target.symlink_to(boot.root / "tls/client/tls.key")
    elif fault == "pki":
        target.write_bytes(b"wrong-key")
    elif fault == "config":
        (boot.root / "gateway.toml").write_text("unsafe = true")
    elif fault == "client":
        (boot.client / "openshell/gateways/saw-local/mtls/tls.key").write_text("wrong")
    else:
        boot.root.chmod(0o755)
    before = len(boot.calls)
    with pytest.raises((installer.InstallerError, OSError)):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert len(boot.calls) == before


def test_failure_before_pki_commit_can_retry_without_active_partial_state(installer, boot, monkeypatch):
    original = installer.guest_boot_command

    def fail(arguments, output=False):
        original(arguments, output)
        raise installer.InstallerError("GatewayBootstrapCommandFailed")

    monkeypatch.setattr(installer, "guest_boot_command", fail)
    with pytest.raises(installer.InstallerError):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert not boot.root.exists() and not boot.client.exists() and not boot.active
    monkeypatch.setattr(installer, "guest_boot_command", original)
    assert installer.prepare_guest_gateway(boot.snapshot, "apply")


def test_failure_between_gateway_and_client_publication_preserves_ca(installer, boot, monkeypatch):
    original = installer.ensure_guest_gateway_client

    def fail(apply=False):
        raise installer.InstallerError("InterruptedClientPublication")

    monkeypatch.setattr(installer, "ensure_guest_gateway_client", fail)
    with pytest.raises(installer.InstallerError):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert boot.root.exists() and not boot.client.exists() and not boot.active
    original_key = (boot.root / "tls/ca.key").read_bytes()
    monkeypatch.setattr(installer, "ensure_guest_gateway_client", original)
    assert installer.prepare_guest_gateway(boot.snapshot, "validate") is False
    assert installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert (boot.root / "tls/ca.key").read_bytes() == original_key
    assert len([cmd for cmd in boot.calls if "generate-certs" in cmd]) == 1


@pytest.mark.parametrize("conflict", ["port", "active", "client"])
def test_never_takes_over_legacy_listener_or_identity(installer, boot, conflict):
    if conflict == "port":
        boot.port_busy = True
    elif conflict == "active":
        boot.active = True
    else:
        boot.client.mkdir()
    with pytest.raises(installer.InstallerError):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert not boot.root.exists() and not boot.calls


def test_active_systemd_unit_is_not_sufficient_for_readiness(installer, boot):
    boot.unavailable = True
    with pytest.raises(installer.InstallerError, match="GatewayNotReady"):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert boot.active and boot.probes == 5
    with pytest.raises(installer.InstallerError):
        installer.prepare_guest_gateway(boot.snapshot, "verify")


def test_bootstrap_config_and_unit_do_not_expose_admin_or_inherit_environment(installer, monkeypatch):
    monkeypatch.setattr(installer, "GUEST_INSTALLED_BOM", ROOT / "examples/saw/installer-bom.yaml")
    monkeypatch.setattr(installer, "guest_runtime_account", lambda: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    config = tomllib.loads(installer.guest_gateway_config({}).decode())
    gateway = config["openshell"]["gateway"]
    assert gateway["bind_address"] == "127.0.0.1:17670"
    assert gateway["mtls_auth"]["enabled"] is True
    assert gateway["auth"]["allow_unauthenticated_users"] is False
    assert not gateway["enable_loopback_service_http"]
    assert gateway["compute_drivers"] == ["podman"]
    assert set(config["openshell"]["drivers"]) == {"podman"}
    driver = config["openshell"]["drivers"]["podman"]
    assert not driver["enable_bind_mounts"]
    assert driver["socket_path"] == "/run/user/1001/podman/podman.sock"
    assert driver["supervisor_image"] == installer.load_installer_bom(installer.GUEST_INSTALLED_BOM)["spec"]["openshell"]["supervisor"]["image"]
    unit = (ROOT / "guest/systemd/saw-openshell-gateway.service").read_text()
    assert "User=cloud-user" in unit and "Group=cloud-user" in unit
    assert "User=root" not in unit
    assert "--guest-gateway-run" in unit
    assert "--guest-gateway-check" in unit
    assert "ReadWritePaths=/var/lib/saw/gateway/state" in unit
    assert "WantedBy=" not in unit
    assert "Requires=podman.socket" not in unit
    assert "docker" not in unit.lower()
    for filename in ('saw-guest.service', 'saw-openshell-gateway.service'):
        hardened = (ROOT / 'guest/systemd' / filename).read_text()
        assert 'ProtectHome=tmpfs' in hardened
        assert 'BindReadOnlyPaths=/run/user' in hardened
        assert 'ProtectHome=false' not in hardened
        assert 'NoNewPrivileges=true' in hardened


@pytest.mark.parametrize("fault", [None, "hash", "override", "reload", "fragment"])
def test_only_bundled_loaded_systemd_unit_is_started(installer, monkeypatch, tmp_path, fault):
    unit = tmp_path / "saw-openshell-gateway.service"
    unit.write_bytes((ROOT / "guest/systemd/saw-openshell-gateway.service").read_bytes())
    manifest = tmp_path / "build.json"
    manifest.write_text(json.dumps({"gatewayUnitSha256": "bad" if fault == "hash" else hashlib.sha256(unit.read_bytes()).hexdigest()}))
    monkeypatch.setattr(installer, "GUEST_GATEWAY_UNIT", unit)
    monkeypatch.setattr(installer, "GUEST_BUILD_MANIFEST", manifest)
    monkeypatch.setattr(installer, "trusted_guest_path", lambda *a, **kw: None)
    output = (f"LoadState=loaded\nFragmentPath={unit if fault != 'fragment' else '/unexpected'}\n"
              f"DropInPaths={'untrusted.conf' if fault == 'override' else ''}\nActiveState=active\n"
              f"NeedDaemonReload={'yes' if fault == 'reload' else 'no'}\n").encode()
    monkeypatch.setattr(installer, "guest_boot_command", lambda *a, **kw: output)
    if fault:
        with pytest.raises(installer.InstallerError):
            installer.guest_gateway_service()
    else:
        assert installer.guest_gateway_service()


def test_podman_supervisor_image_follows_selected_release(installer, monkeypatch, tmp_path):
    monkeypatch.setattr(installer, "guest_runtime_account", lambda: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    bom = installer.load_installer_bom(ROOT / "examples/saw/installer-bom.yaml")
    expected = "registry.example.test/new-supervisor@sha256:" + "b" * 64
    bom["spec"]["openshell"]["supervisor"] = {"version": "1.2.3", "image": expected}
    path = tmp_path / "release.yaml"
    path.write_text(json.dumps(bom))
    monkeypatch.setattr(installer, "GUEST_INSTALLED_BOM", path)
    config = tomllib.loads(installer.guest_gateway_config({}).decode())
    assert config["openshell"]["drivers"]["podman"]["supervisor_image"] == expected


@pytest.mark.parametrize('fault', [None, 'modified', 'extra', 'missing', 'unattested', 'unapproved-path'])
def test_fedora_dropin_requires_exact_build_attestation(installer, monkeypatch, tmp_path, fault):
    unit = tmp_path / 'saw-openshell-gateway.service'
    unit.write_text('[Service]\nUser=cloud-user\n')
    vendor = tmp_path / '10-timeout-abort.conf'
    vendor.write_text('[Service]\nTimeoutStopFailureMode=abort\n')
    trusted = []
    manifest = tmp_path / 'build.json'
    expected = {str(vendor): hashlib.sha256(vendor.read_bytes()).hexdigest()}
    if fault == 'unattested':
        expected = {}
    if fault == 'unapproved-path':
        expected = {str(tmp_path / 'evil.conf'): 'a' * 64}
    manifest.write_text(json.dumps({'gatewayUnitSha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
                                    'gatewayDropIns': expected}))
    if fault == 'modified':
        vendor.write_text('[Service]\nUser=root\n')
    monkeypatch.setattr(installer, 'GUEST_GATEWAY_UNIT', unit)
    monkeypatch.setattr(installer, 'GUEST_BUILD_MANIFEST', manifest)
    monkeypatch.setattr(installer, 'GUEST_VENDOR_DROPIN', vendor)
    monkeypatch.setattr(installer, 'trusted_guest_path', lambda path: trusted.append(path))
    paths = '' if fault == 'missing' else str(vendor)
    if fault == 'extra':
        paths += ' /etc/systemd/system/service.d/evil.conf'
    def command(args, output=False):
        assert '--all' in args
        return (f'LoadState=loaded\nFragmentPath={unit}\nDropInPaths={paths}\n'
                'ActiveState=inactive\nNeedDaemonReload=no\n').encode()
    monkeypatch.setattr(installer, 'guest_boot_command', command)
    if fault:
        with pytest.raises(installer.InstallerError):
            installer.guest_gateway_service()
    else:
        assert not installer.guest_gateway_service()
        assert vendor in trusted


def test_invalid_generated_key_pair_is_never_published(installer, boot, monkeypatch):
    original = installer.guest_boot_command

    def bad_key(arguments, output=False):
        original(arguments, output)
        directory = Path(next(arg.split("=", 1)[1] for arg in arguments if arg.startswith("--output-dir=")))
        (directory / "client/tls.key").write_bytes(b"INVALID-PRIVATE-KEY")

    monkeypatch.setattr(installer, "guest_boot_command", bad_key)
    with pytest.raises(installer.ssl.SSLError):
        installer.prepare_guest_gateway(boot.snapshot, "apply")
    assert not boot.root.exists() and not boot.client.exists() and not boot.active


def test_systemd_restart_guard_rejects_a_cloned_identity_without_logging(installer, boot, monkeypatch, capsys):
    installer.prepare_guest_gateway(boot.snapshot, "apply")
    settings = {"namespace": "saw-test", "instance": "test", "ownerSubject": "owner",
                "enrollmentIdentity": "a" * 64, "profileConfigMaps": [], "providerSecrets": {}}
    original = installer.guest_private_read

    def read(path):
        return json.dumps(settings).encode() if path == installer.GUEST_SETTINGS_PATH else original(path)

    monkeypatch.setattr(installer, "guest_private_read", read)
    assert installer.guest_gateway_check() == 0
    boot.identity["productUUID"] = "different-vm"
    assert installer.guest_gateway_check() == 1
    output = capsys.readouterr()
    assert not output.out and not output.err


@pytest.mark.parametrize("failed", [False, True])
def test_boot_commands_do_not_inherit_credentials_or_log_failures(installer, monkeypatch, failed, capsys):
    monkeypatch.setenv("OPENSHELL_DISABLE_TLS", "true")
    monkeypatch.setenv("NVIDIA_API_KEY", "PRIVATE-CANARY")

    def run(command, **kwargs):
        assert kwargs["env"] == {"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8"}
        assert kwargs["stdin"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 20
        return subprocess.CompletedProcess(command, 1 if failed else 0, b"PRIVATE-CANARY")

    monkeypatch.setattr(installer.subprocess, "run", run)
    if failed:
        with pytest.raises(installer.InstallerError, match="GatewayBootstrapCommandFailed"):
            installer.guest_boot_command(["/fixed/path"])
    else:
        assert installer.guest_boot_command(["/fixed/path"]) is None
    assert "PRIVATE-CANARY" not in capsys.readouterr().out
