"""Privilege boundaries: no real users, engines, sockets or services are changed."""

import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def account(installer, monkeypatch):
    value = SimpleNamespace(pw_uid=1007, pw_gid=1007, pw_dir="/home/cloud-user")
    monkeypatch.setattr(installer.pwd, "getpwnam", lambda name: value)
    monkeypatch.setattr(installer.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="cloud-user"))
    return value


def test_runtime_account_must_not_be_root(installer, account):
    assert installer.guest_runtime_account() is account
    account.pw_uid = 0
    with pytest.raises(installer.InstallerError, match="UnsafeRootlessAccount"):
        installer.guest_runtime_account()


@pytest.mark.parametrize('remote', [False, True])
def test_rootless_command_drops_privileges_and_does_not_use_ambient_env(installer, account, monkeypatch, remote):
    monkeypatch.setenv("NVIDIA_API_KEY", "PRIVATE-CANARY")
    calls = []
    monkeypatch.setattr(installer.os, 'chown', lambda *args: None)

    def run(command, **kwargs):
        calls.append((command, kwargs))
        assert kwargs["user"] == kwargs["group"] == 1007
        assert kwargs["extra_groups"] == []
        assert kwargs["cwd"] == "/"
        home = kwargs['env']['HOME']
        assert Path(home).is_dir() and home != account.pw_dir
        assert kwargs['env']['XDG_CONFIG_HOME'] == home + '/config'
        assert kwargs["env"]["XDG_RUNTIME_DIR"] == (home + '/runtime' if remote else '/run/user/1007')
        assert kwargs['env']['DBUS_SESSION_BUS_ADDRESS'] == 'unix:path=/run/user/1007/bus'
        assert 'CONTAINERS_STORAGE_CONF' not in kwargs['env']
        assert "PRIVATE-CANARY" not in kwargs["env"].values()
        return subprocess.CompletedProcess(command, 0, b"{}")

    monkeypatch.setattr(installer.subprocess, "run", run)
    command = (['/usr/bin/podman', '--remote', '--url=unix:///run/user/1007/podman/podman.sock', 'info'] if remote
               else ["/usr/bin/systemctl", "--user", "start", "podman.socket"])
    assert installer.guest_user_command(command, output=True) == b"{}"
    assert len(calls) == 1
    assert not Path(calls[0][1]['env']['HOME']).exists()


def test_failed_rootless_client_removes_private_directories(installer, account, monkeypatch):
    homes = []
    monkeypatch.setattr(installer.os, 'chown', lambda *args: None)
    def fail(command, **kwargs):
        homes.append(kwargs['env']['HOME'])
        raise subprocess.TimeoutExpired(command, 20)
    monkeypatch.setattr(installer.subprocess, 'run', fail)
    with pytest.raises(installer.InstallerError, match='RootlessCommandFailed'):
        installer.guest_user_command(['/usr/bin/podman', '--remote', 'info'])
    assert homes and all(not Path(home).exists() for home in homes)


@pytest.mark.parametrize("apply", [False, True])
def test_rootless_setup_uses_user_socket_and_rejects_rootful_engine(installer, account, monkeypatch, apply):
    root_calls, user_calls = [], []
    monkeypatch.setattr(Path, "read_text", lambda path, **kw: "cloud-user:100000:65536\n")
    monkeypatch.setattr(Path, "exists", lambda path: True)

    def info(path):
        mode = (stat.S_IFSOCK | 0o660) if path.name == "podman.sock" else (stat.S_IFDIR | 0o700)
        return SimpleNamespace(st_uid=account.pw_uid, st_gid=account.pw_gid, st_mode=mode)

    monkeypatch.setattr(Path, "lstat", info)
    monkeypatch.setattr(Path, "stat", info)
    monkeypatch.setattr(installer, "guest_boot_command", lambda args, **kw: root_calls.append(args))
    rootless = [True]

    def user(args, output=False):
        user_calls.append(args)
        return json.dumps({"host": {"security": {"rootless": rootless[0]}}}).encode()

    monkeypatch.setattr(installer, "guest_user_command", user)
    assert installer.prepare_rootless_podman(apply=apply)
    assert user_calls[-1][:3] == ["/usr/bin/podman", "--remote", "--url=unix:///run/user/1007/podman/podman.sock"]
    assert len(root_calls) == (2 if apply else 0)
    assert not any("podman.socket" in call for call in root_calls)
    if apply:
        assert user_calls[0] == ["/usr/bin/systemctl", "--user", "start", "podman.socket"]
    rootless[0] = False
    with pytest.raises(installer.InstallerError, match="RootlessEngineRequired"):
        installer.prepare_rootless_podman()


def test_missing_subordinate_ids_fail_before_mutation(installer, account, monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda path, **kw: "cloud-user:100000:100\n")
    monkeypatch.setattr(installer, "guest_boot_command", lambda *a, **kw: pytest.fail("must not start services"))
    with pytest.raises(installer.InstallerError, match="RootlessSubordinateIDsRequired"):
        installer.prepare_rootless_podman(apply=True)


def test_gateway_launcher_requires_runtime_uid_and_uses_clean_environment(installer, account, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    with pytest.raises(installer.InstallerError, match="RootlessGatewayRequired"):
        installer.guest_gateway_run()
    monkeypatch.setattr(os, "getuid", lambda: 1007)
    monkeypatch.setattr(os, "getgid", lambda: 1007)
    monkeypatch.setenv("OPENSHELL_DISABLE_TLS", "true")
    calls = []
    monkeypatch.setattr(os, "execve", lambda binary, args, env: calls.append((binary, args, env)))
    installer.guest_gateway_run()
    binary, args, env = calls[0]
    assert binary == "/usr/local/bin/openshell-gateway"
    assert "--enable-mtls-auth=true" in args
    assert env["XDG_RUNTIME_DIR"] == "/run/user/1007"
    assert "OPENSHELL_DISABLE_TLS" not in env


def test_runtime_can_read_inputs_but_not_write_config_or_read_ca_key(installer, account, monkeypatch, tmp_path):
    root = tmp_path / "gateway"
    root.mkdir(mode=0o700)
    (root / "gateway.toml").write_text("config")
    for part in ("server", "client", "jwt"):
        (root / "tls" / part).mkdir(parents=True)
    for name in installer.GUEST_PKI_FILES:
        path = root / "tls" / name
        path.write_text("test")
        path.chmod(0o600)
    (root / "state").mkdir(mode=0o700)
    monkeypatch.setattr(installer, "GUEST_GATEWAY_ROOT", root)
    monkeypatch.setattr(installer, "trusted_guest_path", lambda *a, **kw: None)
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: SimpleNamespace(st_uid=0, st_mode=original(path).st_mode))
    changes = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: changes.append((path, uid, gid)))
    installer.grant_gateway_runtime_access()
    assert (root / "tls/ca.key").stat().st_mode & 0o777 == 0o600
    assert not any(path == root / "tls/ca.key" for path, _, _ in changes)
    assert (root / "gateway.toml").stat().st_mode & 0o777 == 0o640
    assert changes[-1] == (root / "state", 1007, 1007)
    assert all(uid == 0 and gid == 1007 for _, uid, gid in changes[:-1])
