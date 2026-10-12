"""scripts/openshell-saw-vm-ssh.sh: dynamic SSH key provisioning on demand."""
import base64
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "openshell-saw-vm-ssh.sh"
HERE = Path(__file__).parent
PUBKEY = "ssh-ed25519 AAAAC3NzaTEST operator@laptop"


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "oc").symlink_to(HERE / "fake_oc")
    (bin_dir / "virtctl").symlink_to(HERE / "fake_virtctl")
    (bin_dir / "sleep").write_text("#!/bin/sh\n")
    (bin_dir / "sleep").chmod(0o755)
    key = tmp_path / "id"
    key.write_text("PRIVATE")
    Path(f"{key}.pub").write_text(PUBKEY + "\n")
    state = tmp_path / "state"
    state.mkdir()
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_STATE": str(state),
            "SAW_NS": "saw-alice", "VM_NAME": "alice", "SSH_KEY_PATH": str(key),
            "KEY_NAME": "saurabh", "SYNC_TIMEOUT": "5"}


def set_state(env, **st):
    (Path(env["FAKE_STATE"]) / "oc.json").write_text(json.dumps(st))


def state(env):
    return json.loads((Path(env["FAKE_STATE"]) / "oc.json").read_text())


def log(env, tool):
    path = Path(env["FAKE_STATE"]) / f"{tool}.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def is_probe(call):
    return call[-2:] == ["--command", "true"] and "--local-ssh-opts=-oBatchMode=yes" in call


def sessions(env):
    """virtctl calls other than the key-acceptance probes."""
    return [c for c in log(env, "virtctl") if not is_probe(c)]


def run(env, *args):
    return subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)


def test_adds_key_waits_for_sync_then_ssh(env):
    set_state(env, secret="alice-ssh-pubkey", sync_after=3)
    result = run(env)
    assert result.returncode == 0, result.stderr
    assert base64.b64decode(state(env)["data"]["saurabh"]).decode() == PUBKEY
    assert state(env)["polls"] >= 3
    patches = [c for c in log(env, "oc") if c[:2] == ["patch", "secret"]]
    assert patches and patches[0][2] == "alice-ssh-pubkey"
    assert all(PUBKEY not in " ".join(c) for c in log(env, "oc")), "key must not be in argv"
    (ssh,) = sessions(env)
    assert ssh[:4] == ["-n", "saw-alice", "ssh", "cloud-user@vm/alice"]
    assert f"--identity-file={env['SSH_KEY_PATH']}" in ssh and "--command" not in ssh


def test_runs_a_command(env):
    set_state(env, secret="alice-ssh-pubkey")
    assert run(env, "sudo cat /var/lib/saw/status.json").returncode == 0
    (ssh,) = sessions(env)
    assert ssh[-2:] == ["--command", "sudo cat /var/lib/saw/status.json"]


def test_command_from_environment_is_passed_as_one_remote_command(env):
    """make passes CMD= via the environment; pipes must run in the VM."""
    set_state(env, secret="alice-ssh-pubkey")
    env["CMD"] = "cat ~/.ssh/authorized_keys | cut -c1-40; getsebool virt_qemu_ga_manage_ssh"
    assert run(env).returncode == 0
    (ssh,) = sessions(env)
    assert ssh[-2:] == ["--command", env["CMD"]]


def test_make_target_passes_cmd_through_the_environment():
    text = (ROOT / "Makefile-quickstart").read_text()
    recipe = text.split("saw-vm-ssh:", 1)[1].split("\n\n", 1)[0]
    assert "openshell-saw-vm-ssh.sh" in recipe and "$(CMD)" not in recipe


def test_existing_key_is_not_patched_again(env):
    set_state(env, secret="alice-ssh-pubkey",
              data={"saurabh": base64.b64encode(PUBKEY.encode()).decode()})
    result = run(env, "--add-key-only")
    assert result.returncode == 0, result.stderr
    assert "already in Secret" in result.stderr
    assert not result.stdout
    assert not [c for c in log(env, "oc") if c[0] == "patch"]
    assert sessions(env) == []


def test_other_keys_in_the_secret_are_kept(env):
    other = base64.b64encode(b"ssh-ed25519 AAAAother bob").decode()
    set_state(env, secret="alice-ssh-pubkey", data={"bob": other})
    assert run(env, "--add-key-only").returncode == 0
    assert state(env)["data"]["bob"] == other and "saurabh" in state(env)["data"]


def test_secret_read_error_is_visible(env):
    set_state(env, secret="alice-ssh-pubkey", secret_error="Forbidden")
    result = run(env, "--add-key-only")
    assert result.returncode != 0
    assert "Forbidden" in result.stderr
    assert not [c for c in log(env, "oc") if c[0] == "patch"]


def test_vmi_permission_error_stops_without_retry(env):
    set_state(env, secret="alice-ssh-pubkey", vmi_error="Forbidden")
    result = run(env, "--add-key-only")
    assert result.returncode != 0
    assert "Forbidden" in result.stderr
    assert len([c for c in log(env, "oc") if c[:2] == ["get", "vmi"]]) == 1


def test_fails_when_key_never_syncs(env):
    set_state(env, secret="alice-ssh-pubkey", sync_after=10**6)
    env["SYNC_TIMEOUT"] = "0"
    result = run(env)
    assert result.returncode == 1
    assert "not synced" in result.stderr and "virt_qemu_ga_manage_ssh" in result.stderr
    assert log(env, "virtctl") == []


def test_fails_without_access_credentials(env):
    set_state(env, secret="")
    result = run(env)
    assert result.returncode == 1 and "no accessCredentials" in result.stderr


def test_fails_without_public_key(env):
    set_state(env, secret="alice-ssh-pubkey")
    os.remove(env["SSH_KEY_PATH"] + ".pub")
    result = run(env)
    assert result.returncode == 1 and "no public key" in result.stderr


def test_waits_until_the_vm_accepts_the_key(env):
    """Live (fresh VM): the condition was already True for the empty Secret,
    so ssh ran before the new key reached the VM and was refused."""
    set_state(env, secret="alice-ssh-pubkey")
    env["REJECT_PROBES"] = "2"
    result = run(env, "uptime")
    assert result.returncode == 0, result.stderr
    probes = [c for c in log(env, "virtctl") if is_probe(c)]
    assert len(probes) == 3
    (ssh,) = sessions(env)
    assert ssh[-2:] == ["--command", "uptime"]


def test_gives_up_when_the_key_is_never_accepted(env):
    set_state(env, secret="alice-ssh-pubkey")
    env["REJECT_PROBES"] = "1000000"
    env["SYNC_TIMEOUT"] = "0"
    result = run(env, "uptime")
    assert result.returncode == 1 and "does not accept the key" in result.stderr
    assert sessions(env) == []


def test_add_key_only_confirms_the_key_works(env):
    set_state(env, secret="alice-ssh-pubkey")
    assert run(env, "--add-key-only").returncode == 0
    assert [c for c in log(env, "virtctl") if is_probe(c)] and sessions(env) == []
