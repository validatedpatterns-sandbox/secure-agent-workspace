"""End-to-end runs of the real apply_bom.py command line, as systemd runs it.

`install` and `apply` run as separate processes (like saw-install.service and
saw-apply.service). The test hooks --as-current-user and --skip-gateway stand
in for runuser and the user systemd manager, which need a real VM.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml


def run(inputs, state, *args, bin_dir=None, opt_dir=None, etc_dir=None, home=None):
    script = inputs / "installer" / "apply_bom.py"
    cmd = [sys.executable, str(script), *args]
    if args[0] in ("install", "apply"):
        cmd += ["--inputs", str(inputs), "--state-dir", str(state), "--as-current-user"]
    if args[0] == "install":
        cmd += ["--bin-dir", str(bin_dir), "--opt-dir", str(opt_dir), "--skip-gateway",
                "--etc-dir", str(etc_dir)]
    if args[0] == "validate":
        cmd += ["--inputs", str(inputs)]
    return subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, "HOME": str(home)})


@pytest.fixture
def world(tmp_path, inputs_dir, fake_env):
    bom = yaml.safe_load((inputs_dir / "installer" / "installer-bom.yaml").read_text())
    fake_env.images_for_bom(bom)
    state = tmp_path / "var-lib-saw"
    bin_dir = tmp_path / "usr-local-bin"
    opt_dir = tmp_path / "opt"
    etc_dir = tmp_path / "etc-openshell"
    home = tmp_path / "home-cloud-user"
    # The gateway's CA as the golden image leaves it; the installer signs its
    # admin client certificate with it.
    (home / ".local" / "state").mkdir(parents=True)
    shutil.copytree(fake_env.home / ".local" / "state" / "openshell", home / ".local" / "state" / "openshell")

    class World:
        pass
    w = World()
    w.inputs, w.state, w.bin, w.opt, w.fake, w.bom = inputs_dir, state, bin_dir, opt_dir, fake_env, bom
    w.etc, w.home = etc_dir, home
    w.run = lambda *a: run(inputs_dir, state, *a, bin_dir=bin_dir, opt_dir=opt_dir,
                           etc_dir=etc_dir, home=home)
    w.status = lambda: json.loads((state / "status.json").read_text())
    return w


def test_validate_accepts_the_shipped_inputs(world):
    result = world.run("validate")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "inputs are valid" in result.stdout
    assert "2 workspace(s)" in result.stdout and "3 credential(s)" in result.stdout
    assert world.fake.podman_calls() == [] and world.fake.openshell_calls() == []


def test_install_then_apply_reaches_ready(world):
    result = world.run("install")
    assert result.returncode == 0, result.stdout + result.stderr
    assert world.status()["install"]["phase"] == "Done"
    assert not (world.state / "ready").exists()
    assert (world.bin / "openshell-gateway").is_file()

    result = world.run("apply")
    assert result.returncode == 0, result.stdout + result.stderr
    status = world.status()
    assert status["apply"]["phase"] == "Done"
    assert status["apply"]["bom"] == world.bom["metadata"]["name"]
    assert (world.state / "ready").read_text().strip() == world.bom["metadata"]["name"]
    assert set(world.fake.openshell_state()["sandboxes"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}
    # The runtime user runs a root-owned, world-readable copy of the script.
    copy = world.state / "installer" / "apply_bom.py"
    assert copy.read_text() == (world.inputs / "installer" / "apply_bom.py").read_text()
    assert oct(copy.stat().st_mode & 0o777) == "0o644"
    # Credentials never reach logs or status.
    for text in (result.stdout, result.stderr, json.dumps(status)):
        assert "nvapi-TEST-KEY-123" not in text


def test_apply_writes_the_ledger_for_the_runtime_user(world):
    cfg_path = world.inputs / "installer" / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["prune"] = {"mode": "report", "sandboxes": False}
    cfg_path.write_text(json.dumps(cfg))
    assert world.run("install").returncode == 0
    result = world.run("apply")
    assert result.returncode == 0, result.stdout + result.stderr
    ledger = json.loads((world.state / "user" / "managed.json").read_text())
    assert ledger["adopted"] is True
    assert not (world.state / "managed.json").exists()


def test_reboot_reruns_are_cheap_and_stay_ready(world):
    assert world.run("install").returncode == 0
    assert world.run("apply").returncode == 0
    pulls = len([c for c in world.fake.podman_calls() if c[0] == "pull"])
    assert world.run("install").returncode == 0
    assert world.run("apply").returncode == 0
    assert len([c for c in world.fake.podman_calls() if c[0] == "pull"]) == pulls
    assert (world.state / "ready").exists()


def test_apply_before_install_is_refused(world):
    result = world.run("apply")
    assert result.returncode == 1
    assert "run `install` first" in result.stdout
    assert world.status()["apply"]["phase"] == "Failed"
    assert world.fake.openshell_calls() == []


def test_new_bom_needs_install_before_apply(world):
    assert world.run("install").returncode == 0
    assert world.run("apply").returncode == 0
    world.bom["metadata"]["name"] = "openshell-next"
    (world.inputs / "installer" / "installer-bom.yaml").write_text(yaml.safe_dump(world.bom))
    result = world.run("apply")
    assert result.returncode == 1
    assert "install has not finished for BOM openshell-next (install: Done for openshell-0-1-2-rhaiv-0)" in result.stdout
    assert not (world.state / "ready").exists()


def test_failed_install_is_visible_and_clears_ready(world):
    assert world.run("install").returncode == 0
    assert world.run("apply").returncode == 0
    world.bom["spec"]["openshell"]["cli"]["image"] = "quay.io/x/cli@sha256:" + "9" * 64
    (world.inputs / "installer" / "installer-bom.yaml").write_text(yaml.safe_dump(world.bom))
    result = world.run("install")          # the new image is not in the fake registry
    assert result.returncode == 1
    status = world.status()
    assert status["install"]["phase"] == "Failed"
    assert "podman pull" in status["install"]["message"]
    assert not (world.state / "ready").exists()


def test_missing_credential_blocks_apply_but_not_install(world):
    for f in (world.inputs / "secrets" / "web-search").iterdir():
        f.unlink()
    assert world.run("install").returncode == 0      # software install does not read profiles
    result = world.run("apply")
    assert result.returncode == 1
    assert "Secret 'web-search' key 'api_key'" in result.stdout
    assert world.status()["apply"]["phase"] == "Failed"
    assert world.fake.openshell_calls() == []        # nothing half-applied
    assert world.run("validate").returncode == 1


def test_invalid_bom_fails_install_with_reason(world):
    world.bom["spec"]["openshell"]["gateway"]["image"] = "quay.io/x/gateway:latest"
    (world.inputs / "installer" / "installer-bom.yaml").write_text(yaml.safe_dump(world.bom))
    result = world.run("install")
    assert result.returncode == 1
    assert "pinned by digest" in world.status()["install"]["message"]


def test_verification_failure_fails_apply(world):
    assert world.run("install").returncode == 0
    world.fake.deny("sandbox provider")    # attachment check cannot be read
    result = world.run("apply")
    assert result.returncode == 1
    assert "verification failed" in result.stdout


def test_no_profiles_disk_still_configures_gateway(world):
    for f in (world.inputs / "profiles").iterdir():
        f.unlink()
    assert world.run("install").returncode == 0
    result = world.run("apply")
    assert result.returncode == 0, result.stdout
    assert "No enabled workspaces" in result.stdout
    assert world.fake.openshell_state()["selected"] == "saw-installer"


def test_dry_run_changes_nothing(world):
    home_before = sorted(p.relative_to(world.home) for p in world.home.rglob("*"))
    result = world.run("install", "--dry-run")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not world.state.exists() and not world.bin.exists() and not world.etc.exists()
    assert sorted(p.relative_to(world.home) for p in world.home.rglob("*")) == home_before
    assert world.fake.podman_calls() == []
    result = world.run("apply", "--dry-run")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not world.state.exists()
    assert world.fake.openshell_calls() == []
    assert sorted(p.relative_to(world.home) for p in world.home.rglob("*")) == home_before


def test_bad_config_is_reported(world):
    (world.inputs / "installer" / "config.json").write_text("{not json")
    result = world.run("install")
    assert result.returncode == 1 and "cannot read installer config" in result.stdout


def test_dashboard_config_requires_images(ab, tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"vmName": "x", "dashboard": {"enabled": True}}))
    with pytest.raises(ab.InstallerError, match="dashboard.image is required"):
        ab.load_config(path)


def test_dashboard_is_skipped_without_redirect(ab, fake_env, capsys, tmp_path):
    cfg = {"oidcIssuer": "https://kc/realms/openshell",
           "dashboard": {"enabled": True, "image": "i", "proxyImage": "p", "clientId": "c", "redirectUrl": ""}}
    ab.setup_dashboard(ab.Shell(), cfg, tmp_path / "setup-dashboard.sh", tmp_path)
    assert "Dashboard skipped" in capsys.readouterr().out


def test_dashboard_cookie_secret_is_kept_across_runs(ab, tmp_path, fake_env):
    script = tmp_path / "setup-dashboard.sh"
    script.write_text('echo "$DASHBOARD_COOKIE_SECRET" >> "$HOME_OUT"\n')
    cfg = {"oidcIssuer": "https://kc/realms/openshell",
           "dashboard": {"enabled": True, "image": "i", "proxyImage": "p", "clientId": "c",
                         "redirectUrl": "https://webui/oauth2/callback"}}
    shell = ab.Shell(env={"PATH": "/usr/bin:/bin", "HOME_OUT": str(tmp_path / "out")})
    ab.setup_dashboard(shell, cfg, script, tmp_path)
    ab.setup_dashboard(shell, cfg, script, tmp_path)
    first, second = (tmp_path / "out").read_text().split()
    assert first == second and len(first) == 32
    secret = tmp_path / ".config" / "openshell" / "dashboard-cookie-secret"
    assert oct(secret.stat().st_mode & 0o777) == "0o600"


def test_failed_install_blocks_apply_even_if_components_exist(world):
    assert world.run("install").returncode == 0
    (world.inputs / "installer" / "gateway.toml").unlink()   # install now fails
    assert world.run("install").returncode == 1
    result = world.run("apply")
    assert result.returncode == 1 and "(install: Failed" in result.stdout


def test_install_syncs_gateway_config_every_boot(world):
    assert world.run("install").returncode == 0
    env_text = (world.inputs / "installer" / "gateway.env").read_text()
    assert (world.etc / "gateway.env").read_text() == env_text
    user_env = world.home / ".config" / "openshell" / "gateway.env"
    assert user_env.read_text() == env_text
    # The golden image's first-boot setup appends runtime keys; they survive.
    user_env.write_text(user_env.read_text()
                        + "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock\n"
                        + "OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET=/spiffe-workload-api/agent.sock\n")
    # The chart changes the gateway config: the next boot applies it.
    (world.inputs / "installer" / "gateway.env").write_text(env_text + "OPENSHELL_NEW=1\n")
    result = world.run("install")
    assert result.returncode == 0 and "updated" in result.stdout
    text = user_env.read_text()
    assert "OPENSHELL_NEW=1" in text and "OPENSHELL_PODMAN_SOCKET=" in text
    assert "OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET" not in text
    assert "OPENSHELL_NEW=1" in (world.etc / "gateway.env").read_text()


def test_route_host_adds_certificate_san_dropin(world):
    config = json.loads((world.inputs / "installer" / "config.json").read_text())
    config["routeHost"] = "saw-test-gateway-ns.apps.example.com"
    (world.inputs / "installer" / "config.json").write_text(json.dumps(config))
    assert world.run("install").returncode == 0
    dropin = world.home / ".config/systemd/user/openshell-gateway.service.d/route-san.conf"
    assert "--server-san saw-test-gateway-ns.apps.example.com" in dropin.read_text()
    config["routeHost"] = ""
    (world.inputs / "installer" / "config.json").write_text(json.dumps(config))
    assert world.run("install").returncode == 0
    assert not dropin.exists()


def test_credential_is_rotated_on_existing_provider(world):
    assert world.run("install").returncode == 0
    assert world.run("apply").returncode == 0
    (world.inputs / "secrets" / "inference" / "api_key").write_text("nvapi-ROTATED-999\n")
    assert world.run("apply").returncode == 0
    providers = world.fake.openshell_state()["providers"]
    assert providers["default/nvidia"]["credential"] == "NVIDIA_API_KEY=nvapi-ROTATED-999"
    assert providers["cuda-dev/nvidia"]["credential"] == "NVIDIA_API_KEY=nvapi-ROTATED-999"


def test_credentials_never_appear_in_argv(world):
    assert world.run("install").returncode == 0
    assert world.run("apply").returncode == 0
    argv = json.dumps(world.fake.openshell_calls())
    assert "nvapi-TEST-KEY-123" not in argv and "brave-TEST-KEY-456" not in argv
    assert world.fake.openshell_state()["providers"]["default/brave"]["credential"] == \
        "BRAVE_API_KEY=brave-TEST-KEY-456"


def test_owed_gateway_restart_survives_a_failed_attempt(ab, world, monkeypatch):
    """If the gateway restart fails after an upgrade, the retry must still
    restart it (not just `start`, which would keep the old binary running)."""
    calls = []

    def flaky_gateway(shell, user, env, restart, timeout=120):
        calls.append(restart)
        if len(calls) == 2:
            raise ab.InstallerError("user bus not ready")

    monkeypatch.setattr(ab, "ensure_gateway", flaky_gateway)
    monkeypatch.setenv("HOME", str(world.home))
    base = ["install", "--inputs", str(world.inputs), "--state-dir", str(world.state),
            "--bin-dir", str(world.bin), "--opt-dir", str(world.opt), "--etc-dir", str(world.etc),
            "--as-current-user"]
    assert ab.main(base) == 0                   # fresh install: restart owed and done
    world.bom["spec"]["openshell"]["gateway"]["image"] = "quay.io/x/gateway@sha256:" + "4" * 64
    (world.inputs / "installer" / "installer-bom.yaml").write_text(yaml.safe_dump(world.bom))
    world.fake.images_for_bom(world.bom)
    assert ab.main(base) == 1                   # upgrade, but the restart fails
    assert ab.main(base) == 0                   # retry: nothing new to install...
    assert calls == [True, True, True]          # ...but the owed restart still happens
    assert ab.main(base) == 0
    assert calls[-1] is False                   # once done, later boots only `start`
    state = json.loads((world.state / "installed.json").read_text())
    assert "gatewayRestartPending" not in state


def test_install_lets_the_guest_agent_manage_ssh_keys(world):
    """KubeVirt accessCredentials writes authorized_keys through the guest
    agent; SELinux must allow it. Set once, then left alone."""
    assert world.run("install").returncode == 0
    assert world.fake.other_calls("setsebool") == [["-P", "virt_qemu_ga_manage_ssh", "on"]]
    assert world.run("install").returncode == 0
    assert len(world.fake.other_calls("setsebool")) == 1


def test_missing_selinux_boolean_is_not_fatal(world):
    (world.fake.state / "sebool.json").write_text("{}")
    result = world.run("install")
    assert result.returncode == 0
    assert "virt_qemu_ga_manage_ssh not available" in result.stdout


# -- moving to a new OpenShell release series (0.0.x -> 0.1.x) ---------------

def _old_gateway_state(world):
    state = world.home / ".local" / "state" / "openshell" / "gateway"
    state.mkdir(parents=True, exist_ok=True)
    (state / "openshell.db").write_text("0.0.x database")
    return state


def _backups(world):
    return sorted((world.home / ".local" / "state" / "openshell").glob("gateway.0.0.116-rhaiv.0.*"))


def test_a_new_release_series_moves_the_gateway_state_aside(world):
    state = _old_gateway_state(world)
    world.state.mkdir(parents=True, exist_ok=True)
    (world.state / "installed.json").write_text(json.dumps({"components": {"gateway": {
        "image": "quay.io/x/gw@sha256:" + "0" * 64, "version": "0.0.116-rhaiv.0"}}}))
    result = world.run("install")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "is a new release series" in result.stdout
    assert not state.exists()
    [backup] = _backups(world)
    assert (backup / "openshell.db").read_text() == "0.0.x database"
    installed = json.loads((world.state / "installed.json").read_text())
    assert "gatewayStateResetPending" not in installed
    # A reboot afterwards does not reset again.
    _old_gateway_state(world)
    assert world.run("install").returncode == 0
    assert state.exists() and len(_backups(world)) == 1


def test_an_interrupted_upgrade_still_resets_on_retry(world):
    """The first run recorded the new binaries and the pending reset, then died
    before moving the state; the retry sees the new version installed and must
    still reset (PR review, 1)."""
    state = _old_gateway_state(world)
    world.state.mkdir(parents=True, exist_ok=True)
    version = world.bom["spec"]["openshell"]["gateway"]["version"]
    (world.state / "installed.json").write_text(json.dumps({
        "components": {"gateway": {"image": world.bom["spec"]["openshell"]["gateway"]["image"],
                                   "version": version}},
        "gatewayStateResetPending": {"from": "0.0.116-rhaiv.0", "to": version}}))
    result = world.run("install")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not state.exists() and len(_backups(world)) == 1
    assert "gatewayStateResetPending" not in json.loads((world.state / "installed.json").read_text())
