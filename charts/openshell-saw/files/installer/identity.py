#!/usr/bin/env python3
"""Root-owned guest identity installation, launch and recovery diagnostics."""
import json
import base64
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

STATE = Path("/var/lib/spire/agent")
BOOTSTRAP = Path("/run/saw/spire")
MARKER = Path("/var/lib/saw/identity-enrolled")
SOCKET = "/spiffe-workload-api/agent.sock"
AGENT_BIN = "/usr/local/bin/spire-agent"
LAUNCH = Path("/usr/local/lib/saw/spire-agent-launch")
READY_HELPER = Path("/usr/libexec/saw-ready")
STATUS_PATH = Path("/var/lib/saw/status.json")
UNIT_PATH = Path("/etc/systemd/system/spire-agent.service")
POLICY_BASELINE = "selinux-policy-43.3-1.fc44"


def policy_module_path():
    """Prebuilt module shipped beside this file, or the repo build output."""
    here = Path(__file__).resolve().parent
    sibling = here / "saw_spire.pp.b64"
    if sibling.is_file():
        return sibling
    return here.parent / "selinux" / "saw_spire.pp.b64"


def run(*args, cwd=None, **kwargs):
    return subprocess.run(args, check=True, cwd=cwd, **kwargs)


def ensure_fcontext(path, ftype):
    add = subprocess.run(["semanage", "fcontext", "-a", "-t", ftype, path], capture_output=True)
    if add.returncode:
        run("semanage", "fcontext", "-m", "-t", ftype, path)


def drop_fcontext(spec):
    subprocess.run(["semanage", "fcontext", "-d", spec], capture_output=True)


def install_package_without_policy_upgrade(*packages):
    # policycoreutils helpers are not the policy baseline. Never let this
    # transaction install or upgrade a SELinux policy package.
    run("dnf", "install", "-y", "--exclude=selinux-policy*", *packages)


def file_type(path):
    listed = subprocess.run(["ls", "-Zd", path], capture_output=True, text=True, check=True).stdout
    return listed.split()[0].split(":")[2]


def install_selinux_agent_domain():
    """Load the prebuilt agent module and apply its file contexts.

    The module is built against POLICY_BASELINE. This function does not
    install development packages or compile policy.
    """
    if not shutil.which("semodule"):
        raise RuntimeError("semodule is missing; refusing to install selinux-policy packages")
    module = policy_module_path()
    blob = base64.b64decode(module.read_text())
    if len(blob) < 64:
        raise RuntimeError("prebuilt SPIRE policy module is empty")
    pp = Path("/var/lib/saw/saw_spire.pp")
    pp.parent.mkdir(parents=True, exist_ok=True)
    pp.write_bytes(blob)
    os.chmod(pp, 0o644)
    run("semodule", "-i", str(pp))
    # A local file-context rule overrides the module. The old container_file_t
    # rule and the launch-wrapper label must not win.
    drop_fcontext("/spiffe-workload-api(/.*)?")
    drop_fcontext(str(LAUNCH))
    if LAUNCH.exists():
        LAUNCH.unlink()
    for path in (AGENT_BIN, "/var/lib/spire", "/spiffe-workload-api", "/etc/spire"):
        if Path(path).exists():
            run("restorecon", "-R", path)


def readiness_decision(status, unit_exists, agent_healthy):
    """Installer completion and current agent health are separate from enrollment.

    A false result may make the VM unready. It must not discard credentials
    or request re-enrollment.
    """
    install = status.get("install") or {}
    apply = status.get("apply") or {}
    if install.get("phase") != "Done" or apply.get("phase") != "Done":
        return False
    bom = install.get("bom")
    if not bom or bom != apply.get("bom"):
        return False
    if unit_exists and not agent_healthy:
        return False
    return True


def ready():
    # Fixed purpose. Extra arguments are ignored and nothing is written.
    try:
        status = json.loads(STATUS_PATH.read_text())
    except (OSError, ValueError):
        raise SystemExit(1)
    healthy = True
    if UNIT_PATH.exists():
        try:
            probe = subprocess.run([AGENT_BIN, "healthcheck", "-socketPath", SOCKET],
                                   capture_output=True, timeout=5)
            healthy = probe.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            healthy = False
    raise SystemExit(0 if readiness_decision(status, UNIT_PATH.exists(), healthy) else 1)


def mount_inputs():
    BOOTSTRAP.mkdir(parents=True, exist_ok=True, mode=0o700)
    if subprocess.run(["mountpoint", "-q", str(BOOTSTRAP)]).returncode:
        run("mount", "-t", "iso9660", "-o", "ro,nosuid,nodev,noexec",
            "/dev/disk/by-id/virtio-saw-spire", str(BOOTSTRAP))


def credentials_present():
    # SPIRE 1.14 uses agent-data.json, not the old agent_svid.der file.
    # Permission/I/O errors propagate: they do not prove credential loss.
    try:
        cache = json.loads((STATE / "agent-data.json").read_text())
        keys = json.loads((STATE / "keys" / "keys.json").read_text())
        if not isinstance(cache, dict) or not isinstance(keys, dict):
            return False
        if not isinstance(cache.get("svid"), list) or not cache["svid"] or not isinstance(keys.get("keys"), dict):
            return False
        leaf_key = None
        for cert in cache["svid"]:
            pem = base64.b64decode(cert, validate=True)
            probe = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=pem,
                                   capture_output=True, timeout=5)
            if probe.returncode:
                return False
            if leaf_key is None:
                leaf_key = probe.stdout
        for name in ("agent-svid-A", "agent-svid-B"):
            if name not in keys["keys"]:
                continue
            key = base64.b64decode(keys["keys"][name], validate=True)
            probe = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout"],
                                   input=key, capture_output=True, timeout=5)
            if probe.returncode == 0 and probe.stdout == leaf_key:
                return True
        return False
    except (FileNotFoundError, ValueError, TypeError):
        return False


def status():
    generation = MARKER.read_text().strip() if MARKER.exists() else ""
    populated = credentials_present()
    state = "present" if populated else ("missing" if generation else "initializing")
    result = {"state": state, "generation": generation}
    logs = subprocess.run(["journalctl", "-u", "spire-agent", "-n", "8", "--no-pager"],
                          capture_output=True, text=True, timeout=5).stdout
    # Agent identifiers for join-token attestation contain bootstrap material.
    logs = re.sub(r"/spire/agent/join_token/[^\s\"']+", "/spire/agent/join_token/[redacted]", logs)
    token_file = BOOTSTRAP / "token"
    if token_file.exists():
        token = token_file.read_text().strip()
        if token:
            logs = logs.replace(token, "[redacted]")
    result["agentDiagnostics"] = logs
    print(json.dumps(result))


def agent_command(with_token):
    # The token is a file argument, never copied into logs. The path is the
    # service user's private copy, not the root-only bootstrap ISO.
    command = [AGENT_BIN, "run", "-config", "/etc/spire/agent.conf"]
    if with_token:
        command += ["-joinTokenFile", str(STATE / "bootstrap-token")]
    return command


def service_unit(with_token, transport, run_as):
    after = "After=network-online.target"
    if transport == "vsock":
        after += " spire-vsock-relay.service\nRequires=spire-vsock-relay.service"
    command = " ".join(agent_command(with_token))
    # The binary file context is the domain entrypoint. The unit does not
    # override the process context, and it does not call a launch wrapper.
    # CAP_SYS_PTRACE is the only capability. Rootless callers require it for
    # /proc/pid/exe; the policy still has to allow that use.
    return f"""[Unit]
Description=SAW SPIRE workload identity agent
Wants=network-online.target
{after}
[Service]
User={run_as}
Group={run_as}
AmbientCapabilities=CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_SYS_PTRACE
ExecStart={command}
Restart=on-failure
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def give_to_service_user(path, user, mode):
    os.chown(path, user.pw_uid, user.pw_gid)
    os.chmod(path, mode)


def prepare_agent_storage(user):
    """State and config are private to the service user. The socket directory
    stays traversable so attested callers can reach the Workload API."""
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for directory, dirnames, filenames in os.walk(parent):
        give_to_service_user(directory, user, 0o700)
        for name in filenames:
            file_path = Path(directory) / name
            mode = 0o400 if (file_path.stat().st_mode & 0o777) == 0o400 else 0o600
            give_to_service_user(file_path, user, mode)
    etc = Path("/etc/spire")
    etc.mkdir(parents=True, exist_ok=True, mode=0o700)
    give_to_service_user(etc, user, 0o700)
    for child in etc.iterdir():
        if child.is_file():
            give_to_service_user(child, user, 0o600)
    runtime = Path("/spiffe-workload-api")
    runtime.mkdir(exist_ok=True, mode=0o755)
    give_to_service_user(runtime, user, 0o755)
    sock = Path(SOCKET)
    if sock.exists():
        os.chown(sock, user.pw_uid, user.pw_gid)


def publish_bootstrap(user, with_token):
    """Copy bootstrap inputs into the service user's state directory.

    The ISO remains behind the root-only mount. Copies are mode 0400. The
    token copy exists only while this start still needs to enroll.
    """
    bundle_src = BOOTSTRAP / "bundle.pem"
    if not bundle_src.is_file():
        raise RuntimeError("SPIRE trust bundle is missing")
    bundle_dst = STATE / "bootstrap-bundle.pem"
    if bundle_dst.exists():
        bundle_dst.unlink()
    shutil.copyfile(bundle_src, bundle_dst)
    give_to_service_user(bundle_dst, user, 0o400)
    token_dst = STATE / "bootstrap-token"
    if with_token:
        token_src = BOOTSTRAP / "token"
        token = token_src.read_text().strip() if token_src.is_file() else ""
        if not token:
            raise RuntimeError("SPIRE join token is missing")
        if token_dst.exists():
            token_dst.unlink()
        shutil.copyfile(token_src, token_dst)
        give_to_service_user(token_dst, user, 0o400)
    elif token_dst.exists():
        token_dst.unlink()


def assert_agent_enforcing():
    mode = subprocess.run(["getenforce"], capture_output=True, text=True, check=True).stdout.strip()
    if mode != "Enforcing":
        raise RuntimeError(f"SELinux mode is {mode}")
    permissive = subprocess.run(["semanage", "permissive", "-l"], capture_output=True, text=True, check=True).stdout
    if re.search(r"(?m)^saw_spire_agent_t$", permissive):
        raise RuntimeError("saw_spire_agent_t is permissive")
    ps = subprocess.run(["ps", "-eo", "label,args"], capture_output=True, text=True, check=True).stdout
    contexts = []
    for line in ps.splitlines():
        if "spire-agent run " in line:
            contexts.append(line.split(None, 1)[0])
    if not contexts or any(":saw_spire_agent_t:" not in ctx for ctx in contexts):
        raise RuntimeError("SPIRE agent process is not saw_spire_agent_t")
    expected = {
        AGENT_BIN: "saw_spire_agent_exec_t",
        "/var/lib/spire": "saw_spire_var_lib_t",
        SOCKET: "saw_spire_runtime_t",
        "/etc/spire": "saw_spire_etc_t",
    }
    for path, label in expected.items():
        actual = file_type(path)
        if actual != label:
            raise RuntimeError(f"{path} is {actual}, expected {label}")


def install(config_path):
    cfg = json.loads(Path(config_path).read_text())
    identity = cfg["spiffe"]
    user = pwd.getpwnam(cfg["runtimeUser"])
    if user.pw_uid != identity["gatewayUID"]:
        raise RuntimeError("runtime UID differs from the registered gateway selector")
    mount_inputs()
    transport = identity["serverTransport"]
    if transport not in ("tcp", "vsock"):
        raise RuntimeError("unsupported SPIRE server transport")
    td = identity["trustDomain"]
    previous = Path("/etc/spire/trust-domain")
    if previous.exists() and previous.read_text().strip() != td:
        raise RuntimeError("SPIRE trust domain cannot change in place")
    Path("/etc/spire").mkdir(parents=True, exist_ok=True, mode=0o700)
    previous.write_text(td + "\n")
    generation = (BOOTSTRAP / "generation").read_text().strip()
    attempted = Path("/var/lib/saw/identity-bootstrap-generation")
    attempted.parent.mkdir(parents=True, exist_ok=True)
    prior = attempted.read_text().strip() if attempted.exists() else (MARKER.read_text().strip() if MARKER.exists() else "")
    if prior and prior != generation:
        # Only a new controller-authorized generation permits discarding state.
        # A retry in the same generation or a network outage never does this.
        subprocess.run(["systemctl", "stop", "spire-agent.service"], check=False, capture_output=True)
        if STATE.exists():
            shutil.rmtree(STATE)
    attempted.write_text(generation)
    prepare_agent_storage(user)
    with_token = not credentials_present()
    publish_bootstrap(user, with_token)
    if not shutil.which("semanage"):
        install_package_without_policy_upgrade("policycoreutils-python-utils")
    run("runuser", "-u", cfg["runtimeUser"], "--", "env",
        f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}", "systemctl", "--user", "enable", "--now", "podman.socket")
    conf = {"agent": {"data_dir": str(STATE), "trust_domain": td,
                      "server_address": "127.0.0.1" if transport == "vsock" else identity["serverAddress"],
                      "server_port": 18081 if transport == "vsock" else identity["serverPort"],
                      "socket_path": SOCKET, "trust_bundle_path": str(STATE / "bootstrap-bundle.pem"),
                      "log_level": "ERROR", "rebootstrap_mode": "never"},
            "plugins": {"NodeAttestor": [{"join_token": {"plugin_data": {}}}],
                        "KeyManager": [{"disk": {"plugin_data": {"directory": str(STATE / "keys")}}}],
                        "WorkloadAttestor": [
                            # Registration requires UID and executable path, not
                            # a digest. Keep path discovery while avoiding reads
                            # of container executables solely to hash them.
                            {"unix": {"plugin_data": {"discover_workload_path": True,
                                                       "workload_size_limit": -1}}},
                            {"docker": {"plugin_data": {
                                "docker_socket_path": f"unix:///run/user/{user.pw_uid}/podman/podman.sock",
                                "use_new_container_locator": True}}}]}}
    target = Path("/etc/spire/agent.conf")
    rendered = json.dumps(conf, indent=2) + "\n"
    changed = not target.exists() or target.read_text() != rendered
    target.write_text(rendered)
    give_to_service_user(target, user, 0o600)
    give_to_service_user(previous, user, 0o600)
    helper = Path("/usr/local/lib/saw/identity.py")
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(__file__, helper)
    os.chmod(helper, 0o755)
    Path("/usr/libexec/saw-identity-status").write_text(
        "#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/saw/identity.py status\n")
    os.chmod("/usr/libexec/saw-identity-status", 0o755)
    # Only these fixed, root-owned entry points get the supported QEMU-agent
    # transition. Sandbox domains remain confined and enforcing. Bare
    # `test -f /var/lib/saw/ready` is denied against var_lib_t.
    ensure_fcontext("/usr/libexec/saw-identity-status", "virt_qemu_ga_unconfined_exec_t")
    run("restorecon", "/usr/libexec/saw-identity-status")
    READY_HELPER.write_text(
        "#!/bin/sh\n"
        "# Fixed-purpose readiness check. Arguments are ignored.\n"
        "# Failure does not delete enrollment state or request re-enrollment.\n"
        "exec /usr/bin/python3 /usr/local/lib/saw/identity.py ready\n")
    os.chmod(READY_HELPER, 0o755)
    ensure_fcontext(str(READY_HELPER), "virt_qemu_ga_unconfined_exec_t")
    run("restorecon", str(READY_HELPER))
    run("setsebool", "-P", "virt_qemu_ga_run_unconfined", "on")
    install_selinux_agent_domain()
    # Fault injection is available only on explicitly designated test VMs.
    # QGA callers are authenticated platform administrators; this root-only
    # helper does not grant privileges to a guest user or sandbox process.
    test_helper = Path("/usr/libexec/saw-identity-test")
    if identity.get("testMode", False):
        test_helper.write_text('#!/bin/sh\nexec "$@"\n')
        test_helper.chmod(0o700)
        ensure_fcontext(str(test_helper), "virt_qemu_ga_unconfined_exec_t")
        run("restorecon", str(test_helper))
    elif test_helper.exists():
        test_helper.unlink()
    if transport == "vsock":
        if not shutil.which("socat"):
            install_package_without_policy_upgrade("socat")
        Path("/etc/systemd/system/spire-vsock-relay.service").write_text("""[Unit]
Description=SAW SPIRE VSOCK relay
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:18081,bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:2:18081
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
""")
    unit = service_unit(with_token, transport, user.pw_name)
    changed_unit = not UNIT_PATH.exists() or UNIT_PATH.read_text() != unit
    UNIT_PATH.write_text(unit)
    run("systemctl", "daemon-reload")
    if transport == "vsock":
        run("systemctl", "enable", "--now", "spire-vsock-relay.service")
    run("systemctl", "enable", "spire-agent.service")
    run("systemctl", "restart" if (changed or changed_unit) else "start", "spire-agent.service")
    for _ in range(90):
        healthy = subprocess.run([AGENT_BIN, "healthcheck", "-socketPath", SOCKET],
                                 capture_output=True, timeout=5)
        if healthy.returncode == 0:
            run("restorecon", "-R", "/spiffe-workload-api")
            if with_token and credentials_present():
                token_copy = STATE / "bootstrap-token"
                if token_copy.exists():
                    token_copy.unlink()
                UNIT_PATH.write_text(service_unit(False, transport, user.pw_name))
                run("systemctl", "daemon-reload")
            assert_agent_enforcing()
            MARKER.parent.mkdir(parents=True, exist_ok=True)
            MARKER.write_text((BOOTSTRAP / "generation").read_text().strip())
            return
        time.sleep(2)
    raise RuntimeError("SPIRE agent did not become attested and healthy")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "status":
        status()
    elif command == "ready":
        ready()
    else:
        try:
            install(sys.argv[1])
        except Exception:
            status()
            raise
