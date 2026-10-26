#!/usr/bin/env python3
"""Live compatibility gate. Exit 2 means blocked, never full acceptance success.

This runner currently covers infrastructure and binary compatibility probes.
Unimplemented VM scenarios are reported explicitly; an audit dependency does
not block unrelated VM implementation or testing.
No existing VM is mutated. Temporary version-probe pods are always cleaned up.
"""
import argparse
import base64
import datetime
import gzip
import hashlib
import json
import re
import signal
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parents[1]
NS = "zero-trust-workload-identity-manager"
SCENARIOS = (
    "automatic-provisioning", "identity-correctness", "isolation",
    "client-credentials", "token-exchange", "rotation", "negative-grants",
    "normal-restart", "state-loss-recovery", "bootstrap-failure",
    "infrastructure-outage", "lifecycle-cleanup", "scheduling",
    "disabled-mode-live", "audit", "network-policy", "trust-domain-drift-live",
)


def command(args, stdin=None, timeout=360):
    return subprocess.run(args, input=stdin, capture_output=True, text=True,
                          check=True, timeout=timeout).stdout


def ready(resource):
    return any(c["type"] == "Ready" and c["status"] == "True"
               for c in resource.get("status", {}).get("conditions", []))


PROCEDURES = {
    "bootstrap-failure": (
        "Manual evidence exists, including operator restore by deleting only "
        "saw.redhat.com/recovery-attempts. The compatibility gate does not execute it."
    ),
    "infrastructure-outage": (
        "Manual evidence exists for registrar and VM-to-SPIRE connectivity outages. "
        "The compatibility gate does not execute them. Post-expiry connectivity "
        "denial is --scenario vm-spire-deny-expiry; a bounded shared-server "
        "interruption is --scenario spire-server-outage."
    ),
    "lifecycle-cleanup": (
        "Profile removal and restoration is --scenario profile-remove-restore. "
        "The compatibility gate does not execute it. VM recreation and namespace "
        "deletion are not automated."
    ),
    "disabled-mode-live": (
        "Manual acceptance is recorded for identity-q, identity-s, and identity-t. "
        "Re-enable was not tested. "
        "The compatibility gate does not execute it."
    ),
}


def blocked_cases(transport):
    if transport != "tcp":
        raise ValueError("only tcp is supported and this acceptance run does not execute another transport")
    transports = (transport,)
    return [{"name": f"{t}/{case}", "status": "blocked",
             "detail": PROCEDURES.get(case) or (
                 "Pinned OpenShell lacks correlated injected identity audit claims"
                 if case == "audit" else "Scenario automation not implemented yet")}
            for t in transports for case in SCENARIOS]


def exhausted_observation(samples):
    """Require a new retry-limit reconcile while the exhausted VM stays unchanged."""
    if len(samples) < 2:
        raise ValueError("exhausted observation needs repeated samples")
    first = samples[0]
    identity = (first["generation"], first["attempts"], first["resourceVersion"],
                first["vmi"], first["agentPresent"], first["tokenExpired"])
    if identity != (first["generation"], "3", first["resourceVersion"], first["vmi"], False, True):
        raise ValueError("sample is not an exhausted retry")
    for sample in samples[1:]:
        current = (sample["generation"], sample["attempts"], sample["resourceVersion"],
                   sample["vmi"], sample["agentPresent"], sample["tokenExpired"])
        if current != identity:
            raise ValueError("exhausted state changed during observation")
    if samples[0]["latestLog"] == samples[-1]["latestLog"]:
        raise ValueError("no new retry-limit reconcile was observed")
    return "retry limit still enforced"


def operator_restore_command(state):
    """Return the only mutation an operator restore may perform."""
    if state.get("faultPresent"):
        raise ValueError("remove the test fault before resetting the retry budget")
    if state.get("attempts") != "3" or state.get("agentPresent") or not state.get("tokenExpired"):
        raise ValueError("operator restore requires an exhausted expired enrollment")
    namespace = state["namespace"]
    secret = state["secret"]
    if not namespace or not secret or "/" in namespace or "/" in secret:
        raise ValueError("operator restore target is not a single secret")
    return ["oc", "--context", state["context"], "annotate", "-n", namespace,
            "secret/" + secret, "saw.redhat.com/recovery-attempts-"]


def expiry_denial_result(before, denied, restored):
    """Post-expiry connectivity denial, then fresh issuance on the same enrollment."""
    if before.get("registrarReady") is not True or denied.get("registrarReady") is not True:
        raise AssertionError("registrar was not running throughout the denial")
    if not before.get("providers"):
        raise AssertionError("active providers were not recorded")
    expiries = [before["accessExp"], before["svidExp"]]
    if denied["now"] <= max(expiries):
        raise AssertionError("denial was checked before credential expiry")
    if denied.get("http") == 200:
        raise AssertionError("expired credentials produced a protected success")
    for phase in (denied, restored):
        if phase["generation"] != before["generation"] or phase["vmi"] != before["vmi"]:
            raise AssertionError("enrollment generation or VM changed")
        if phase.get("agentPresent") is not True or phase.get("credentialsPresent") is not True:
            raise AssertionError("credentials or the agent record disappeared")
    if restored.get("http") != 200:
        raise AssertionError("fresh protected request failed after connectivity returned")
    if restored["accessExp"] <= before["accessExp"] or restored["svidExp"] <= before["svidExp"]:
        raise AssertionError("issuance was not fresh")
    return "fresh issuance without a new enrollment generation"


def _sanitize(value):
    text = json.dumps(value)
    if "eyJ" in text or "/join_token/" in text:
        raise AssertionError("evidence contained a credential")
    return value


def _launcher(oc, namespace, vm):
    raw = command(oc + ["get", "pods", "-n", namespace, "-l", "vm.kubevirt.io/name=" + vm,
                        "--field-selector=status.phase=Running",
                        "-o", "jsonpath={.items[0].metadata.name}"], timeout=30)
    if not raw.strip():
        raise AssertionError("virt-launcher is not running")
    return raw.strip()


def _qga(oc, namespace, vm, request, timeout=60):
    raw = command(oc + ["exec", "-n", namespace, _launcher(oc, namespace, vm), "-c", "compute", "--",
                        "virsh", "-c", "qemu:///session", "qemu-agent-command",
                        namespace + "_" + vm, json.dumps(request)], timeout=timeout)
    result = json.loads(raw)["return"]
    if not isinstance(result, dict):
        raise AssertionError("guest agent returned an unexpected result")
    return result


def _guest(oc, namespace, vm, script, timeout=80):
    payload = base64.b64encode(script.encode()).decode()
    writer = ("import base64,pathlib; pathlib.Path('/tmp/saw-expiry.py').write_bytes(base64.b64decode('%s'))"
              % payload)
    started = _qga(oc, namespace, vm, {"execute": "guest-exec", "arguments": {
        "path": "/usr/libexec/saw-identity-test", "arg": ["python3", "-c", writer], "capture-output": True}})
    _qga_wait(oc, namespace, vm, started["pid"], 20)
    started = _qga(oc, namespace, vm, {"execute": "guest-exec", "arguments": {
        "path": "/usr/libexec/saw-identity-test",
        "arg": ["python3", "/tmp/saw-expiry.py"], "capture-output": True}})
    code, out = _qga_wait(oc, namespace, vm, started["pid"], timeout)
    if code:
        raise AssertionError("guest step failed")
    return _sanitize(json.loads(out))


def _qga_wait(oc, namespace, vm, pid, limit):
    deadline = time.time() + limit
    while time.time() < deadline:
        status = _qga(oc, namespace, vm, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if status.get("exited"):
            out = base64.b64decode(status.get("out-data") or "").decode()
            err = base64.b64decode(status.get("err-data") or "").decode()
            if "eyJ" in out or "eyJ" in err or "/join_token/" in out or "/join_token/" in err:
                raise AssertionError("guest output contained a credential")
            if status.get("exitcode"):
                detail = err.strip().splitlines()[-1][:180] if err.strip() else "guest step failed"
                if "eyJ" in detail or "/join_token/" in detail:
                    detail = "guest step failed"
                raise AssertionError(detail)
            return status.get("exitcode"), out
        time.sleep(1)
    raise AssertionError("guest step timed out")


def _identity_view(oc, namespace, vm):
    secret = json.loads(command(oc + ["get", "secret", "-n", namespace, vm + "-spire-join-token", "-o", "json"], timeout=30))
    generation = base64.b64decode(secret["data"]["generation"]).decode()
    path = base64.b64decode(secret["data"]["node-path"]).decode()
    path_hash = hashlib.sha256(path.encode()).hexdigest()[:12]
    vmi = json.loads(command(oc + ["get", "vmi", "-n", namespace, vm, "-o", "json"], timeout=30))
    agents = json.loads(command(oc + ["exec", "-n", NS, "spire-server-0", "-c", "spire-server", "--",
                                      "/spire-server", "agent", "list", "-output", "json"], timeout=40))
    present = False
    for agent in agents.get("agents", []):
        agent_path = (agent.get("id") or {}).get("path") or ""
        if "/join_token/" in agent_path and hashlib.sha256(agent_path.encode()).hexdigest()[:12] == path_hash:
            present = agent.get("banned") is False
    registrar = json.loads(command(oc + ["get", "deploy", "-n", NS, "saw-spire-registrar", "-o", "json"], timeout=30))
    return {"generation": generation, "vmi": vmi["metadata"]["uid"],
            "agentPresent": present, "pathHash": path_hash,
            "registrarReady": registrar["spec"].get("replicas") == 1 and registrar["status"].get("readyReplicas") == 1}


GUEST_EXPIRY = r"""
import base64, json, os, subprocess, sys
from pathlib import Path
AUDIENCE = sys.argv[1]
SPIRE = sys.argv[2]
TD = sys.argv[3]
NS = sys.argv[4]
VM = sys.argv[5]
ACTION = sys.argv[6]
PEER_NS = sys.argv[7] if len(sys.argv) > 7 else ""
PEER_VM = sys.argv[8] if len(sys.argv) > 8 else ""

def cu(args, timeout=40):
    env = os.environ.copy()
    env["XDG_RUNTIME_DIR"] = "/run/user/1000"
    return subprocess.run(["runuser", "-u", "cloud-user", "--", *args], capture_output=True, text=True, timeout=timeout, env=env)

def claims(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))

def redact(text):
    import re
    text = text or ""
    text = re.sub(r"eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*){0,2}", "[redacted]", text)
    text = re.sub(r"/join_token/\S+", "/join_token/[redacted]", text)
    return " ".join(text.split())[:240]

def grant(ws):
    import re
    try:
        result = cu(["openshell", "--gateway", "saw-installer", "--workspace", ws, "sandbox", "exec",
                     "-n", "agent", "--no-tty", "--", "curl", "-sS", "-m", "25", "-D", "-",
                     "http://identity-demo.saw-identity-demo.svc.cluster.local:8080/protected"])
    except subprocess.TimeoutExpired:
        return {"http": 0, "curlExit": None, "diagnostic": "guest command timed out", "error": "timeout"}
    stdout = result.stdout or ""
    match = re.search(r"HTTP/\S+\s+(\d+)", stdout)
    parts = re.split(r"\r?\n\r?\n", stdout, maxsplit=1)
    body = parts[-1].strip() if parts else ""
    summary = {"http": int(match.group(1)) if match else 0, "curlExit": result.returncode}
    try:
        payload = json.loads(body.splitlines()[0])
        summary.update({k: payload.get(k) for k in ("sub", "aud", "azp", "client_id", "exp", "error")})
    except Exception:
        if summary["http"] == 0:
            summary["error"] = "unparsed"
    diagnostic = redact((result.stderr or "") + " " + body)
    summary["diagnostic"] = diagnostic or redact(str(summary.get("error") or ""))
    return summary

def svid(ws):
    spiffe = "spiffe://%s/saw/%s/%s/ws/%s/sandbox/agent" % (TD, NS, VM, ws)
    result = fetch_svid(ws, spiffe)
    if not result.get("ok"):
        return {"error": result.get("error", "fetch failed")}
    return {key: result.get(key) for key in ("exp", "sub", "aud")}

def snapshot():
    status = json.loads(subprocess.run(["/usr/libexec/saw-identity-status"], capture_output=True, text=True, timeout=20).stdout)
    epoch = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout.strip())
    state = Path("/var/lib/spire/agent")
    out = {"epoch": epoch, "state": status.get("state"), "generation": status.get("generation"),
           "credentialsPresent": (state / "agent-data.json").is_file() and (state / "keys" / "keys.json").is_file(),
           "providers": {}, "grants": {}, "svids": {}}
    for ws in ("default", "research"):
        listed = cu(["openshell", "--gateway", "saw-installer", "--workspace", ws, "provider", "list"])
        out["providers"][ws] = listed.stdout.strip()[:300]
        out["grants"][ws] = grant(ws)
        out["svids"][ws] = svid(ws)
    print(json.dumps(out))

def firewall(add):
    import socket
    path = Path("/tmp/sawtest.nft")
    if add:
        path.write_text("table inet sawtest {\n chain output {\n  type filter hook output priority 0; policy accept;\n  ip daddr %s tcp dport 443 drop\n }\n}\n" % SPIRE)
        subprocess.run(["nft", "delete", "table", "inet", "sawtest"], capture_output=True)
        result = subprocess.run(["nft", "-f", str(path)], capture_output=True, text=True)
        key = "add"
    else:
        result = subprocess.run(["nft", "delete", "table", "inet", "sawtest"], capture_output=True, text=True)
        key = "delete"
    dial = "ok"
    try:
        socket.create_connection((SPIRE, 443), timeout=4).close()
    except Exception as exc:
        dial = type(exc).__name__
    print(json.dumps({key: result.returncode, "dial": dial}))

def research_probe():
    status = json.loads(subprocess.run(["/usr/libexec/saw-identity-status"], capture_output=True, text=True, timeout=20).stdout)
    epoch = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout.strip())
    state = Path("/var/lib/spire/agent")
    out = {"epoch": epoch, "state": status.get("state"), "generation": status.get("generation"),
           "credentialsPresent": (state / "agent-data.json").is_file() and (state / "keys" / "keys.json").is_file(),
           "providers": {}, "grant": grant("research"), "svid": svid("research")}
    for ws in ("default", "research"):
        listed = cu(["openshell", "--gateway", "saw-installer", "--workspace", ws, "provider", "list"])
        out["providers"][ws] = redact(listed.stdout)
    print(json.dumps(out))

def supervisor_container(ws):
    names = cu(["podman", "ps", "--format", "{{.Names}}"]).stdout.split()
    matches = []
    for name in names:
        if not name.startswith("openshell-supervisor-"):
            continue
        inspected = cu(["podman", "inspect", name, "--format", "{{json .Config.Labels}}"])
        if inspected.returncode:
            continue
        labels = json.loads(inspected.stdout)
        if (labels.get("openshell.managed") == "true" and
            labels.get("openshell.ai/isolation-role") == "supervisor" and
            labels.get("openshell.ai/sandbox-workspace") == ws and
            labels.get("openshell.ai/sandbox-name") == "agent"):
            matches.append(name)
    return matches[0] if len(matches) == 1 else ""

def fetch_svid(ws, spiffe):
    # OpenShell 0.1.2 mounts the socket only into its supervisor container.
    # podman exec against the workload container correctly cannot see it.
    container = supervisor_container(ws)
    if not container:
        return {"ok": False, "error": "exactly one managed supervisor container is required"}
    visible = cu(["podman", "exec", container, "/bin/sh", "-c",
                  "test -S /spiffe-workload-api/agent.sock"])
    if visible.returncode:
        return {"ok": False, "error": "supervisor socket is unavailable"}
    probe = "/usr/local/bin/saw-spire-probe-%s" % os.getpid()
    copied = cu(["podman", "cp", "/usr/local/bin/spire-agent", container + ":" + probe])
    if copied.returncode:
        return {"ok": False, "error": "probe binary copy failed"}
    try:
        fetched = cu(["podman", "exec", container, probe, "api", "fetch", "jwt",
                      "-socketPath", "/spiffe-workload-api/agent.sock", "-audience", AUDIENCE,
                      "-output", "json", "-spiffeID", spiffe], timeout=25)
    finally:
        removed = cu(["podman", "exec", "--user", "0", container, "/bin/rm", "-f", probe])
    if removed.returncode:
        return {"ok": False, "error": "probe binary cleanup failed"}
    if fetched.returncode:
        error = fetched.stderr or fetched.stdout or ""
        if "PermissionDenied" in error and "no identity issued" in error:
            return {"ok": False, "denied": True, "error": "PermissionDenied: no identity issued"}
        return {"ok": False, "error": redact(error) or "fetch failed"}
    try:
        data = json.loads(fetched.stdout)
    except Exception:
        return {"ok": False, "error": "unparsed"}
    tokens = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        for entry in item.get("svids") or []:
            tokens.append((entry.get("spiffe_id"), entry.get("svid") or ""))
    if len(tokens) != 1 or tokens[0][0] != spiffe:
        return {"ok": False, "error": "unexpected identity set"}
    token = tokens[0][1]
    if token.count(".") != 2:
        return {"ok": False, "error": "missing"}
    body = claims(token)
    audiences = body.get("aud")
    if body.get("sub") != spiffe or audiences not in (AUDIENCE, [AUDIENCE]):
        return {"ok": False, "error": "unexpected SVID claims"}
    return {"ok": True, "sub": body.get("sub"), "aud": AUDIENCE, "exp": body.get("exp")}

def isolation():
    base = "spiffe://%s/saw/%s/%s" % (TD, NS, VM)
    wanted = {"gateway": base + "/gateway",
              "default": base + "/ws/default/sandbox/agent",
              "research": base + "/ws/research/sandbox/agent"}
    print(json.dumps({ws: {name: fetch_svid(ws, spiffe) for name, spiffe in wanted.items()}
                      for ws in ("default", "research")}))

def workload_sockets():
    names = cu(["podman", "ps", "--format", "{{.Names}}"]).stdout.split()
    result = {}
    for ws in ("default", "research"):
        matches = [name for name in names if name.startswith("openshell-%s--agent-" % ws)]
        if len(matches) != 1:
            result[ws] = {"error": "exactly one workload container is required"}
            continue
        checked = cu(["podman", "exec", matches[0], "/bin/sh", "-c",
                      "test -S /spiffe-workload-api/agent.sock"])
        result[ws] = {"hidden": checked.returncode == 1, "probeExit": checked.returncode}
    print(json.dumps(result))

def attest():
    import re
    mode = subprocess.run(["getenforce"], capture_output=True, text=True).stdout.strip()
    permissive = subprocess.run(["semanage", "permissive", "-l"], capture_output=True, text=True)
    ps = subprocess.run(["ps", "-eo", "label,args"], capture_output=True, text=True).stdout
    contexts = [line.split(None, 1)[0] for line in ps.splitlines() if "spire-agent run " in line]
    conf_path = Path("/etc/spire/agent.conf")
    unix = {}
    if conf_path.is_file():
        data = json.loads(conf_path.read_text())
        for item in data.get("plugins", {}).get("WorkloadAttestor", []):
            if "unix" in item:
                unix = item["unix"].get("plugin_data") or {}
    journal = subprocess.run(["journalctl", "-u", "spire-agent", "-o", "cat", "--no-pager", "-n", "200"],
                             capture_output=True, text=True)
    bad = []
    for line in (journal.stdout or "").splitlines():
        if re.search(r"attestor|workload path|selector", line, re.I) and re.search(r"error|fail", line, re.I):
            bad.append(redact(line))
    policy = subprocess.run(["rpm", "-q", "selinux-policy"], capture_output=True, text=True).stdout.strip()
    print(json.dumps({"enforce": mode,
                      "agentPermissive": bool(re.search(r"(?m)^saw_spire_agent_t$", permissive.stdout or "")),
                      "contexts": contexts, "unix": unix, "journalRc": journal.returncode,
                      "journalLines": len((journal.stdout or "").splitlines()),
                      "attestorErrors": bad[:8], "policy": policy}))

def cross_fetch():
    base = "spiffe://%s/saw/%s/%s" % (TD, PEER_NS, PEER_VM)
    wanted = {"gateway": base + "/gateway",
              "default": base + "/ws/default/sandbox/agent",
              "research": base + "/ws/research/sandbox/agent"}
    print(json.dumps({ws: {name: fetch_svid(ws, spiffe) for name, spiffe in wanted.items()}
                      for ws in ("default", "research")}))

def guest_status():
    status = json.loads(subprocess.run(["/usr/libexec/saw-identity-status"], capture_output=True, text=True, timeout=20).stdout)
    state = Path("/var/lib/spire/agent")
    print(json.dumps({"epoch": int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout.strip()),
                      "state": status.get("state"), "generation": status.get("generation"),
                      "credentialsPresent": (state / "agent-data.json").is_file() and (state / "keys" / "keys.json").is_file()}))

if ACTION == "snapshot":
    snapshot()
elif ACTION == "research":
    research_probe()
elif ACTION == "isolation":
    isolation()
elif ACTION == "status":
    guest_status()
elif ACTION == "attest":
    attest()
elif ACTION == "cross":
    cross_fetch()
elif ACTION == "workload-sockets":
    workload_sockets()
elif ACTION == "epoch":
    print(json.dumps({"epoch": int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout.strip())}))
elif ACTION == "dial":
    import socket
    result = "ok"
    try:
        socket.create_connection((SPIRE, 443), timeout=4).close()
    except Exception as exc:
        result = type(exc).__name__
    print(json.dumps({"dial": result}))
elif ACTION == "deny":
    firewall(True)
elif ACTION == "allow":
    firewall(False)
else:
    raise SystemExit(1)
"""


def _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, action, timeout=90, peer_ns="", peer_vm=""):
    script = GUEST_EXPIRY
    # The uploaded program reads its parameters from argv. qemu-exec passes them.
    wrapped = "import sys\nsys.argv = ['saw-expiry.py', %r, %r, %r, %r, %r, %r, %r, %r]\n" % (
        audience, spire_ip, trust_domain, namespace, vm, action, peer_ns, peer_vm) + script
    return _guest(oc, namespace, vm, wrapped, timeout=timeout)


def run_vm_spire_deny_expiry(args):
    """Execute the post-expiry VM-to-SPIRE denial and always remove the nft table."""
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    namespace, vm = args.vm_namespace, args.vm
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
    trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
    service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
    spire_ip = service["spec"]["clusterIP"]
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", spire_ip):
        raise AssertionError("SPIRE Service address is not an IPv4 cluster IP")
    report = {"scenario": "vm-spire-deny-expiry", "executed": True, "acceptanceComplete": False,
              "status": "fail", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    fault = False
    body_error = None
    try:
        before_id = _identity_view(oc, namespace, vm)
        guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=100)
        if not all(str(guest["providers"].get(ws, "")).strip() for ws in ("default", "research")):
            raise AssertionError("active providers were not recorded")
        access_exp = min(guest["grants"][ws]["exp"] for ws in ("default", "research"))
        svid_exp = min(guest["svids"][ws]["exp"] for ws in ("default", "research"))
        before = {**before_id, "registrarReady": before_id["registrarReady"],
                  "providers": guest["providers"], "accessExp": access_exp, "svidExp": svid_exp,
                  "credentialsPresent": guest["credentialsPresent"],
                  "grants": guest["grants"], "svids": {ws: guest["svids"][ws] for ws in ("default", "research")}}
        report["before"] = _sanitize(before)
        if not all(guest["grants"][ws]["http"] == 200 for ws in ("default", "research")):
            raise AssertionError("baseline protected requests were not successful")
        denied_fw = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "deny", timeout=30)
        if denied_fw.get("add") == 0:
            fault = True
        if denied_fw.get("add") != 0 or denied_fw.get("dial") == "ok":
            raise AssertionError("SPIRE connectivity was not denied")
        deadline = max(access_exp, svid_exp) + 5
        while True:
            current = _identity_view(oc, namespace, vm)
            if current["generation"] != before["generation"] or current["vmi"] != before["vmi"] or not current["registrarReady"]:
                raise AssertionError("enrollment changed while SPIRE connectivity was denied")
            if time.time() > deadline:
                epoch = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "epoch", timeout=20)
                if epoch["epoch"] > max(access_exp, svid_exp):
                    break
            if time.time() > deadline + 120:
                raise AssertionError("guest clock did not pass credential expiry")
            time.sleep(15)
        denied_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=100)
        denied_id = _identity_view(oc, namespace, vm)
        denied = {**denied_id, "now": denied_guest["epoch"], "credentialsPresent": denied_guest["credentialsPresent"],
                  "http": denied_guest["grants"]["default"]["http"],
                  "grants": denied_guest["grants"]}
        report["denied"] = _sanitize(denied)
        if denied["http"] == 200 or denied_guest["grants"]["research"]["http"] == 200:
            raise AssertionError("expired credentials produced a protected success")
    except AssertionError as error:
        body_error = error
        report["detail"] = str(error)[:500]
    finally:
        if fault:
            try:
                allowed = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "allow", timeout=30)
                report["allow"] = _sanitize(allowed)
                report["faultRestored"] = allowed.get("delete") == 0 and allowed.get("dial") == "ok"
            except AssertionError:
                report["faultRestored"] = False
    if body_error or report.get("faultRestored") is False:
        return report
    restored_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=100)
    restored_id = _identity_view(oc, namespace, vm)
    restored = {**restored_id, "credentialsPresent": restored_guest["credentialsPresent"],
                "http": restored_guest["grants"]["default"]["http"],
                "accessExp": min(restored_guest["grants"][ws]["exp"] for ws in ("default", "research")),
                "svidExp": min(restored_guest["svids"][ws]["exp"] for ws in ("default", "research")),
                "grants": restored_guest["grants"],
                "svids": restored_guest["svids"]}
    report["restored"] = _sanitize(restored)
    try:
        report["result"] = expiry_denial_result(before, denied, restored)
        if restored_guest["grants"]["research"]["http"] != 200:
            raise AssertionError("research grant was not fresh")
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError) as error:
        report["status"] = "fail"
        report["detail"] = str(error)[:500]
    return report


def _replicas(oc, kind, name):
    obj = json.loads(command(oc + ["get", kind, "-n", NS, name, "-o", "json"], timeout=30))
    return obj["spec"].get("replicas", 1), obj.get("status", {}).get("readyReplicas", 0)


def _wait_replicas(oc, kind, name, desired, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        actual, ready_count = _replicas(oc, kind, name)
        if actual != desired:
            raise AssertionError(f"{kind}/{name} was reconciled to {actual}, expected {desired}")
        if ready_count == desired:
            return
        time.sleep(3)
    raise AssertionError(f"{kind}/{name} did not reach {desired} ready replicas")


def _spire_consumers(oc):
    agents = json.loads(command(oc + ["exec", "-n", NS, "spire-server-0", "-c", "spire-server", "--",
                                    "/spire-server", "agent", "list", "-output", "json"], timeout=40))
    entries = json.loads(command(oc + ["exec", "-n", NS, "spire-server-0", "-c", "spire-server", "--",
                                     "/spire-server", "entry", "show", "-output", "json"], timeout=40))
    if agents.get("next_page_token") or entries.get("next_page_token"):
        raise AssertionError("shared SPIRE inventory was truncated")
    return {"agents": len(agents.get("agents", [])), "entries": len(entries.get("entries", []))}


def run_spire_server_outage(args):
    """Stop the shared server long enough to expire the canary's cached token, then restore it."""
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    namespace, vm = args.vm_namespace, args.vm
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    operator = "zero-trust-workload-identity-manager-controller-manager"
    report = {"scenario": "spire-server-outage", "executed": True, "acceptanceComplete": False,
              "status": "fail", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
    if (vm_obj["metadata"].get("labels") or {}).get("saw.redhat.com/spiffe") != "true":
        raise AssertionError("target VM is not explicitly opted into SPIFFE")
    trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
    service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
    spire_ip = service["spec"]["clusterIP"]
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", spire_ip):
        raise AssertionError("SPIRE Service address is not an IPv4 cluster IP")
    if _replicas(oc, "deploy", operator) != (1, 1) or _replicas(oc, "sts", "spire-server") != (1, 1):
        raise AssertionError("SPIRE operator and server must each start with one ready replica")
    before_id = _identity_view(oc, namespace, vm)
    report["sharedConsumersBefore"] = _spire_consumers(oc)
    before_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=100)
    baseline = before_guest["grants"]["default"]
    if (baseline.get("http"), baseline.get("curlExit")) != (200, 0):
        raise AssertionError("canary protected baseline did not succeed")
    if "protected" not in before_guest["providers"].get("default", ""):
        raise AssertionError("the expected client-credentials provider is not present")
    if baseline.get("sub") != baseline.get("azp") or baseline.get("sub") != baseline.get("client_id"):
        raise AssertionError("baseline is not a sandbox-bound client-credentials grant")
    report["before"] = _sanitize({"identity": before_id, "guestState": before_guest["state"],
                                  "guestGeneration": before_guest["generation"],
                                  "provider": "protected/saw-demo-cc", "grant": baseline})
    scaled_operator = False
    scaled_server = False
    interrupted = False
    old_handler = signal.getsignal(signal.SIGTERM)
    def stop_signal(_signum, _frame):
        raise InterruptedError("outage runner interrupted")
    signal.signal(signal.SIGTERM, stop_signal)
    try:
        scaled_operator = True
        command(oc + ["scale", "deploy/" + operator, "-n", NS, "--replicas=0"], timeout=30)
        _wait_replicas(oc, "deploy", operator, 0)
        scaled_server = True
        command(oc + ["scale", "sts/spire-server", "-n", NS, "--replicas=0"], timeout=30)
        _wait_replicas(oc, "sts", "spire-server", 0)
        outage_epoch = int(time.time())
        report["outageStart"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Both demo access tokens and SPIRE JWT-SVIDs have five-minute maximum validity.
        deadline = max(outage_epoch + 310, int(baseline["exp"]) + 10)
        if deadline > outage_epoch + 420:
            raise AssertionError("credential expiry exceeds the bounded outage window")
        while time.time() <= deadline:
            if _replicas(oc, "sts", "spire-server") != (0, 0):
                raise AssertionError("SPIRE server returned during the outage window")
            if _replicas(oc, "deploy", operator) != (0, 0):
                raise AssertionError("SPIRE operator returned during the outage window")
            time.sleep(min(15, max(1, deadline - time.time() + 1)))
        denied_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=100)
        denied = denied_guest["grants"]["default"]
        status = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "status", timeout=30)
        report["denied"] = _sanitize({"epoch": denied_guest["epoch"], "grant": denied,
                                      "guest": status, "serverReplicas": _replicas(oc, "sts", "spire-server")})
        if denied_guest["epoch"] <= max(outage_epoch + 300, int(baseline["exp"])):
            raise AssertionError("denial was sampled before cached credentials expired")
        if (denied.get("http"), denied.get("curlExit")) != (502, 0):
            raise AssertionError("post-expiry protected request did not return parsed HTTP 502")
        if status.get("generation") != before_id["generation"] or not status.get("credentialsPresent"):
            raise AssertionError("guest enrollment changed during server outage")
    except (AssertionError, OSError, subprocess.SubprocessError, InterruptedError) as error:
        report["detail"] = str(error)[:500]
        interrupted = True
    finally:
        restore_errors = []
        if scaled_server:
            try:
                command(oc + ["scale", "sts/spire-server", "-n", NS, "--replicas=1"], timeout=30)
                _wait_replicas(oc, "sts", "spire-server", 1, timeout=240)
            except (AssertionError, OSError, subprocess.SubprocessError) as error:
                restore_errors.append(str(error)[:250])
        if scaled_operator:
            try:
                command(oc + ["scale", "deploy/" + operator, "-n", NS, "--replicas=1"], timeout=30)
                _wait_replicas(oc, "deploy", operator, 1, timeout=180)
            except (AssertionError, OSError, subprocess.SubprocessError) as error:
                restore_errors.append(str(error)[:250])
        report["faultRestored"] = not restore_errors
        if restore_errors:
            report["restoreDetail"] = "; ".join(restore_errors)[:500]
        signal.signal(signal.SIGTERM, old_handler)
    if interrupted or not report["faultRestored"]:
        return report
    for _ in range(12):
        restored_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=100)
        if restored_guest["grants"]["default"].get("http") == 200:
            break
        time.sleep(10)
    restored_id = _identity_view(oc, namespace, vm)
    report["sharedConsumersAfter"] = _spire_consumers(oc)
    restored = restored_guest["grants"]["default"]
    report["restored"] = _sanitize({"identity": restored_id, "guestGeneration": restored_guest["generation"],
                                    "guestState": restored_guest["state"], "grant": restored})
    if (restored.get("http"), restored.get("curlExit")) != (200, 0):
        report["detail"] = "protected grant did not recover after server restoration"
    elif restored_id["generation"] != before_id["generation"] or restored_id["vmi"] != before_id["vmi"]:
        report["detail"] = "recovery minted a new enrollment or restarted the VM"
    elif restored["exp"] <= baseline["exp"] or restored.get("sub") != baseline.get("sub"):
        report["detail"] = "fresh sandbox-bound token was not observed"
    else:
        report["status"] = "pass"
        report["result"] = "post-expiry fail-closed and fresh grant on the same enrollment"
    return report


def run(args):
    run_id = "identity-" + uuid.uuid4().hex[:10]
    namespace = args.namespace_prefix + "-" + run_id
    if len(namespace) > 63 or not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", namespace):
        raise ValueError("namespace-prefix must produce a DNS label of at most 63 characters")
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    report = {"runId": run_id, "context": args.context,
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "commit": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
              "dirty": bool(command(["git", "-C", str(ROOT), "status", "--porcelain"]).strip()),
              "stage": "compatibility-gate", "acceptanceComplete": False, "checks": []}
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    created = False

    def get(kind, name=None, ns=None):
        return json.loads(command(oc + ["get", kind] + ([name] if name else [])
                                  + (["-n", ns] if ns else []) + ["-o", "json"]))

    def check(name, action):
        try:
            detail = action()
            report["checks"].append({"name": name, "status": "pass", "detail": detail})
        except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
            # Deliberately omit arbitrary command stdout/stderr from artifacts.
            report["checks"].append({"name": name, "status": "fail",
                                     "detail": str(error)[:1000]})

    def check_ready(kind):
        obj = get(kind, "cluster")
        assert ready(obj), f"{kind}/cluster is not Ready"
        return "Ready"

    def discovery():
        server = get("spireserver", "cluster")
        issuer = server["spec"]["jwtIssuer"]
        origin = urlparse(issuer)
        assert origin.scheme == "https" and not origin.username and not origin.password
        # curl uses the workstation certificate trust store; never disable TLS validation.
        doc = json.loads(command(["curl", "--fail", "--silent", "--show-error",
                                  "--max-time", "30", issuer + "/.well-known/openid-configuration"]))
        assert doc["issuer"] == issuer, "Discovery issuer mismatch"
        keys_url = urlparse(doc["jwks_uri"])
        assert keys_url.scheme == "https" and keys_url.netloc == origin.netloc, "Unexpected JWKS origin"
        keys = json.loads(command(["curl", "--fail", "--silent", "--show-error",
                                   "--max-time", "30", doc["jwks_uri"]]))
        assert keys.get("keys"), "Empty JWKS"
        return {"issuer": issuer, "keyCount": len(keys["keys"])}

    def probe(component, image, binary, expected):
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": component, "namespace": namespace,
                            "labels": {"saw.redhat.com/identity-test-run": run_id}},
               "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": component, "image": image,
                                        "command": [binary, "--version"],
                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                            "capabilities": {"drop": ["ALL"]}},
                                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                      "limits": {"cpu": "1", "memory": "256Mi"}}}]}}
        command(oc + ["create", "-f", "-"], json.dumps(pod))
        command(oc + ["wait", "-n", namespace, "pod/" + component,
                      "--for=jsonpath={.status.phase}=Succeeded", "--timeout=180s"])
        output = command(oc + ["logs", "-n", namespace, component]).strip()
        assert expected.split("-", 1)[0] in output, "Unexpected pinned binary version"
        return {"image": image, "version": output}

    try:
        report["server"] = command(oc + ["whoami", "--show-server"]).strip()
        report["clusterVersion"] = get("clusterversion", "version")["status"]["desired"]["version"]
        for kind in ("spireserver", "spireagent", "spiffecsidriver",
                     "spireoidcdiscoveryprovider", "zerotrustworkloadidentitymanager"):
            check(kind, lambda kind=kind: check_ready(kind))
        check("https-discovery-jwks", discovery)
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace,
              "labels": {"saw.redhat.com/identity-test-run": run_id}}}
        command(oc + ["create", "-f", "-"], json.dumps(ns))
        created = True
        bom = yaml.safe_load((ROOT / "charts/openshell-saw/values.yaml").read_text())["bom"]
        for comp, binary in (("gateway", "/usr/local/bin/openshell-gateway"),
                             ("cli", "/usr/local/bin/openshell"),
                             ("supervisor", "/openshell-supervisor")):
            pinned = bom["spec"]["openshell"][comp]
            image, expected = pinned["image"], pinned["version"]
            check("binary/" + comp,
                  lambda comp=comp, image=image, binary=binary, expected=expected:
                  probe(comp, image, binary, expected))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["checks"].append({"name": "preflight", "status": "fail", "detail": str(error)[:1000]})
    finally:
        if created:
            def cleanup():
                ns = get("namespace", namespace)
                assert ns["metadata"]["labels"].get("saw.redhat.com/identity-test-run") == run_id
                command(oc + ["delete", "namespace", namespace, "--wait=true", "--timeout=120s"])
                return "Run-owned namespace deleted"
            check("cleanup", cleanup)
        report["checks"].extend(blocked_cases(args.transport))
        report["status"] = "fail" if any(c["status"] == "fail" for c in report["checks"]) else "blocked"
        path = args.artifact_dir / (run_id + ".json")
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{report['status'].upper()}: {path}")
    return 1 if report["status"] == "fail" else 2


def research_expiry_result(before, denied, restored):
    """Research protected call fails closed after expiry, then a new grant uses the same enrollment."""
    for phase, label in ((before, "before"), (restored, "after")):
        providers = phase.get("providers") or {}
        if not all(str(providers.get(ws, "")).strip() for ws in ("default", "research")):
            raise AssertionError("providers were not recorded " + label + " restoration")
    if before.get("registrarReady") is not True or denied.get("registrarReady") is not True:
        raise AssertionError("registrar was not running throughout the research denial")
    if denied["now"] <= max(before["accessExp"], before["svidExp"]):
        raise AssertionError("research denial was checked before credential expiry")
    if not isinstance(denied.get("curlExit"), int) or not str(denied.get("diagnostic") or "").strip():
        raise AssertionError("research curl exit status and diagnostics were not recorded")
    if denied.get("http") in (None, 0, 200) or denied.get("error") in (None, "", "unparsed"):
        raise AssertionError("research response did not establish fail-closed behavior")
    for phase in (denied, restored):
        if phase["generation"] != before["generation"] or phase["vmi"] != before["vmi"]:
            raise AssertionError("research recovery replaced the enrollment")
        if phase.get("agentPresent") is not True or phase.get("credentialsPresent") is not True:
            raise AssertionError("credentials or the agent record disappeared")
    if restored.get("http") != 200 or restored["accessExp"] <= before["accessExp"] or restored["svidExp"] <= before["svidExp"]:
        raise AssertionError("research issuance was not fresh")
    return "research fail-closed after expiry without replacing enrollment"


def profile_removal_result(before, held, removed, denied, restored):
    """Research registration survives registrar downtime, then is removed and recreated."""
    if before.get("registrarReady") is not True or before.get("parentHash") != before.get("agentHash"):
        raise AssertionError("research registration was not parented to the current agent")
    if "research" not in before["paths"] or "default" not in before["paths"] or "gateway" not in before["paths"]:
        raise AssertionError("expected registrations were not present")
    if held.get("registrarReady") is not False or "research" not in held["paths"]:
        raise AssertionError("downtime did not hold the existing registration")
    if held["generation"] != before["generation"] or held["vmi"] != before["vmi"]:
        raise AssertionError("enrollment changed during registrar downtime")
    if "research" in removed["paths"] or "default" not in removed["paths"] or "gateway" not in removed["paths"]:
        raise AssertionError("stale research registration was not removed")
    if removed["parentHash"] != before["agentHash"] or removed.get("agentPresent") is not True:
        raise AssertionError("profile removal changed the remaining parent or agent")
    if removed["generation"] != before["generation"] or removed["vmi"] != before["vmi"]:
        raise AssertionError("profile removal minted an enrollment or restarted the VM")
    if denied["now"] <= denied["accessExp"] or denied["researchHttp"] == 200 or denied.get("researchSvid") == "ok":
        raise AssertionError("expired research credential was still issued or accepted")
    if denied["defaultHttp"] != 200:
        raise AssertionError("default workspace did not keep working")
    if restored["generation"] != before["generation"] or restored["vmi"] != before["vmi"]:
        raise AssertionError("restoration restarted the VM or minted a generation")
    if "research" not in restored["paths"] or restored["parentHash"] != before["agentHash"]:
        raise AssertionError("restored registration was not parented to the current agent")
    if restored["selectors"] != before["selectors"] or restored.get("admin") is not False:
        raise AssertionError("restored registration selectors or admin bit changed")
    if restored["researchHttp"] != 200 or restored["accessExp"] <= before["accessExp"]:
        raise AssertionError("restored research grant was not fresh")
    return "stale registration removed and restored on the same agent"


def _owned_entries(oc, vm_uid):
    raw = command(oc + ["exec", "-n", NS, "spire-server-0", "-c", "spire-server", "--",
                        "/spire-server", "entry", "show", "-output", "json"], timeout=60)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AssertionError("SPIRE entry list was not JSON") from error
    if data.get("next_page_token"):
        raise AssertionError("SPIRE entry list was truncated")
    hint = "saw:" + vm_uid
    found = []
    for entry in data.get("entries") or []:
        if entry.get("hint") != hint:
            continue
        parent = ((entry.get("parent_id") or {}).get("path")) or ""
        path = ((entry.get("spiffe_id") or {}).get("path")) or ""
        selectors = sorted("%s:%s" % (item.get("type"), item.get("value")) for item in entry.get("selectors") or [])
        found.append({"id": entry.get("id"), "path": path,
                      "parentHash": hashlib.sha256(parent.encode()).hexdigest()[:12],
                      "admin": entry.get("admin") is True, "selectors": selectors,
                      "jwtSvidTtl": entry.get("jwt_svid_ttl")})
    return _sanitize(found)


def _registrar_pods(oc):
    deployment = json.loads(command(oc + ["get", "deploy", "-n", NS, "saw-spire-registrar", "-o", "json"], timeout=30))
    selector = ",".join("%s=%s" % item for item in sorted(deployment["spec"]["selector"]["matchLabels"].items()))
    pods = json.loads(command(oc + ["get", "pods", "-n", NS, "-l", selector, "-o", "json"], timeout=30))
    return [pod["metadata"]["name"] for pod in pods.get("items", [])
            if pod.get("status", {}).get("phase") not in ("Succeeded", "Failed")]


def _wait_registrar(oc, replicas):
    deadline = time.time() + 120
    while time.time() < deadline:
        deployment = json.loads(command(oc + ["get", "deploy", "-n", NS, "saw-spire-registrar", "-o", "json"], timeout=30))
        ready = deployment.get("status", {}).get("readyReplicas") or 0
        if deployment.get("spec", {}).get("replicas") == replicas and ready == replicas:
            if replicas == 0 and not _registrar_pods(oc):
                return
            if replicas == 1:
                return
        time.sleep(2)
    raise AssertionError("registrar replica change did not finish")


def _scale_registrar(oc, replicas):
    command(oc + ["scale", "deploy/saw-spire-registrar", "-n", NS, "--replicas=%s" % replicas], timeout=30)
    _wait_registrar(oc, replicas)


def _profile_keys(namespace, vm):
    return tuple("profiles__identity-demo__research__%s.yaml" % name
                 for name in ("providers", "sandbox", "workspace"))


def _entry_names(entries, namespace, vm):
    base = "/saw/%s/%s/" % (namespace, vm)
    names = set()
    for entry in entries:
        path = entry["path"]
        if path == base + "gateway":
            names.add("gateway")
        elif path == base + "ws/default/sandbox/agent":
            names.add("default")
        elif path == base + "ws/research/sandbox/agent":
            names.add("research")
        else:
            names.add("other")
    return names


def _research_entry(entries, namespace, vm):
    path = "/saw/%s/%s/ws/research/sandbox/agent" % (namespace, vm)
    found = [entry for entry in entries if entry["path"] == path]
    return found[0] if found else None


def _wait_research(oc, vm_uid, namespace, vm, present):
    deadline = time.time() + 90
    last = None
    while time.time() < deadline:
        last = _owned_entries(oc, vm_uid)
        if (_research_entry(last, namespace, vm) is not None) is present:
            return last
        time.sleep(5)
    raise AssertionError("research registration did not reach the expected presence")


def _restore_profile_keys(oc, namespace, saved):
    command(oc + ["patch", "cm", "saw-bom-profiles", "-n", namespace, "--type", "merge",
                  "-p", json.dumps({"data": saved})], timeout=30)


def run_profile_remove_restore(args):
    """Remove the research profile while the registrar is down, then restore it."""
    namespace, vm = args.vm_namespace, args.vm
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    report = {"scenario": "profile-remove-restore", "executed": True, "acceptanceComplete": False,
              "status": "fail", "faultRestored": False,
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    removed = False
    scaled = False
    saved = None
    vm_uid = None
    body_error = None
    result = None
    try:
        vm_object = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
        trust_domain = (vm_object["metadata"].get("annotations") or {}).get("saw.redhat.com/trust-domain")
        if not trust_domain:
            raise AssertionError("VM has no trust domain")
        vm_uid = vm_object["metadata"]["uid"]
        identity = _identity_view(oc, namespace, vm)
        if identity["registrarReady"] is not True:
            raise AssertionError("registrar was not ready")
        configmap = json.loads(command(oc + ["get", "cm", "-n", namespace, "saw-bom-profiles", "-o", "json"], timeout=30))
        keys = _profile_keys(namespace, vm)
        if any(key not in configmap.get("data", {}) for key in keys):
            raise AssertionError("research profile documents are absent")
        saved = {key: configmap["data"][key] for key in keys}
        entries = _owned_entries(oc, vm_uid)
        names = _entry_names(entries, namespace, vm)
        research = _research_entry(entries, namespace, vm)
        if names != {"gateway", "default", "research"} or research is None:
            raise AssertionError("owned registrations are not the expected set")
        if research["parentHash"] != identity["pathHash"] or research["admin"] is not False:
            raise AssertionError("research registration parent or admin bit is wrong")
        parents = {entry["parentHash"] for entry in entries}
        if parents != {identity["pathHash"]}:
            raise AssertionError("registrations are not parented to the current agent")
        service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
        spire_ip = service["spec"]["clusterIP"]
        audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
        before_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=150)
        if any(before_guest["grants"][ws]["http"] != 200 for ws in ("default", "research")):
            raise AssertionError("baseline grant failed")
        if not all(str(before_guest["providers"].get(ws, "")).strip() for ws in ("default", "research")):
            raise AssertionError("active providers were not recorded")
        access_exp = before_guest["grants"]["research"].get("exp")
        svid_exp = before_guest["svids"]["research"].get("exp")
        if not isinstance(access_exp, int) or not isinstance(svid_exp, int):
            raise AssertionError("baseline research expiries were not recorded")
        before = {**identity, "registrarReady": True, "paths": sorted(names),
                  "parentHash": research["parentHash"], "agentHash": identity["pathHash"],
                  "selectors": research["selectors"], "admin": False, "accessExp": access_exp,
                  "providers": before_guest["providers"]}
        report["before"] = _sanitize(before)
        _scale_registrar(oc, 0)
        scaled = True
        held_entries = _owned_entries(oc, vm_uid)
        if "research" not in _entry_names(held_entries, namespace, vm):
            raise AssertionError("research registration disappeared before the profile change")
        ops = [{"op": "remove", "path": "/data/" + key} for key in keys]
        command(oc + ["patch", "cm", "saw-bom-profiles", "-n", namespace, "--type", "json",
                      "-p", json.dumps(ops)], timeout=30)
        removed = True
        time.sleep(20)
        held_entries = _owned_entries(oc, vm_uid)
        held_identity = _identity_view(oc, namespace, vm)
        held = {**held_identity, "paths": sorted(_entry_names(held_entries, namespace, vm))}
        report["held"] = _sanitize(held)
        _scale_registrar(oc, 1)
        scaled = False
        removed_entries = _wait_research(oc, vm_uid, namespace, vm, present=False)
        removed_identity = _identity_view(oc, namespace, vm)
        removed_names = _entry_names(removed_entries, namespace, vm)
        removed_parents = {entry["parentHash"] for entry in removed_entries}
        removed_view = {**removed_identity, "paths": sorted(removed_names),
                        "parentHash": next(iter(removed_parents)) if removed_parents else ""}
        report["removed"] = _sanitize(removed_view)
        expiry_deadline = max(access_exp, svid_exp) + 5
        wait_until = time.time() + 420
        while True:
            epoch = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "epoch", timeout=20)
            if epoch["epoch"] > expiry_deadline:
                break
            if time.time() > wait_until:
                raise AssertionError("guest clock did not pass the research credential expiry")
            time.sleep(15)
        denied_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=150)
        research_svid = denied_guest["svids"]["research"]
        fresh_svid = isinstance(research_svid.get("exp"), int) and research_svid["exp"] > denied_guest["epoch"]
        denied = {"now": denied_guest["epoch"], "accessExp": access_exp,
                  "researchHttp": denied_guest["grants"]["research"]["http"],
                  "researchSvid": "ok" if fresh_svid else research_svid.get("error") or "expired",
                  "defaultHttp": denied_guest["grants"]["default"]["http"],
                  "grants": denied_guest["grants"], "svids": denied_guest["svids"]}
        report["denied"] = _sanitize(denied)
        _restore_profile_keys(oc, namespace, saved)
        restored_entries = _wait_research(oc, vm_uid, namespace, vm, present=True)
        removed = False
        restored_entry = _research_entry(restored_entries, namespace, vm)
        restored_identity = _identity_view(oc, namespace, vm)
        restored_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=150)
        restored = {**restored_identity, "paths": sorted(_entry_names(restored_entries, namespace, vm)),
                    "parentHash": restored_entry["parentHash"], "selectors": restored_entry["selectors"],
                    "admin": restored_entry["admin"], "researchHttp": restored_guest["grants"]["research"]["http"],
                    "accessExp": restored_guest["grants"]["research"].get("exp"),
                    "grants": restored_guest["grants"], "svids": restored_guest["svids"],
                    "providers": restored_guest["providers"]}
        report["restored"] = _sanitize(restored)
        result = profile_removal_result(before, held, removed_view, denied, restored)
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError) as error:
        body_error = error
        report["detail"] = str(error)[:500]
    finally:
        try:
            if scaled:
                _scale_registrar(oc, 1)
                scaled = False
            if removed and saved is not None:
                _restore_profile_keys(oc, namespace, saved)
                if vm_uid is None:
                    raise AssertionError("profile documents were restored without an entry check")
                _wait_research(oc, vm_uid, namespace, vm, present=True)
                removed = False
            report["faultRestored"] = not removed and not scaled
        except (AssertionError, subprocess.SubprocessError, KeyError, OSError) as error:
            report["faultRestored"] = False
            report["cleanupDetail"] = str(error)[:300]
    if body_error or report.get("faultRestored") is not True or result is None:
        report["status"] = "fail"
    else:
        report["result"] = result
        report["status"] = "pass"
    return report


def run_research_expiry_denial(args):
    """Repeat only the research post-expiry denial, including provider lists and curl diagnostics."""
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    namespace, vm = args.vm_namespace, args.vm
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
    trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
    service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
    spire_ip = service["spec"]["clusterIP"]
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", spire_ip):
        raise AssertionError("SPIRE Service address is not an IPv4 cluster IP")
    report = {"scenario": "research-expiry-denial", "executed": True, "acceptanceComplete": False,
              "status": "fail", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    fault = False
    body_error = None
    try:
        before_id = _identity_view(oc, namespace, vm)
        guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "research", timeout=120)
        grant_body = guest["grant"]
        svid_body = guest["svid"]
        if grant_body.get("http") != 200 or not isinstance(grant_body.get("exp"), int) or not isinstance(svid_body.get("exp"), int):
            raise AssertionError("baseline research grant was not successful")
        before = {**before_id, "providers": guest["providers"], "accessExp": grant_body["exp"],
                  "svidExp": svid_body["exp"], "credentialsPresent": guest["credentialsPresent"],
                  "http": grant_body["http"], "curlExit": grant_body.get("curlExit"),
                  "sub": grant_body.get("sub"), "aud": grant_body.get("aud"),
                  "azp": grant_body.get("azp"), "client_id": grant_body.get("client_id")}
        report["before"] = _sanitize(before)
        denied_fw = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "deny", timeout=30)
        if denied_fw.get("add") == 0:
            fault = True
        if denied_fw.get("add") != 0 or denied_fw.get("dial") == "ok":
            raise AssertionError("SPIRE connectivity was not denied")
        deadline = max(before["accessExp"], before["svidExp"]) + 5
        wait_until = time.time() + 420
        while True:
            current = _identity_view(oc, namespace, vm)
            if current["generation"] != before["generation"] or current["vmi"] != before["vmi"] or not current["registrarReady"]:
                raise AssertionError("enrollment changed while SPIRE connectivity was denied")
            epoch = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "epoch", timeout=20)
            if epoch["epoch"] > max(before["accessExp"], before["svidExp"]) and time.time() > deadline - 5:
                break
            if time.time() > wait_until:
                raise AssertionError("guest clock did not pass the research credential expiry")
            time.sleep(15)
        denied_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "research", timeout=120)
        denied_id = _identity_view(oc, namespace, vm)
        denied_grant = denied_guest["grant"]
        denied = {**denied_id, "now": denied_guest["epoch"], "credentialsPresent": denied_guest["credentialsPresent"],
                  "http": denied_grant.get("http"), "curlExit": denied_grant.get("curlExit"),
                  "diagnostic": denied_grant.get("diagnostic"), "error": denied_grant.get("error"),
                  "providers": denied_guest["providers"]}
        report["denied"] = _sanitize(denied)
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError) as error:
        body_error = error
        report["detail"] = str(error)[:500]
    finally:
        if fault:
            try:
                allowed = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "allow", timeout=30)
                report["allow"] = _sanitize(allowed)
                report["faultRestored"] = allowed.get("delete") == 0 and allowed.get("dial") == "ok"
            except (AssertionError, subprocess.SubprocessError, OSError):
                report["faultRestored"] = False
    if body_error or report.get("faultRestored") is not True:
        report["status"] = "fail"
        return report
    try:
        restored_guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "research", timeout=120)
        restored_id = _identity_view(oc, namespace, vm)
        restored_grant = restored_guest["grant"]
        restored = {**restored_id, "credentialsPresent": restored_guest["credentialsPresent"],
                    "providers": restored_guest["providers"], "http": restored_grant.get("http"),
                    "curlExit": restored_grant.get("curlExit"), "diagnostic": restored_grant.get("diagnostic"),
                    "accessExp": restored_grant.get("exp"), "svidExp": restored_guest["svid"].get("exp"),
                    "sub": restored_grant.get("sub"), "aud": restored_grant.get("aud"),
                    "azp": restored_grant.get("azp"), "client_id": restored_grant.get("client_id")}
        report["restored"] = _sanitize(restored)
        report["result"] = research_expiry_result(before, denied, restored)
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError) as error:
        report["status"] = "fail"
        report["detail"] = str(error)[:500]
    return report


def vm_recreate_result(before, removed, created, later):
    """A Helm reinstall must replace the VM UID, agent, and registrations without reusing them."""
    if before["vmUid"] == created["vmUid"]:
        raise AssertionError("recreated VM kept the old UID")
    if removed.get("agentBanned") is not True or removed.get("entryIds"):
        raise AssertionError("old agent was not invalidated or its registrations remained")
    if removed.get("peers") != before.get("peers"):
        raise AssertionError("another SAW changed while the dedicated VM was deleted")
    if created["agentHash"] == before["agentHash"] or created["parentHash"] != created["agentHash"]:
        raise AssertionError("replacement entries are not parented exclusively to the new agent")
    if created.get("agentPresent") is not True or created.get("agentBanned") is not False:
        raise AssertionError("fresh enrollment did not produce an unbanned agent")
    if created["generation"] != created["guestGeneration"] or created.get("guestState") != "present":
        raise AssertionError("guest enrollment does not match the registrar")
    if created["selectors"] != before["selectors"] or created.get("admin") is not False:
        raise AssertionError("selectors or admin bit changed")
    if created["paths"] != ["default", "gateway", "research"]:
        raise AssertionError("replacement registrations are not the expected set")
    for ws, peer in (("default", "research"), ("research", "default")):
        grant = created["grants"][ws]
        if grant.get("http") != 200 or grant.get("sub") != grant.get("azp") or grant.get("client_id") != grant.get("sub"):
            raise AssertionError("workspace grant did not use its sandbox identity")
        if grant.get("aud") != "saw-protected-service":
            raise AssertionError("workspace grant audience changed")
        own = created["isolation"][ws][ws]
        if own.get("ok") is not True or own.get("sub") != grant.get("sub"):
            raise AssertionError("sandbox could not fetch its own identity")
        for other in ("gateway", peer):
            row = created["isolation"][ws][other]
            if row.get("ok") is not False or not str(row.get("error") or "").strip():
                raise AssertionError("gateway or peer identity was not rejected")
    if not all(str((created.get("providers") or {}).get(ws, "")).strip() for ws in ("default", "research")):
        raise AssertionError("providers were not recorded after recreation")
    if later["entryIds"] != created["entryIds"] or later["vmUid"] != created["vmUid"] or later["generation"] != created["generation"]:
        raise AssertionError("registrations changed after additional reconciliation")
    if later.get("oldEntryIds") or later.get("oldAgentBanned") is not True or later.get("peers") != before.get("peers"):
        raise AssertionError("stale agent or registrations returned")
    return "fresh enrollment parented exclusively to the new agent"


def namespace_delete_result(before, held, gone):
    """Namespace deletion waits for the registrar, then removes that VM's agent and registrations."""
    if held.get("registrarReady") is not False or held.get("namespacePhase") != "Terminating":
        raise AssertionError("namespace deletion was not held during registrar downtime")
    if held.get("finalizer") is not True or held.get("entryIds") != before.get("entryIds"):
        raise AssertionError("registrations changed while the registrar was down")
    if gone.get("namespaceExists") is not False or gone.get("entryIds") or gone.get("agentBanned") is not True:
        raise AssertionError("namespace cleanup left the namespace, an active agent, or a registration")
    if gone.get("spireReady") is not True or gone.get("peers") != before.get("peers") or gone.get("otherVms") != before.get("otherVms"):
        raise AssertionError("shared SPIRE server or another SAW changed")
    return "namespace cleanup completed after the registrar returned"


def _agent_index(oc):
    agents = json.loads(command(oc + ["exec", "-n", NS, "spire-server-0", "-c", "spire-server", "--",
                                      "/spire-server", "agent", "list", "-output", "json"], timeout=40))
    index = {}
    for agent in agents.get("agents") or []:
        path = (agent.get("id") or {}).get("path") or ""
        if "/join_token/" not in path:
            continue
        index[hashlib.sha256(path.encode()).hexdigest()[:12]] = agent.get("banned") is True
    return index


def _entry_ids_present(oc, ids):
    raw = command(oc + ["exec", "-n", NS, "spire-server-0", "-c", "spire-server", "--",
                        "/spire-server", "entry", "show", "-output", "json"], timeout=60)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AssertionError("SPIRE entry list was not JSON") from error
    if data.get("next_page_token"):
        raise AssertionError("SPIRE entry list was truncated")
    wanted = set(ids)
    return sorted(entry.get("id") for entry in data.get("entries") or [] if entry.get("id") in wanted)


def _peer_agents(oc, namespace, vm):
    listed = json.loads(command(oc + ["get", "vm", "-A", "-l", "saw.redhat.com/spiffe=true", "-o", "json"], timeout=40))
    index = _agent_index(oc)
    peers = []
    for item in listed.get("items") or []:
        peer_ns = item["metadata"]["namespace"]
        peer_vm = item["metadata"]["name"]
        if peer_ns == namespace and peer_vm == vm:
            continue
        try:
            secret = json.loads(command(oc + ["get", "secret", "-n", peer_ns, peer_vm + "-spire-join-token", "-o", "json"], timeout=30))
        except subprocess.CalledProcessError:
            continue
        path = base64.b64decode(secret["data"]["node-path"]).decode()
        digest = hashlib.sha256(path.encode()).hexdigest()[:12]
        peers.append({"namespace": peer_ns, "vm": peer_vm, "pathHash": digest,
                      "present": digest in index, "banned": index.get(digest, False)})
    return _sanitize(sorted(peers, key=lambda item: (item["namespace"], item["vm"])))


def _helm(args, timeout=600):
    result = subprocess.run(["helm", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout or "helm failed")[-400:]
        if "eyJ" in detail or "/join_token/" in detail or "BEGIN " in detail:
            detail = "helm failed"
        raise AssertionError(detail)
    return result.stdout


def _blob(value):
    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            return value.encode()
    return value or b""


def _extract_release_chart(oc, namespace, release, dest):
    listed = json.loads(command(oc + ["get", "secret", "-n", namespace, "-l",
                                      "owner=helm,name=" + release, "-o", "json"], timeout=30))
    names = sorted(item["metadata"]["name"] for item in listed.get("items") or [])
    if not names:
        raise AssertionError("Helm release secret is absent")
    secret = json.loads(command(oc + ["get", "secret", "-n", namespace, names[-1], "-o", "json"], timeout=30))
    payload = gzip.decompress(base64.b64decode(base64.b64decode(secret["data"]["release"])))
    chart = json.loads(payload)["chart"]
    if dest.exists():
        import shutil
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    metadata = dict(chart.get("metadata") or {})
    metadata.pop("modtime", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(metadata, sort_keys=False))
    for item in (chart.get("templates") or []) + (chart.get("files") or []):
        path = dest / item["name"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_blob(item.get("data")))
    (dest / "values.yaml").write_text(yaml.safe_dump(chart.get("values") or {}))
    return dest


def _dedicated_vm(oc, namespace, vm):
    if namespace != "saw-identity-b" or vm != "identity-b":
        raise AssertionError("refusing to recreate anything except the dedicated test VM")
    vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
    labels = vm_obj["metadata"].get("labels") or {}
    annotations = vm_obj["metadata"].get("annotations") or {}
    if labels.get("saw.redhat.com/identity-test-run") != "agent-identity-fresh-20260927":
        raise AssertionError("refusing to recreate a VM that is not the dedicated test VM")
    if annotations.get("meta.helm.sh/release-name") != vm or annotations.get("meta.helm.sh/release-namespace") != namespace:
        raise AssertionError("VM is not owned by its Helm release")
    return vm_obj


def _selector_map(entries, namespace, vm):
    base = "/saw/%s/%s/" % (namespace, vm)
    found = {}
    for entry in entries:
        if entry["path"] == base + "gateway":
            found["gateway"] = entry["selectors"]
        elif entry["path"] == base + "ws/default/sandbox/agent":
            found["default"] = entry["selectors"]
        elif entry["path"] == base + "ws/research/sandbox/agent":
            found["research"] = entry["selectors"]
    return found


def run_vm_recreate(args):
    """Delete and recreate the dedicated VM through its Helm release."""
    namespace, vm = args.vm_namespace, args.vm
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    report = {"scenario": "vm-recreate", "executed": True, "acceptanceComplete": False,
              "status": "fail", "faultRestored": False,
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    uninstalled = False
    values_path = args.artifact_dir / "identity-b-helm-values.yaml"
    chart_dir = args.artifact_dir / "identity-b-chart"
    try:
        vm_obj = _dedicated_vm(oc, namespace, vm)
        trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
        identity = _identity_view(oc, namespace, vm)
        if identity["registrarReady"] is not True:
            raise AssertionError("registrar was not ready")
        entries = _owned_entries(oc, vm_obj["metadata"]["uid"])
        names = _entry_names(entries, namespace, vm)
        selectors = _selector_map(entries, namespace, vm)
        if names != {"gateway", "default", "research"} or set(selectors) != names:
            raise AssertionError("owned registrations are not the expected set")
        if any(entry["admin"] for entry in entries) or {entry["parentHash"] for entry in entries} != {identity["pathHash"]}:
            raise AssertionError("current registrations are not parented to the current agent")
        agent = _agent_index(oc).get(identity["pathHash"])
        if agent is not False:
            raise AssertionError("current agent is not an unbanned registration parent")
        before = {"vmUid": vm_obj["metadata"]["uid"], "vmi": identity["vmi"],
                  "generation": identity["generation"], "agentHash": identity["pathHash"],
                  "agentBanned": False, "entryIds": sorted(entry["id"] for entry in entries),
                  "selectors": selectors, "paths": ["default", "gateway", "research"],
                  "peers": _peer_agents(oc, namespace, vm)}
        report["before"] = _sanitize(before)
        (args.artifact_dir / "scenario-vm-recreate-before.json").write_text(json.dumps(report["before"], indent=2) + "\n")
        values = command(["helm", "get", "values", vm, "-n", namespace, "--kube-context", args.context,
                          "-a", "-o", "yaml"], timeout=60)
        values_path.write_text(values)
        values_path.chmod(0o600)
        _extract_release_chart(oc, namespace, vm, chart_dir)
        _helm(["uninstall", vm, "-n", namespace, "--kube-context", args.context, "--wait", "--timeout", "10m"], timeout=700)
        uninstalled = True
        removed_ids = _entry_ids_present(oc, before["entryIds"])
        removed_agent = _agent_index(oc)
        removed = {"entryIds": removed_ids, "agentBanned": removed_agent.get(before["agentHash"], False) is True
                   and before["agentHash"] in removed_agent,
                   "peers": _peer_agents(oc, namespace, vm)}
        report["removed"] = _sanitize(removed)
        for kind in ("dv", "pvc", "vmi"):
            command(oc + ["delete", kind, "-n", namespace, vm if kind == "vmi" else vm + "-root",
                          "--ignore-not-found", "--wait=true", "--timeout=180s"], timeout=200)
        leftover = subprocess.run(oc + ["get", "secret", "-n", namespace, vm + "-spire-join-token", "-o", "json"],
                                  capture_output=True, text=True, timeout=30)
        if leftover.returncode == 0:
            secret = json.loads(leftover.stdout)
            owners = [item.get("uid") for item in secret["metadata"].get("ownerReferences") or []]
            if not owners or before["vmUid"] in owners:
                command(oc + ["delete", "secret", "-n", namespace, vm + "-spire-join-token", "--wait=true"], timeout=60)
        _helm(["upgrade", "--install", vm, str(chart_dir), "-n", namespace, "--kube-context", args.context,
              "-f", str(values_path), "--timeout", "15m"], timeout=960)
        uninstalled = False
        deadline = time.time() + 900
        created_vm = None
        while time.time() < deadline:
            try:
                created_vm = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
                if created_vm["metadata"]["uid"] == before["vmUid"]:
                    created_vm = None
                    time.sleep(5)
                    continue
                vmi = json.loads(command(oc + ["get", "vmi", "-n", namespace, vm, "-o", "json"], timeout=30))
                if vmi.get("status", {}).get("phase") != "Running":
                    time.sleep(10)
                    continue
                service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
                guest = _guest_action(oc, namespace, vm, trust_domain, audience, service["spec"]["clusterIP"], "status", timeout=40)
                current = _identity_view(oc, namespace, vm)
                owned = _owned_entries(oc, created_vm["metadata"]["uid"])
                if guest.get("state") == "present" and guest.get("generation") == current["generation"] and len(owned) == 3:
                    break
            except (AssertionError, subprocess.CalledProcessError, KeyError, json.JSONDecodeError):
                created_vm = None
            time.sleep(10)
        else:
            raise AssertionError("recreated VM did not enroll")
        if created_vm is None:
            raise AssertionError("recreated VM did not enroll")
        current = _identity_view(oc, namespace, vm)
        owned = _owned_entries(oc, created_vm["metadata"]["uid"])
        service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
        spire_ip = service["spec"]["clusterIP"]
        guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=160)
        isolated = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "isolation", timeout=160)
        created = {"vmUid": created_vm["metadata"]["uid"], "vmi": current["vmi"],
                   "generation": current["generation"], "guestGeneration": guest["generation"],
                   "guestState": guest["state"], "agentHash": current["pathHash"],
                   "agentPresent": current["agentPresent"],
                   "agentBanned": _agent_index(oc).get(current["pathHash"]) is True,
                   "parentHash": next(iter(parents)) if len(parents := {entry["parentHash"] for entry in owned}) == 1 else "",
                   "entryIds": sorted(entry["id"] for entry in owned),
                   "selectors": _selector_map(owned, namespace, vm),
                   "paths": sorted(_entry_names(owned, namespace, vm)),
                   "admin": any(entry["admin"] for entry in owned),
                   "grants": guest["grants"], "providers": guest["providers"], "isolation": isolated,
                   "credentialsPresent": guest["credentialsPresent"]}
        report["created"] = _sanitize(created)
        time.sleep(45)
        later_vm = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
        later_id = _identity_view(oc, namespace, vm)
        later_owned = _owned_entries(oc, later_vm["metadata"]["uid"])
        later_agents = _agent_index(oc)
        later = {"vmUid": later_vm["metadata"]["uid"], "generation": later_id["generation"],
                 "entryIds": sorted(entry["id"] for entry in later_owned),
                 "oldEntryIds": _entry_ids_present(oc, before["entryIds"]),
                 "oldAgentBanned": later_agents.get(before["agentHash"]) is True and before["agentHash"] in later_agents,
                 "peers": _peer_agents(oc, namespace, vm)}
        report["later"] = _sanitize(later)
        report["result"] = vm_recreate_result(before, removed, created, later)
        report["faultRestored"] = True
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
        report["detail"] = str(error)[:500]
        report["status"] = "fail"
    finally:
        if uninstalled:
            try:
                _helm(["upgrade", "--install", vm, str(chart_dir), "-n", namespace, "--kube-context", args.context,
                      "-f", str(values_path), "--timeout", "15m"], timeout=960)
                report["faultRestored"] = True
            except (AssertionError, subprocess.SubprocessError, OSError):
                report["faultRestored"] = False
    return report


def run_vm_recreate_verify(args):
    """Finish recreation checks without deleting the VM again."""
    namespace, vm = args.vm_namespace, args.vm
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    report = {"scenario": "vm-recreate-verify", "executed": True, "acceptanceComplete": False,
              "status": "fail", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        before = json.loads((args.artifact_dir / "scenario-vm-recreate-before.json").read_text())
        report["before"] = _sanitize(before)
        vm_obj = _dedicated_vm(oc, namespace, vm)
        if vm_obj["metadata"]["uid"] == before["vmUid"]:
            raise AssertionError("verification is still looking at the old VM")
        trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
        agents = _agent_index(oc)
        removed = {"entryIds": _entry_ids_present(oc, before["entryIds"]),
                   "agentBanned": agents.get(before["agentHash"]) is True and before["agentHash"] in agents,
                   "peers": _peer_agents(oc, namespace, vm)}
        report["removed"] = _sanitize(removed)
        service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
        spire_ip = service["spec"]["clusterIP"]
        deadline = time.time() + 480
        guest = None
        while time.time() < deadline:
            guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=160)
            grants = guest.get("grants") or {}
            if all(grants.get(ws, {}).get("http") == 200 for ws in ("default", "research")):
                if all(isinstance((guest.get("svids") or {}).get(ws, {}).get("exp"), int) for ws in ("default", "research")):
                    break
            time.sleep(15)
        else:
            raise AssertionError("recreated sandboxes did not grant")
        isolated = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "isolation", timeout=160)
        current = _identity_view(oc, namespace, vm)
        owned = _owned_entries(oc, vm_obj["metadata"]["uid"])
        parents = {entry["parentHash"] for entry in owned}
        created = {"vmUid": vm_obj["metadata"]["uid"], "vmi": current["vmi"],
                   "generation": current["generation"], "guestGeneration": guest["generation"],
                   "guestState": guest["state"], "agentHash": current["pathHash"],
                   "agentPresent": current["agentPresent"],
                   "agentBanned": _agent_index(oc).get(current["pathHash"]) is True,
                   "parentHash": next(iter(parents)) if len(parents) == 1 else "",
                   "entryIds": sorted(entry["id"] for entry in owned),
                   "selectors": _selector_map(owned, namespace, vm),
                   "paths": sorted(_entry_names(owned, namespace, vm)),
                   "admin": any(entry["admin"] for entry in owned),
                   "grants": guest["grants"], "providers": guest["providers"], "isolation": isolated,
                   "credentialsPresent": guest["credentialsPresent"]}
        report["created"] = _sanitize(created)
        time.sleep(45)
        later_id = _identity_view(oc, namespace, vm)
        later_owned = _owned_entries(oc, vm_obj["metadata"]["uid"])
        later_agents = _agent_index(oc)
        later = {"vmUid": vm_obj["metadata"]["uid"], "generation": later_id["generation"],
                 "entryIds": sorted(entry["id"] for entry in later_owned),
                 "oldEntryIds": _entry_ids_present(oc, before["entryIds"]),
                 "oldAgentBanned": later_agents.get(before["agentHash"]) is True and before["agentHash"] in later_agents,
                 "peers": _peer_agents(oc, namespace, vm)}
        report["later"] = _sanitize(later)
        report["result"] = vm_recreate_result(before, removed, created, later)
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
        report["detail"] = str(error)[:500]
        report["status"] = "fail"
    return report


def _namespace_phase(oc, namespace):
    result = subprocess.run(oc + ["get", "namespace", namespace, "-o", "json"], capture_output=True, text=True, timeout=30)
    if result.returncode:
        if "NotFound" in result.stderr:
            return None
        raise AssertionError("namespace lookup failed")
    return json.loads(result.stdout)


def run_namespace_delete(args):
    """Delete the dedicated namespace while the registrar is down, then let it clean up."""
    namespace, vm = args.vm_namespace, args.vm
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    report = {"scenario": "namespace-delete", "executed": True, "acceptanceComplete": False,
              "status": "fail", "faultRestored": False,
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    scaled = False
    try:
        vm_obj = _dedicated_vm(oc, namespace, vm)
        identity = _identity_view(oc, namespace, vm)
        entries = _owned_entries(oc, vm_obj["metadata"]["uid"])
        other_vms = [{"namespace": item["metadata"]["namespace"], "vm": item["metadata"]["name"],
                      "uid": item["metadata"]["uid"]}
                     for item in json.loads(command(oc + ["get", "vm", "-A", "-o", "json"], timeout=40)).get("items") or []
                     if item["metadata"]["namespace"] != namespace]
        before = {"vmUid": vm_obj["metadata"]["uid"], "agentHash": identity["pathHash"],
                  "entryIds": sorted(entry["id"] for entry in entries),
                  "peers": _peer_agents(oc, namespace, vm),
                  "selectors": _selector_map(entries, namespace, vm),
                  "otherVms": sorted(other_vms, key=lambda item: (item["namespace"], item["vm"]))}
        report["before"] = _sanitize(before)
        preserved = args.artifact_dir / "scenario-namespace-delete-before.json"
        preserved.write_text(json.dumps(report["before"], indent=2) + "\n")
        if not preserved.is_file():
            raise AssertionError("evidence was not preserved outside the namespace")
        server = json.loads(command(oc + ["get", "pod", "-n", NS, "spire-server-0", "-o", "json"], timeout=30))
        if not server["status"]["containerStatuses"][0]["ready"]:
            raise AssertionError("SPIRE server is not ready")
        _scale_registrar(oc, 0)
        scaled = True
        command(oc + ["delete", "namespace", namespace, "--wait=false"], timeout=60)
        deadline = time.time() + 90
        held_ns = None
        while time.time() < deadline:
            held_ns = _namespace_phase(oc, namespace)
            if held_ns and held_ns["status"].get("phase") == "Terminating":
                break
            time.sleep(3)
        if not held_ns or held_ns["status"].get("phase") != "Terminating":
            raise AssertionError("namespace did not stay terminating while the registrar was down")
        held_vm = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
        held = {"registrarReady": False, "namespacePhase": "Terminating",
                "finalizer": "saw.redhat.com/spire-registration" in (held_vm["metadata"].get("finalizers") or []),
                "entryIds": _entry_ids_present(oc, before["entryIds"])}
        report["held"] = _sanitize(held)
        _scale_registrar(oc, 1)
        scaled = False
        deadline = time.time() + 300
        while time.time() < deadline:
            if _namespace_phase(oc, namespace) is None:
                break
            time.sleep(5)
        else:
            raise AssertionError("namespace cleanup did not finish after the registrar returned")
        agents = _agent_index(oc)
        server = json.loads(command(oc + ["get", "pod", "-n", NS, "spire-server-0", "-o", "json"], timeout=30))
        gone = {"namespaceExists": _namespace_phase(oc, namespace) is not None,
                "entryIds": _entry_ids_present(oc, before["entryIds"]),
                "agentBanned": agents.get(before["agentHash"]) is True and before["agentHash"] in agents,
                "spireReady": server["status"]["containerStatuses"][0]["ready"] is True,
                "peers": _peer_agents(oc, namespace, vm),
                "otherVms": sorted(({"namespace": item["metadata"]["namespace"], "vm": item["metadata"]["name"],
                                     "uid": item["metadata"]["uid"]}
                                    for item in json.loads(command(oc + ["get", "vm", "-A", "-o", "json"], timeout=40)).get("items") or []
                                    if item["metadata"]["namespace"] != namespace),
                                   key=lambda item: (item["namespace"], item["vm"]))}
        report["gone"] = _sanitize(gone)
        report["result"] = namespace_delete_result(before, held, gone)
        report["faultRestored"] = True
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
        report["detail"] = str(error)[:500]
        report["status"] = "fail"
    finally:
        if scaled:
            try:
                _scale_registrar(oc, 1)
                report["faultRestored"] = True
            except (AssertionError, subprocess.SubprocessError, OSError):
                report["faultRestored"] = False
    return report


def cross_vm_result(left, right):
    """Repeated workspace names stay on their own VM and are rejected across VMs."""
    if left["vmUid"] == right["vmUid"] or left["agentHash"] == right["agentHash"]:
        raise AssertionError("the two VMs are not distinct enrollments")
    if left["selectors"] != right["selectors"]:
        raise AssertionError("repeated workspace selectors differ")
    for side in (left, right):
        peer = right if side is left else left
        if side.get("admin") is not False or side["paths"] != ["default", "gateway", "research"]:
            raise AssertionError("registrations are not the expected non-admin set")
        if side["parentHash"] != side["agentHash"] or side.get("agentPresent") is not True:
            raise AssertionError("registrations are not parented to the local agent")
        if side["generation"] != side["guestGeneration"] or side.get("guestState") != "present":
            raise AssertionError("guest enrollment does not match the registrar")
        attest = side["attest"]
        if attest.get("enforce") != "Enforcing" or attest.get("agentPermissive") is not False:
            raise AssertionError("agent domain is not enforcing")
        if not attest.get("contexts") or any("saw_spire_agent_t" not in ctx for ctx in attest["contexts"]):
            raise AssertionError("agent process is not saw_spire_agent_t")
        unix = attest.get("unix") or {}
        if unix.get("discover_workload_path") is not True or unix.get("workload_size_limit") != -1:
            raise AssertionError("unix attestor is not configured for path discovery")
        if attest.get("journalRc") != 0 or attest.get("attestorErrors"):
            raise AssertionError("attestor diagnostics were missing or not clean")
        if not all(str((side.get("providers") or {}).get(ws, "")).strip() for ws in ("default", "research")):
            raise AssertionError("providers were not recorded")
        for ws, other in (("default", "research"), ("research", "default")):
            grant = side["grants"][ws]
            expected = "spiffe://%s/saw/%s/%s/ws/%s/sandbox/agent" % (
                side["trustDomain"], side["namespace"], side["vm"], ws)
            if grant.get("http") != 200 or grant.get("sub") != expected or grant.get("azp") != expected or grant.get("client_id") != expected:
                raise AssertionError("grant claim is not the sandbox identity")
            if grant.get("aud") != "saw-protected-service":
                raise AssertionError("grant audience changed")
            own = side["isolation"][ws][ws]
            if own.get("ok") is not True or own.get("sub") != expected:
                raise AssertionError("sandbox could not fetch its own identity")
            for name in ("gateway", other):
                row = side["isolation"][ws][name]
                if row.get("ok") is not False or "PermissionDenied" not in str(row.get("error") or ""):
                    raise AssertionError("gateway or peer workspace identity was not rejected")
            for name in ("gateway", "default", "research"):
                row = side["cross"][ws][name]
                expected_peer = "spiffe://%s/saw/%s/%s" % (peer["trustDomain"], peer["namespace"], peer["vm"])
                if expected_peer not in str(row.get("error") or "") and row.get("ok") is not False:
                    raise AssertionError("cross-VM identity was not rejected")
                if row.get("ok") is not False or "PermissionDenied" not in str(row.get("error") or ""):
                    raise AssertionError("cross-VM identity was not rejected")
    return "own identities succeed and cross-VM identities are rejected"


def _vm_side(oc, namespace, vm, trust_domain, audience, spire_ip, peer):
    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
            vmi = json.loads(command(oc + ["get", "vmi", "-n", namespace, vm, "-o", "json"], timeout=30))
            if vmi.get("status", {}).get("phase") != "Running":
                time.sleep(10)
                continue
            status = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "status", timeout=40)
            current = _identity_view(oc, namespace, vm)
            owned = _owned_entries(oc, vm_obj["metadata"]["uid"])
            if status.get("state") != "present" or status.get("generation") != current["generation"] or len(owned) != 3:
                time.sleep(15)
                continue
            guest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "snapshot", timeout=160)
            if not all(guest["grants"][ws].get("http") == 200 for ws in ("default", "research")):
                time.sleep(15)
                continue
            parents = {entry["parentHash"] for entry in owned}
            attest = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "attest", timeout=40)
            isolated = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "isolation", timeout=160)
            cross = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "cross", timeout=160,
                                  peer_ns=namespace, peer_vm=peer)
            return {"vm": vm, "namespace": namespace, "trustDomain": trust_domain,
                    "vmUid": vm_obj["metadata"]["uid"], "vmi": current["vmi"],
                    "generation": current["generation"], "guestGeneration": guest["generation"],
                    "guestState": guest["state"], "agentHash": current["pathHash"],
                    "agentPresent": current["agentPresent"],
                    "parentHash": next(iter(parents)) if len(parents) == 1 else "",
                    "selectors": _selector_map(owned, namespace, vm),
                    "paths": sorted(_entry_names(owned, namespace, vm)),
                    "admin": any(entry["admin"] for entry in owned),
                    "grants": guest["grants"], "providers": guest["providers"],
                    "isolation": isolated, "cross": cross, "attest": attest}
        except (AssertionError, subprocess.CalledProcessError, KeyError, json.JSONDecodeError):
            time.sleep(15)
    raise AssertionError(vm + " did not become ready for cross-VM checks")


def upgrade_idempotent_result(before, after):
    """A second Helm upgrade must not replace the enrollment."""
    for key in ("vmUid", "vmi", "generation", "agentHash", "entryIds"):
        if before.get(key) != after.get(key):
            raise AssertionError("upgrade changed " + key)
    if after.get("helmRevision") != before.get("helmRevision", 0) + 1:
        raise AssertionError("upgrade did not create exactly one release revision")
    if after.get("agentPresent") is not True or after.get("guestState") != "present":
        raise AssertionError("enrollment was not preserved")
    if after.get("recoveryAttempts"):
        raise AssertionError("upgrade triggered recovery")
    return "helm upgrade preserved the enrollment"


def disabled_mode_result(before, after):
    """Opting out stops guest identity services and revokes registrations."""
    if before.get("optedIn") is not True or before.get("agentPresent") is not True:
        raise AssertionError("identity was not active before disable")
    if before.get("guestState") != "present" or len(before.get("entryIds") or []) != 3:
        raise AssertionError("identity was not enrolled before disable")
    if after.get("vmUid") != before.get("vmUid"):
        raise AssertionError("disable replaced the VM")
    if after.get("optedIn") is not False:
        raise AssertionError("VM is still opted into identity")
    if after.get("entryIds"):
        raise AssertionError("registrations were not removed")
    if after.get("agentBanned") is not True:
        raise AssertionError("agent was not revoked")
    if after.get("agentUnit") is not False or after.get("agentActive") is not False:
        raise AssertionError("guest identity service is still installed")
    if after.get("vmReady") is not True:
        raise AssertionError("VM did not return Ready")
    if after.get("recoveryAttempts"):
        raise AssertionError("disable started a recovery bootstrap")
    return "identity services stopped and registrations revoked"


def networkpolicy_result(before, denied, restored, scope):
    """Guest TCP to SPIRE must follow a policy on the dedicated launchers only."""
    if set(before) != set(denied) or set(before) != set(restored) or len(before) < 2:
        raise AssertionError("both dedicated VMs were not measured")
    if any(value != "ok" for value in before.values()):
        raise AssertionError("guest could not reach SPIRE before the policy")
    if any(value == "ok" for value in denied.values()):
        raise AssertionError("NetworkPolicy did not stop guest traffic")
    if any(value != "ok" for value in restored.values()):
        raise AssertionError("guest traffic did not recover after policy removal")
    if scope.get("policyPresent") is not False:
        raise AssertionError("test NetworkPolicy was left in place")
    if scope.get("spireReady") is not True:
        raise AssertionError("SPIRE server was not ready after the policy test")
    if scope.get("policiesBefore") != scope.get("policiesAfter"):
        raise AssertionError("NetworkPolicy inventory changed")
    if scope.get("vmUids") != scope.get("vmUidsAfter"):
        raise AssertionError("a VM UID changed during the policy test")
    return "guest TCP to SPIRE follows the dedicated namespace NetworkPolicy"


DENY_EGRESS_POLICY = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: saw-identity-cross-deny-egress
  labels:
    saw.redhat.com/identity-test-run: agent-identity-cross-20261004
spec:
  podSelector:
    matchLabels:
      kubevirt.io: virt-launcher
  policyTypes:
    - Egress
  egress: []
"""


def _policy_index(oc):
    listed = json.loads(command(oc + ["get", "networkpolicy", "-A", "-o", "json"], timeout=40))
    return sorted((item["metadata"]["namespace"], item["metadata"]["name"])
                  for item in listed.get("items") or [])


def _vm_uids(oc):
    listed = json.loads(command(oc + ["get", "vm", "-A", "-o", "json"], timeout=40))
    return sorted((item["metadata"]["namespace"], item["metadata"]["name"], item["metadata"]["uid"])
                  for item in listed.get("items") or [])


def _dial_guests(oc, namespace, vms, trust_domain, audience, spire_ip):
    return {vm: _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "dial", timeout=30)["dial"]
            for vm in vms}


def run_networkpolicy(args):
    """Deny virt-launcher egress in the dedicated namespace and restore it."""
    namespace, left, right = args.vm_namespace, args.vm, args.peer_vm
    if namespace != "saw-identity-c" or left != "identity-c" or right != "identity-d":
        raise AssertionError("refusing to apply a NetworkPolicy outside the dedicated cross-VM namespace")
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    policy = "saw-identity-cross-deny-egress"
    report = {"scenario": "networkpolicy", "executed": True, "acceptanceComplete": False,
              "status": "fail", "faultRestored": False,
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    applied = False
    try:
        ns = json.loads(command(oc + ["get", "namespace", namespace, "-o", "json"], timeout=30))
        if (ns["metadata"].get("labels") or {}).get("saw.redhat.com/identity-test-run") != "agent-identity-cross-20261004":
            raise AssertionError("namespace is not the dedicated cross-VM run")
        for vm in (left, right):
            vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
            if (vm_obj["metadata"].get("labels") or {}).get("saw.redhat.com/identity-test-run") != "agent-identity-cross-20261004":
                raise AssertionError("VM is not one of the dedicated cross-VM instances")
        trust_domain = json.loads(command(oc + ["get", "vm", "-n", namespace, left, "-o", "json"], timeout=30))["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
        spire_ip = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))["spec"]["clusterIP"]
        before_policies = _policy_index(oc)
        if (namespace, policy) in before_policies:
            raise AssertionError("a test NetworkPolicy is already present")
        vm_uids = _vm_uids(oc)
        before = _dial_guests(oc, namespace, (left, right), trust_domain, audience, spire_ip)
        report["before"] = before
        if any(value != "ok" for value in before.values()):
            raise AssertionError("guest could not reach SPIRE before the policy")
        command(oc + ["apply", "-n", namespace, "-f", "-"], stdin=DENY_EGRESS_POLICY, timeout=30)
        applied = True
        live = json.loads(command(oc + ["get", "networkpolicy", "-n", namespace, policy, "-o", "json"], timeout=30))
        if live["spec"].get("policyTypes") != ["Egress"] or live["spec"].get("podSelector", {}).get("matchLabels") != {"kubevirt.io": "virt-launcher"}:
            raise AssertionError("applied NetworkPolicy does not select virt-launcher egress")
        if (namespace, policy) not in _policy_index(oc) or set(_policy_index(oc)) - set(before_policies) != {(namespace, policy)}:
            raise AssertionError("NetworkPolicy apply changed more than the dedicated namespace")
        deadline = time.time() + 90
        denied = _dial_guests(oc, namespace, (left, right), trust_domain, audience, spire_ip)
        while time.time() < deadline and any(value == "ok" for value in denied.values()):
            time.sleep(3)
            denied = _dial_guests(oc, namespace, (left, right), trust_domain, audience, spire_ip)
        report["denied"] = denied
        command(oc + ["delete", "networkpolicy", "-n", namespace, policy, "--ignore-not-found", "--wait=true"], timeout=60)
        applied = False
        deadline = time.time() + 90
        restored = _dial_guests(oc, namespace, (left, right), trust_domain, audience, spire_ip)
        while time.time() < deadline and any(value != "ok" for value in restored.values()):
            time.sleep(3)
            restored = _dial_guests(oc, namespace, (left, right), trust_domain, audience, spire_ip)
        report["restored"] = restored
        server = json.loads(command(oc + ["get", "pod", "-n", NS, "spire-server-0", "-o", "json"], timeout=30))
        scope = {"policyPresent": (namespace, policy) in _policy_index(oc),
                 "spireReady": server["status"]["containerStatuses"][0]["ready"] is True,
                 "policiesBefore": before_policies, "policiesAfter": _policy_index(oc),
                 "vmUids": vm_uids, "vmUidsAfter": _vm_uids(oc)}
        report["scope"] = {"policyPresent": scope["policyPresent"], "spireReady": scope["spireReady"],
                           "policiesUnchanged": scope["policiesBefore"] == scope["policiesAfter"],
                           "vmUidsUnchanged": scope["vmUids"] == scope["vmUidsAfter"]}
        report["result"] = networkpolicy_result(before, denied, restored, scope)
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
        report["detail"] = str(error)[:500]
        report["status"] = "fail"
    finally:
        try:
            command(oc + ["delete", "networkpolicy", "-n", namespace, policy, "--ignore-not-found", "--wait=true"], timeout=60)
            report["faultRestored"] = (namespace, policy) not in _policy_index(oc)
        except (AssertionError, subprocess.SubprocessError, OSError):
            report["faultRestored"] = False
    return report


def run_cross_vm_isolation(args):
    """Exercise repeated workspace names on two dedicated VMs."""
    namespace = args.vm_namespace
    left_vm, right_vm = args.vm, args.peer_vm
    if namespace in ("saw-identity-a", "saw-alice") or left_vm in ("identity-a", "alice") or right_vm in ("identity-a", "alice"):
        raise AssertionError("refusing to use a diagnostic or shared VM as the acceptance baseline")
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    report = {"scenario": "cross-vm-isolation", "executed": True, "acceptanceComplete": False,
              "status": "fail", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
        spire_ip = service["spec"]["clusterIP"]
        sides = {}
        for vm, peer in ((left_vm, right_vm), (right_vm, left_vm)):
            vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
            trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
            label = (vm_obj["metadata"].get("labels") or {}).get("saw.redhat.com/identity-test-run")
            if label != "agent-identity-cross-20261004":
                raise AssertionError("VM is not one of the dedicated cross-VM instances")
            sides[vm] = _vm_side(oc, namespace, vm, trust_domain, audience, spire_ip, peer)
            report[vm] = _sanitize(sides[vm])
        report["result"] = cross_vm_result(sides[left_vm], sides[right_vm])
        report["status"] = "pass"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
        report["detail"] = str(error)[:500]
        report["status"] = "fail"
    return report


def supervisor_identity_result(paths, probes, workload_sockets):
    """Require registered identities and a private supervisor socket."""
    if "gateway" not in paths or "default" not in paths:
        raise AssertionError("gateway and default sandbox registrations are required")
    for ws in ("default", "research"):
        if ws not in paths:
            continue
        own = probes[ws][ws]
        if own.get("ok") is not True or not own.get("sub", "").endswith("/ws/%s/sandbox/agent" % ws):
            raise AssertionError(ws + " supervisor did not receive its own identity")
        if workload_sockets[ws].get("hidden") is not True:
            raise AssertionError(ws + " workload can access the Workload API socket")
        wrong = ["gateway"] + (["research" if ws == "default" else "default"] if "research" in paths else [])
        for name in wrong:
            row = probes[ws][name]
            if row.get("ok") is not False or row.get("denied") is not True:
                raise AssertionError(ws + " supervisor was not denied " + name + " identity")
    if "research" in paths:
        return "supervisor own identities succeed; gateway and peer identities are rejected"
    return "default supervisor identity succeeds; gateway identity is rejected"


def run_supervisor_identity(args):
    """Probe SPIRE from the supervisor container, never the workload container."""
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    namespace, vm = args.vm_namespace, args.vm
    audience = "http://identity-demo.saw-identity-demo.svc.cluster.local:8080"
    report = {"scenario": "supervisor-identity", "executed": True,
              "acceptanceComplete": False, "status": "fail",
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        vm_obj = json.loads(command(oc + ["get", "vm", "-n", namespace, vm, "-o", "json"], timeout=30))
        if (vm_obj["metadata"].get("labels") or {}).get("saw.redhat.com/spiffe") != "true":
            raise AssertionError("VM is not opted into SPIFFE")
        trust_domain = vm_obj["metadata"]["annotations"]["saw.redhat.com/trust-domain"]
        service = json.loads(command(oc + ["get", "svc", "-n", NS, "spire-server", "-o", "json"], timeout=30))
        spire_ip = service["spec"]["clusterIP"]
        registration = _identity_view(oc, namespace, vm)
        owned = _owned_entries(oc, vm_obj["metadata"]["uid"])
        paths = sorted(_entry_names(owned, namespace, vm))
        if not registration["agentPresent"] or {"gateway", "default"} - set(paths):
            raise AssertionError("active agent and gateway/default registrations are required")
        if len(owned) != len(paths) or "other" in paths or any(entry["admin"] for entry in owned):
            raise AssertionError("unexpected, duplicate, or admin registration")
        if {entry["parentHash"] for entry in owned} != {registration["pathHash"]}:
            raise AssertionError("registrations are not parented to the attested agent")
        selectors = _selector_map(owned, namespace, vm)
        if set(selectors.get("gateway") or []) != {
            "unix:uid:1000", "unix:path:/usr/local/bin/openshell-gateway"}:
            raise AssertionError("gateway selectors changed")
        for ws in ("default", "research"):
            if ws in paths and set(selectors.get(ws) or []) != {
                "docker:label:openshell.managed:true",
                "docker:label:openshell.ai/sandbox-workspace:" + ws,
                "docker:label:openshell.ai/sandbox-name:agent"}:
                raise AssertionError(ws + " sandbox selectors changed")
        probes = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip, "isolation", timeout=160)
        sockets = _guest_action(oc, namespace, vm, trust_domain, audience, spire_ip,
                                "workload-sockets", timeout=50)
        report.update({"vmUid": vm_obj["metadata"]["uid"], "generation": registration["generation"],
                       "agentHash": registration["pathHash"], "registeredPaths": paths,
                       "parentHash": owned[0]["parentHash"], "selectors": selectors,
                       "probes": _sanitize(probes), "workloadSockets": _sanitize(sockets)})
        report["result"] = supervisor_identity_result(paths, probes, sockets)
        if "research" in paths:
            report["status"] = "pass"
            report["acceptanceComplete"] = True
        else:
            report["status"] = "blocked"
            report["detail"] = "gateway rejection passed; a registered research sandbox is required for peer rejection"
    except (AssertionError, KeyError, TypeError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
        report["detail"] = str(error)[:500]
        report["status"] = "fail"
    return report


def execute_scenario(args):
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    runners = {"vm-spire-deny-expiry": run_vm_spire_deny_expiry,
               "supervisor-identity": run_supervisor_identity,
               "spire-server-outage": run_spire_server_outage,
               "profile-remove-restore": run_profile_remove_restore,
               "research-expiry-denial": run_research_expiry_denial,
               "vm-recreate": run_vm_recreate,
               "vm-recreate-verify": run_vm_recreate_verify,
               "namespace-delete": run_namespace_delete,
               "cross-vm-isolation": run_cross_vm_isolation,
               "networkpolicy": run_networkpolicy}
    try:
        report = runners[args.scenario](args)
    except (AssertionError, OSError, subprocess.SubprocessError, KeyError, ValueError) as error:
        report = {"scenario": args.scenario, "executed": True, "status": "fail",
                  "acceptanceComplete": False, "faultRestored": False,
                  "detail": str(error)[:500]}
    if "eyJ" in json.dumps(report) or "/join_token/" in json.dumps(report):
        report = {"scenario": args.scenario, "status": "fail", "detail": "evidence contained a credential and was omitted"}
    path = args.artifact_dir / ("scenario-" + args.scenario + ".json")
    path.write_text(json.dumps(report, indent=2) + "\n")
    print("%s: %s" % (report.get("status", "fail").upper(), path))
    return {"pass": 0, "blocked": 2}.get(report.get("status"), 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace-prefix", required=True)
    parser.add_argument("--transport", required=True, choices=("tcp",))
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--scenario", choices=("supervisor-identity", "vm-spire-deny-expiry", "spire-server-outage", "profile-remove-restore",
                                              "research-expiry-denial", "vm-recreate", "vm-recreate-verify",
                                              "namespace-delete", "cross-vm-isolation", "networkpolicy"))
    parser.add_argument("--vm-namespace")
    parser.add_argument("--vm")
    parser.add_argument("--peer-vm")
    args = parser.parse_args()
    if not args.context.strip() or not args.namespace_prefix.strip():
        parser.error("--context and --namespace-prefix must not be empty")
    if args.scenario:
        if not args.vm_namespace or not args.vm:
            parser.error("--scenario requires --vm-namespace and --vm")
        if args.scenario in ("cross-vm-isolation", "networkpolicy") and not args.peer_vm:
            parser.error("--scenario %s requires --peer-vm" % args.scenario)
        raise SystemExit(execute_scenario(args))
    raise SystemExit(run(args))
