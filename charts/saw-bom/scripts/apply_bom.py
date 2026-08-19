#!/usr/bin/env python3
"""
apply_bom.py — BOM-driven agent configuration for SAW.

Single entry point for provisioning an OpenShell Secure Agent Workspace.
Reads BOM profile directories, sets up the gateway, installs CLIs as needed,
creates workspaces, providers, and sandboxes.

Runs INSIDE the gateway VM.

Usage:
    python3 apply_bom.py --profiles-dir /path/to/profiles \
        --oidc-gateway openshell --mtls-gateway openshell-local
"""

import argparse
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Provider:
    name: str
    type: str
    enabled: bool = True
    nemoclaw_provider: str = ""
    credential_secret: str = ""
    credential_secret_key: str = "api_key"
    model: str = ""


@dataclass
class Sandbox:
    name: str
    type: str = "generic"       # nemoclaw, openclaw, generic
    enabled: bool = True
    agent: str = "openclaw"     # openclaw, hermes
    image: str = ""
    providers: list = field(default_factory=list)
    model: str = ""
    # GPU passthrough request for this sandbox (container-level `--gpu` on
    # `openshell sandbox create`). Independent of the gateway VM's own
    # vm.gpu.enabled (KubeVirt hostDevices, node->VM hop) — this only controls
    # whether *this* sandbox's container asks the driver for GPU resources.
    # See docs/gpu-passthrough.md.
    gpu_enabled: bool = False
    gpu_count: int = 1


@dataclass
class Workspace:
    name: str
    enabled: bool = True
    description: str = ""
    providers: list = field(default_factory=list)
    sandboxes: list = field(default_factory=list)


@dataclass
class Profile:
    name: str
    workspaces: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shell runner
# ---------------------------------------------------------------------------

class Shell:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run

    def run(self, cmd, env=None, check=True):
        display = re.sub(
            r'(--credential\s+\S+=)\S+',
            r'\1***',
            " ".join(cmd))
        display = re.sub(
            r'(API_KEY=|api_key=|TOKEN=|token=)\S+',
            r'\1***',
            display)
        # openclaw's own "config set gateway.auth.token '<value>'" call style has
        # no '=' at all, so the regex above never touches it — this leaked the
        # raw gateway auth token to Job logs in plaintext. Catch it explicitly.
        display = re.sub(
            r"(gateway\.auth\.token\s+')[^']+(')",
            r'\1***\2',
            display)
        if self.dry_run:
            log(f"[dry-run] {display}")
            return 0, "", ""
        log(f"$ {display}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                env={**os.environ, **(env or {})}, check=False
            )
        except FileNotFoundError:
            log(f"  WARN: command not found: {cmd[0]}")
            return 1, "", f"{cmd[0]}: not found"
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if stdout:
            for line in stdout.split("\n"):
                log(f"  {line}")
        if result.returncode != 0:
            if "already exists" in (stdout + stderr):
                log("  (already exists)")
                return 0, stdout, stderr
            if stderr:
                log(f"  WARN: {stderr[:300]}")
        return result.returncode, stdout, stderr


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg, indent=0):
    prefix = "  " * indent
    print(f"{prefix}{msg}", flush=True)


def banner(title):
    log(f"\n{'=' * 60}")
    log(title)
    log(f"{'=' * 60}")


def section(title):
    log(f"\n  [{title}]")


# ---------------------------------------------------------------------------
# Profile parser
# ---------------------------------------------------------------------------

def load_yaml_file(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_profiles(profiles_dir):
    profiles = []
    for profile_entry in sorted(Path(profiles_dir).iterdir()):
        if not profile_entry.is_dir():
            continue
        profile = Profile(name=profile_entry.name)
        for ws_entry in sorted(profile_entry.iterdir()):
            if not ws_entry.is_dir():
                continue
            ws_file = ws_entry / "workspace.yaml"
            if not ws_file.exists():
                log(f"WARN: {ws_entry} missing workspace.yaml, skipping")
                continue
            ws_data = load_yaml_file(ws_file)
            ws_meta = ws_data.get("metadata", {})
            ws = Workspace(
                name=ws_meta.get("name", ws_entry.name),
                enabled=ws_data.get("spec", {}).get("enabled", True),
                description=ws_meta.get("description", ""),
            )
            prov_file = ws_entry / "providers.yaml"
            if prov_file.exists():
                prov_data = load_yaml_file(prov_file)
                for p in prov_data.get("spec", {}).get("providers", []):
                    ws.providers.append(Provider(
                        name=p["name"],
                        type=p["type"],
                        enabled=p.get("enabled", True),
                        nemoclaw_provider=p.get("nemoclawProvider", ""),
                        credential_secret=p.get("credentialSecret", ""),
                        credential_secret_key=p.get("credentialSecretKey", "api_key"),
                        model=p.get("model", ""),
                    ))
            sb_file = ws_entry / "sandbox.yaml"
            if sb_file.exists():
                sb_data = load_yaml_file(sb_file)
                for s in sb_data.get("spec", {}).get("sandboxes", []):
                    gpu = s.get("gpu", {}) or {}
                    ws.sandboxes.append(Sandbox(
                        name=s["name"],
                        type=s.get("type", "generic"),
                        enabled=s.get("enabled", True),
                        agent=s.get("agent", "openclaw"),
                        image=s.get("image", ""),
                        providers=s.get("providers", []),
                        model=s.get("model", ""),
                        gpu_enabled=gpu.get("enabled", False),
                        gpu_count=gpu.get("count", 1),
                    ))
            profile.workspaces.append(ws)
        if profile.workspaces:
            profiles.append(profile)
    return profiles




# ---------------------------------------------------------------------------
# Credential resolver
# ---------------------------------------------------------------------------

PROVIDER_CRED_MAP = {
    "gemini": "GEMINI_API_KEY",
    "google-vertex-ai": "GOOGLE_API_KEY",
    "claude-code": "ANTHROPIC_API_KEY",
    "codex": "OPENAI_API_KEY",
    "nvidia": "NVIDIA_API_KEY",
    "build": "NVIDIA_INFERENCE_API_KEY",
    "brave": "BRAVE_API_KEY",
    "tavily": "TAVILY_API_KEY",
}


def resolve_credential(provider):
    env_var = f"PROV_{provider.name}_KEY".replace("-", "_").upper()
    val = os.environ.get(env_var)
    if val:
        return val
    cred_key = PROVIDER_CRED_MAP.get(provider.type)
    if cred_key:
        val = os.environ.get(cred_key)
        if val:
            return val
    return None


def resolve_configured_type(provider):
    """The credential secret's own `provider:` field (if setup-bom-profiles.sh
    found one alongside the API key), e.g. "gemini" or "build" (NVIDIA
    Build's own provider identifier — distinct from the OpenShell provider
    *type* "nvidia"). Returns None if not present, e.g. for secrets that
    don't carry a provider field at all.
    """
    env_var = f"PROV_{provider.name}_TYPE".replace("-", "_").upper()
    return os.environ.get(env_var) or None


def check_provider_type_mismatch(provider):
    """Validate that the credential secret's own declared provider matches
    what this BOM profile expects, before we create a provider using a
    credential that may belong to an entirely different service. Returns
    an error string if there's a mismatch, or None if it's fine / unknown.

    A profile's `type` (the OpenShell provider type, e.g. "nvidia") and
    `nemoclaw_provider` (a NemoClaw-specific alias, e.g. "build" for NVIDIA
    Build) are both accepted as valid matches, since values-secret.yaml's
    documented provider identifiers ("gemini, anthropic, openai, build
    (NVIDIA), openrouter, ...") use the nemoclaw-style alias, not the
    OpenShell type, for NVIDIA specifically.
    """
    configured = resolve_configured_type(provider)
    if not configured:
        return None
    valid = {v for v in (provider.type, provider.nemoclaw_provider) if v}
    if configured not in valid:
        expected = " or ".join(sorted(valid)) if valid else provider.type
        return (f"BOM profile expects provider type '{expected}' for "
                f"'{provider.name}', but the credential secret is "
                f"configured for provider '{configured}'")
    return None


def find_provider(ws, names):
    """Look up a provider by name from a sandbox's own declared providers list.

    Falls back to the first workspace provider only if the sandbox didn't
    declare any (or none of its declared names match) — previously this
    fallback was the *only* behavior, silently ignoring `sandbox.providers`
    entirely and wiring up whatever happened to be first in the workspace's
    provider list (e.g. attaching a web-search credential as if it were an
    LLM provider, if that provider happened to be declared first).
    """
    for name in names or []:
        for p in ws.providers:
            if p.name == name:
                return p
    return ws.providers[0] if ws.providers else None


# ---------------------------------------------------------------------------
# Gateway setup
# ---------------------------------------------------------------------------

class GatewaySetup:
    def __init__(self, shell, oidc_gw, mtls_gw):
        self.sh = shell
        self.oidc_gw = oidc_gw
        self.mtls_gw = mtls_gw

    def configure_oidc(self, token, issuer, client_id):
        if not token:
            return
        section("Configuring OIDC token")
        gw_name = self.oidc_gw
        token_dir = Path.home() / ".config" / "openshell" / "gateways" / gw_name
        token_dir.mkdir(parents=True, exist_ok=True)
        token_path = token_dir / "oidc_token.json"
        token_data = {
            "access_token": token,
            "issuer": issuer,
            "client_id": client_id,
        }
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_data, f)
        token_path.chmod(0o600)
        log(f"OIDC token written for gateway '{gw_name}'")

    def register_mtls_gateway(self):
        section("Registering mTLS gateway")
        self.sh.run(["openshell", "gateway", "remove", self.mtls_gw],
                     check=False)
        self.sh.run([
            "openshell", "gateway", "add",
            "https://127.0.0.1:17670",
            "--name", self.mtls_gw, "--local"
        ])
        self.sh.run(["openshell", "gateway", "select", self.mtls_gw])

    def grant_default_workspace_access(self):
        section("Granting default workspace access")
        self._with_oidc(lambda: self.sh.run([
            "openshell", "workspace", "member", "add",
            "--workspace", "default",
            "--subject", "openshell-client",
            "--role", "admin"
        ], check=False))

    def enable_providers_v2(self):
        section("Enabling providers_v2")
        self._with_oidc(lambda: self.sh.run([
            "openshell", "settings", "set",
            "--global", "--key", "providers_v2_enabled",
            "--value", "true", "--yes"
        ], check=False))

    def select_oidc(self):
        if self.oidc_gw:
            self.sh.run(["openshell", "gateway", "select", self.oidc_gw],
                         check=False)

    def select_mtls(self):
        self.sh.run(["openshell", "gateway", "select", self.mtls_gw],
                     check=False)

    def _with_oidc(self, fn):
        if self.oidc_gw:
            self.select_oidc()
            fn()
            self.select_mtls()
        else:
            fn()


# ---------------------------------------------------------------------------
# Workspace deployer
# ---------------------------------------------------------------------------

class WorkspaceDeployer:
    def __init__(self, shell, gateway_setup):
        self.sh = shell
        self.gw = gateway_setup

    def create_workspace(self, ws):
        if ws.name == "default":
            log(f"Using existing 'default' workspace")
            return
        log(f"Creating workspace '{ws.name}'")
        self.gw._with_oidc(lambda: (
            self.sh.run(["openshell", "workspace", "create",
                         "--name", ws.name], check=False),
            self.sh.run(["openshell", "workspace", "member", "add",
                         "--workspace", ws.name,
                         "--subject", "openshell-client",
                         "--role", "admin"], check=False),
        ))

    def create_provider(self, provider, credential,
                        workspace_name="default"):
        mismatch = check_provider_type_mismatch(provider)
        if mismatch:
            log(f"ERROR: {mismatch} — skipping provider "
                f"'{provider.name}' creation. Fix values-secret.yaml or "
                f"the BOM profile's declared type/nemoclawProvider.")
            return
        args = ["openshell", "provider", "create",
                "--name", provider.name, "--type", provider.type]
        if workspace_name != "default":
            args += ["--workspace", workspace_name]
        cred_key = PROVIDER_CRED_MAP.get(provider.type, "API_KEY")
        if credential and cred_key:
            args += ["--credential", f"{cred_key}={credential}"]
        else:
            args += ["--from-existing"]
        self.sh.run(args, check=False)

    def create_sandbox_generic(self, sandbox, workspace_name="default"):
        ws_args = (["--workspace", workspace_name]
                   if workspace_name != "default" else [])
        rc, out, _ = self.sh.run(
            ["openshell", "sandbox", "get", sandbox.name] + ws_args,
            check=False)
        if rc == 0:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', out)
            if "Error" in clean:
                log(f"Sandbox '{sandbox.name}' is in Error state, "
                    "recreating...")
                self.sh.run(
                    ["openshell", "sandbox", "delete",
                     sandbox.name] + ws_args,
                    check=False)
            else:
                log(f"Sandbox '{sandbox.name}' already exists")
                return
        is_full_ref = sandbox.image and ("/" in sandbox.image or ":" in sandbox.image)
        if is_full_ref:
            self.sh.run(["sudo", "docker", "pull", sandbox.image], check=False)
        args = ["openshell", "sandbox", "create", "--name", sandbox.name]
        if sandbox.image:
            args += ["--from", sandbox.image]
        if workspace_name != "default":
            args += ["--workspace", workspace_name]
        for prov in sandbox.providers:
            args += ["--provider", prov]
        if sandbox.gpu_enabled:
            # `--gpu [<COUNT>]` is a native openshell CLI flag (confirmed live against
            # v0.0.103+rhaiv.0) — it asks the configured driver (docker/podman) to attach
            # GPU resources to the sandbox container. Only actually works if the runtime is
            # GPU-capable (NVIDIA Container Toolkit + CDI) and the VM itself received a
            # passed-through GPU (vm.gpu.enabled) — a no-op request otherwise. See
            # docs/gpu-passthrough.md.
            args += ["--gpu", str(sandbox.gpu_count)]
        args += ["--no-tty", "--", "sh", "-c", "echo sandbox-ready"]
        rc, out, err = self.sh.run(args, check=False)
        combined = re.sub(r'\x1b\[[0-9;]*m', '',
                          (out or "") + " " + (err or ""))
        if "Error" in combined or "Restarting" in combined:
            log("Sandbox entered Error state, waiting 10s for logs...")
            if not self.sh.dry_run:
                time.sleep(10)
            self.sh.run([
                "bash", "-c",
                "CNAME=$(sudo docker ps -a "
                f"--filter 'name=openshell.*{sandbox.name}' "
                "--format '{{.Names}}' | head -1) && "
                "echo \"Container: $CNAME\" && "
                "echo \"Status: $(sudo docker inspect $CNAME "
                "--format '{{.State.Status}} ExitCode={{.State.ExitCode}}')"
                "\" && echo '--- logs ---' && "
                "sudo docker logs $CNAME 2>&1 | tail -30"
            ], check=False)

    def install_nemoclaw_cli(self, cli_image):
        if not cli_image:
            return
        rc, _, _ = self.sh.run(["which", "nemoclaw"], check=False)
        if rc == 0:
            log("nemoclaw CLI already installed, skipping")
            return
        section("Installing nemoclaw CLI")
        self.sh.run([
            "bash", "-c",
            f"CID=$(docker create '{cli_image}' 2>/dev/null) && "
            f"docker cp $CID:/opt/nemoclaw /tmp/nemoclaw-cli && "
            f"docker rm $CID >/dev/null && "
            f"sudo mv /tmp/nemoclaw-cli /opt/nemoclaw && "
            f"printf '#!/usr/bin/env bash\\nexec node "
            f"/opt/nemoclaw/bin/nemoclaw.js \"$@\"\\n' "
            f"| sudo tee /usr/local/bin/nemoclaw >/dev/null && "
            f"sudo chmod 755 /usr/local/bin/nemoclaw"
        ], check=False)

    def onboard_nemoclaw(self, sandbox, provider, credential):
        state_dir = str(Path.home() / ".local" / "state" / "openshell")
        mgmt_path = str(Path.home() / "gateway-management.json")
        mgmt = {
            "version": 1, "mode": "externally-supervised",
            "endpoint": "https://127.0.0.1:17670",
            "stateDir": state_dir,
            "supervisor": {
                "kind": "systemd-user",
                "serviceName": "openshell-gateway.service",
                "execPath": "/usr/local/bin/openshell-gateway",
            },
        }
        if not self.sh.dry_run:
            os.makedirs(os.path.dirname(mgmt_path), exist_ok=True)
            with open(mgmt_path, "w", encoding="utf-8") as f:
                json.dump(mgmt, f)

        nc_prov = provider.nemoclaw_provider or provider.type
        env = {
            "NEMOCLAW_GATEWAY_MANAGEMENT": mgmt_path,
            "NEMOCLAW_GATEWAY_PORT": "17670",
            "NEMOCLAW_IGNORE_RUNTIME_RESOURCES": "1",
            "NEMOCLAW_OPENSHELL_GATEWAY_BIN":
                "/usr/local/bin/openshell-gateway",
            "NEMOCLAW_OPENSHELL_SANDBOX_BIN":
                "/usr/local/bin/openshell-supervisor",
            "NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE": "1",
            "NEMOCLAW_PROVIDER": nc_prov,
        }
        if sandbox.model or provider.model:
            env["NEMOCLAW_MODEL"] = sandbox.model or provider.model
        if credential:
            env["NEMOCLAW_PROVIDER_KEY"] = credential
            cred_key = PROVIDER_CRED_MAP.get(nc_prov, "")
            if cred_key:
                env[cred_key] = credential
        if sandbox.gpu_enabled:
            # Best-effort: pass GPU intent through to nemoclaw onboard in case it has its
            # own GPU detection/tool-selection logic. NemoClaw is an upstream, closed-source
            # binary — this repo cannot verify what (if anything) it does with these env
            # vars. See docs/gpu-passthrough.md.
            env["NEMOCLAW_GPU_ENABLED"] = "true"
            env["NEMOCLAW_GPU_COUNT"] = str(sandbox.gpu_count)
        cmd = [
            "nemoclaw", "onboard",
            "--fresh", "--non-interactive",
            "--name", sandbox.name,
            "--agent", sandbox.agent or "openclaw",
            "--yes", "--yes-i-accept-third-party-software",
        ]
        rc, _, _ = self.sh.run(cmd, env=env, check=False)
        return rc == 0

    def start_openclaw_gateway(self, sandbox_name, dashboard_route,
                               workspace_name="default",
                               provider_id="nvidia",
                               model_id="nvidia/nemotron-3-super-120b-a12b"):
        import secrets as secrets_mod

        ws_args = ["--workspace", workspace_name] if workspace_name else []

        # Wait for sandbox to reach Ready
        if not self.sh.dry_run:
            for i in range(20):
                rc, out, _ = self.sh.run([
                    "openshell", "sandbox", "get", sandbox_name
                ] + ws_args, check=False)
                clean = re.sub(r'\x1b\[[0-9;]*m', '', out or "")
                if "Ready" in clean and "Error" not in clean:
                    log(f"Sandbox '{sandbox_name}' is Ready")
                    break
                log(f"  waiting for sandbox ready... (attempt {i+1})")
                time.sleep(5)

        token = secrets_mod.token_hex(16)
        exec_cmd = ["openshell", "sandbox", "exec", "-n",
                     sandbox_name] + ws_args + ["--no-tty", "--"]

        # Configure openclaw: model, agent, gateway token
        oc_env = ("OPENCLAW_HOME=/sandbox "
                  "SQLITE_TMPDIR=/sandbox/.openclaw/state "
                  "TMPDIR=/sandbox/.openclaw/state "
                  "OPENCLAW_NIX_MODE=0")

        log("Running openclaw onboard...")
        self.sh.run(
            exec_cmd + ["sh", "-c",
                        f"{oc_env} CUSTOM_API_KEY=proxy-managed "
                        f"openclaw onboard "
                        f"--non-interactive --accept-risk "
                        f"--mode local "
                        f"--auth-choice custom-api-key "
                        f'--custom-base-url "https://inference.local/v1" '
                        f"--custom-provider-id {provider_id} "
                        f'--custom-model-id "{model_id}" '
                        f"--custom-compatibility openai "
                        f"--skip-channels --skip-health"],
            check=False)
        # Set gateway token
        self.sh.run(
            exec_cmd + ["sh", "-c",
                        f"{oc_env} openclaw config set "
                        f"gateway.auth.token '{token}'"],
            check=False)
        if dashboard_route:
            self.sh.run(
                exec_cmd + ["sh", "-c",
                            f"{oc_env} openclaw config set "
                            "gateway.controlUi.allowedOrigins "
                            f"'[\"https://{dashboard_route}\"]'"],
                check=False)

        log(f"Starting openclaw gateway (token={token[:8]}...)")
        self.sh.run(
            exec_cmd + ["sh", "-c",
                        f"export OPENCLAW_GATEWAY_TOKEN={token} "
                        f"OPENCLAW_HOME=/sandbox "
                        f"SQLITE_TMPDIR=/sandbox/.openclaw/state "
                        f"TMPDIR=/sandbox/.openclaw/state "
                        f"OPENCLAW_NIX_MODE=0 && "
                        f"nohup openclaw gateway run "
                        f"--allow-unconfigured "
                        f"--bind lan --port 18789 "
                        f"> /tmp/openclaw-gateway.log "
                        f"2>&1 &"],
            check=False)

        if not self.sh.dry_run:
            for i in range(10):
                rc, out, _ = self.sh.run(
                    exec_cmd + [
                    "curl", "-sf", "http://127.0.0.1:18789/health"
                ], check=False)
                if rc == 0 and "ok" in out:
                    log("openclaw gateway ready")
                    return
                log(f"  waiting for openclaw gateway... (attempt {i+1})")
                time.sleep(3)
            log("WARN: openclaw gateway health check failed")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class Verifier:
    def __init__(self, shell):
        self.sh = shell
        self.passed = 0
        self.failed = 0

    def check(self, desc, cmd):
        rc, out, _ = self.sh.run(cmd, check=False)
        if rc == 0:
            log(f"PASS  {desc}")
            self.passed += 1
        else:
            log(f"FAIL  {desc}")
            self.failed += 1
        return rc == 0, out

    def _ws_args(self, ws_name):
        if ws_name != "default":
            return ["--workspace", ws_name]
        return []

    def verify_profiles(self, profiles):
        banner("VERIFICATION")
        for profile in profiles:
            log(f"\nProfile: {profile.name}")
            for ws in profile.workspaces:
                if not ws.enabled:
                    continue
                ws_flag = self._ws_args(ws.name)
                log(f"\n  Workspace: {ws.name}")

                if ws.name != "default":
                    ok, out = self.check(
                        f"workspace '{ws.name}'",
                        ["openshell", "workspace", "list"])
                    if ok and ws.name not in (out or ""):
                        log(f"FAIL  workspace '{ws.name}' not in output")
                        self.passed -= 1
                        self.failed += 1

                for prov in ws.providers:
                    if not prov.enabled:
                        continue
                    self.check(
                        f"provider '{prov.name}' in '{ws.name}'",
                        ["openshell", "provider", "get",
                         prov.name] + ws_flag)

                for sb in ws.sandboxes:
                    if not sb.enabled:
                        continue
                    self.check(
                        f"sandbox '{sb.name}' in '{ws.name}'",
                        ["openshell", "sandbox", "get",
                         sb.name] + ws_flag)
                    if sb.providers:
                        _, out = self.check(
                            f"sandbox '{sb.name}' provider list",
                            ["openshell", "sandbox", "provider",
                             "list", sb.name] + ws_flag)
                        for prov_name in sb.providers:
                            if prov_name in (out or ""):
                                log(f"  PASS  '{sb.name}' "
                                    f"has provider '{prov_name}'")
                                self.passed += 1
                            else:
                                log(f"  FAIL  '{sb.name}' "
                                    f"missing provider '{prov_name}'")
                                self.failed += 1

        banner(f"Results: {self.passed} passed, {self.failed} failed")
        if self.failed > 0:
            log("STATUS: INCOMPLETE")
        else:
            log("STATUS: ALL PASSED")
        return self.failed == 0


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="BOM-driven agent configuration for SAW")
    parser.add_argument("--profiles-dir", required=True)
    parser.add_argument("--oidc-gateway", default="")
    parser.add_argument("--mtls-gateway", default="openshell-local")
    parser.add_argument("--nemoclaw-cli-image", default="")
    parser.add_argument("--dashboard-route", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # --- Parse profiles ---
    profiles = parse_profiles(args.profiles_dir)
    if not profiles:
        log("No profiles found, nothing to do")
        return

    total_ws = sum(len(p.workspaces) for p in profiles)
    total_sb = sum(len(sb) for p in profiles for ws in p.workspaces
                   for sb in [ws.sandboxes])
    banner(f"BOM Apply: {len(profiles)} profile(s), "
           f"{total_ws} workspace(s)")

    oidc_gw = args.oidc_gateway or os.environ.get("OPENSHELL_GATEWAY", "")
    sh = Shell(dry_run=args.dry_run)

    # --- Phase 1: Gateway setup ---
    banner("Phase 1: Gateway Setup")
    gw = GatewaySetup(sh, oidc_gw, args.mtls_gateway)

    oidc_token = os.environ.get("OIDC_TOKEN", "")
    gw.configure_oidc(
        oidc_token,
        os.environ.get("OIDC_ISSUER", ""),
        os.environ.get("OIDC_CLIENT_ID", "openshell-cli"),
    )
    gw.register_mtls_gateway()
    gw.grant_default_workspace_access()
    gw.enable_providers_v2()

    # --- Phase 2: Deploy profiles ---
    deployer = WorkspaceDeployer(sh, gw)
    for profile in profiles:
        banner(f"Phase 2: Profile '{profile.name}' "
               f"({len(profile.workspaces)} workspace(s))")

        for ws in profile.workspaces:
            log(f"\n  Workspace: {ws.name}")
            log(f"  {'─' * 50}")

            if not ws.enabled:
                log("  (disabled, skipping)")
                continue

            deployer.create_workspace(ws)

            # Create providers in the workspace
            enabled_provs = [p for p in ws.providers if p.enabled]
            if enabled_provs:
                section(f"Providers ({len(enabled_provs)}) "
                        f"in workspace '{ws.name}'")
                for prov in enabled_provs:
                    cred = resolve_credential(prov)
                    deployer.create_provider(prov, cred, ws.name)

            # Create sandboxes
            nemoclaw_cli_installed = False
            for sb in ws.sandboxes:
                if not sb.enabled:
                    log(f"  Sandbox '{sb.name}' disabled, skipping")
                    continue
                section(f"Sandbox '{sb.name}' (type={sb.type})")

                if sb.type == "nemoclaw":
                    # Nemoclaw flow (matches feat/fix-docker-golden-image):
                    # 1. Install nemoclaw CLI
                    # 2. nemoclaw onboard (configures provider)
                    # 3. Fallback: openshell provider create
                    # 4. openshell sandbox create
                    # 5. Start openclaw gateway inside sandbox
                    if not nemoclaw_cli_installed:
                        cli_img = args.nemoclaw_cli_image or \
                            os.environ.get("NEMOCLAW_CLI_IMAGE", "")
                        if cli_img:
                            deployer.install_nemoclaw_cli(cli_img)
                            nemoclaw_cli_installed = True

                    is_full_ref = sb.image and ("/" in sb.image
                                                or ":" in sb.image)
                    if is_full_ref:
                        deployer.sh.run(
                            ["sudo", "docker", "pull", sb.image],
                            check=False)

                    prov = find_provider(ws, sb.providers)
                    cred = resolve_credential(prov) if prov else None
                    mismatch = check_provider_type_mismatch(prov) if prov else None
                    if mismatch:
                        log(f"ERROR: {mismatch} — skipping nemoclaw "
                            f"onboard for '{sb.name}'.")
                    elif prov and cred:
                        nc_prov = prov.nemoclaw_provider or prov.type
                        log(f"nemoclaw onboard --agent {sb.agent or 'openclaw'}"
                            f" (provider={nc_prov})")
                        ok = deployer.onboard_nemoclaw(sb, prov, cred)
                        if not ok:
                            log("nemoclaw onboard failed, "
                                "configuring provider manually")
                            deployer.create_provider(prov, cred, ws.name)

                    deployer.create_sandbox_generic(sb, ws.name)
                    prov_id = prov.type if prov else "nvidia"
                    model = sb.model or (prov.model if prov else "")
                    deployer.start_openclaw_gateway(
                        sb.name, args.dashboard_route or "",
                        workspace_name=ws.name,
                        provider_id=prov_id,
                        model_id=model or "nvidia/nemotron-3-super-120b-a12b")

                elif sb.type == "openclaw":
                    deployer.create_sandbox_generic(sb, ws.name)
                    prov = find_provider(ws, sb.providers)
                    prov_id = prov.type if prov else "nvidia"
                    model = sb.model or (prov.model if prov else "")
                    deployer.start_openclaw_gateway(
                        sb.name, args.dashboard_route or "",
                        workspace_name=ws.name,
                        provider_id=prov_id,
                        model_id=model or "nvidia/nemotron-3-super-120b-a12b")

                else:
                    # Generic: just create the sandbox
                    deployer.create_sandbox_generic(sb, ws.name)

    # --- Phase 4: Verify ---
    if not args.dry_run:
        verifier = Verifier(sh)
        ok = verifier.verify_profiles(profiles)
        if not ok:
            # Without this, the setup Job reports "Complete" even when the
            # BOM apply only partially succeeded — verified live: a run with
            # 9 passed / 1 failed still showed Job status Complete, with the
            # only signal being "STATUS: INCOMPLETE" buried in the full log.
            raise SystemExit(1)


if __name__ == "__main__":
    main()
