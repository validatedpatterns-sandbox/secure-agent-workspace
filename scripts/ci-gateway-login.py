"""VP CI bootstrap; keep browser login and the live harness unchanged."""

import base64
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import time

import yaml

ROOT = Path(__file__).resolve().parents[1]


class SetupError(RuntimeError):
    pass


class Bootstrap:
    def __init__(self, env):
        self.env = dict(env)
        self.name = self.env.get("OPENSHELL_SAW_NAME") or "alice"
        if self.name != "alice":
            raise SetupError("The CI variant authenticates as alice; OPENSHELL_SAW_NAME must be alice")
        self.namespace = self.env.get("SAW_NS") or f"saw-{self.name}"
        self.keycloak_ns = self.env.get("KEYCLOAK_NS") or "saw-keycloak"
        timeout = float(self.env.get("CI_READINESS_TIMEOUT", "1800"))
        if not 0 < timeout < float("inf"):
            raise SetupError("CI_READINESS_TIMEOUT must be a positive number of seconds")
        self.deadline = time.monotonic() + timeout
        config = Path(self.env.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        self.gateway_dir = config / "openshell" / "gateways" / self.name
        self.env.update(OPENSHELL_SAW_NAME=self.name, SAW_NS=self.namespace,
                        VM_NAME=self.name, KEY_NAME="vp-ci-harness", WORKSPACE="default",
                        OIDC_TOKEN_DIR=str(config / "openshell" / "oidc"),
                        NS=self.keycloak_ns)
        self.env.setdefault("SSH_KEY_PATH", str(config / "openshell" / "ci-ssh"))
        # generate-keys.sh must not create a values-secret in the runner's HOME.
        self.env["VALUES_SECRET"] = str(ROOT / "values-secret.yaml.template")
        self.stage = "preflight"

    def run(self, args, *, env=None, limit=120):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SetupError(f"Readiness timed out during {self.stage}")
        # Kill the entire process group on timeout, including virtctl's SSH
        # child and shell helpers. Otherwise captured pipes can stay open.
        with subprocess.Popen(args, cwd=ROOT, env=env or self.env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=min(limit, remaining))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
                return subprocess.CompletedProcess(args, 124, stdout, stderr + "\nCommand timed out")
            return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)

    def wait(self, stage, operation, ready=lambda output: bool(output.strip())):
        self.stage = stage
        print(f"Waiting for {stage}...", flush=True)
        last = "not ready"
        while time.monotonic() < self.deadline:
            result = operation()
            if result.returncode == 0 and ready(result.stdout):
                return result.stdout
            last = result.stderr.strip() or "resource not ready"
            if any(error in last.lower() for error in
                   ("forbidden", "unauthorized", "permission denied", "password login failed",
                    "password login returned an invalid token")):
                raise SetupError(f"{stage}: {last}")
            time.sleep(min(10, max(0, self.deadline - time.monotonic())))
        raise SetupError(f"Readiness timed out during {stage}: {last}")

    def checked(self, args, **kwargs):
        result = self.run(args, **kwargs)
        if result.returncode:
            raise SetupError(f"{self.stage}: {result.stderr.strip() or 'command failed'}")
        return result.stdout

    @staticmethod
    def installer_ready(output):
        try:
            status = json.loads(output)
            phases = [(status.get(phase) or {}).get("phase") for phase in ("install", "apply")]
        except (ValueError, AttributeError, TypeError) as error:
            raise SetupError("Installer status did not return a JSON status object") from error
        if any(phase in ("Failed", "Error") for phase in phases):
            raise SetupError(f"Installer failed: install={phases[0]}, apply={phases[1]}")
        return phases == ["Done", "Done"]

    def setup(self):
        for tool in ("oc", "make", "ssh", "ssh-keygen", "curl", "jq", "openssl"):
            if not shutil.which(tool, path=self.env.get("PATH")):
                raise SetupError(f"{tool} is required on the VP CI runner")
        self.checked(["bash", str(ROOT / "scripts/check-saw-name.sh")])
        self.ensure_tools()
        self.checked(["make", "ssh-key-generate"])
        host = self.wait("gateway route", lambda: self.run([
            "oc", "get", "route", f"{self.name}-gateway", "-n", self.namespace,
            "-o", "jsonpath={.spec.host}"])).strip()
        issuer = self.env.get("OIDC_ISSUER")
        if not issuer:
            keycloak_host = self.wait("Keycloak host", lambda: self.run([
                "bash", str(ROOT / "scripts/keycloak-host.sh"), self.keycloak_ns])).strip()
            issuer = f"https://{keycloak_host}/realms/{self.env.get('KEYCLOAK_REALM') or 'openshell'}"
        password_data = self.wait("Keycloak user password Secret", lambda: self.run([
            "oc", "get", "secret", "openshell-keycloak-user-passwords", "-n", self.keycloak_ns,
            "-o", "jsonpath={.data.alice}"]), ready=lambda output: True)
        try:
            password = base64.b64decode(password_data.strip(), validate=True).decode()
        except (ValueError, UnicodeError) as error:
            raise SetupError("Invalid alice password data in the Keycloak Secret") from error
        if not password:
            raise SetupError("The Keycloak Secret has no alice password")

        self.env["OIDC_ISSUER"] = issuer
        self.wait("OIDC login", lambda: self.run([
            "bash", str(ROOT / "scripts/oidc-login.sh"), "login"],
            env={**self.env, "OIDC_FLOW": "password", "OIDC_USERNAME": "alice",
                 "OIDC_PASSWORD": password}), ready=lambda output: True)
        del password
        self.wait("VM installer completion", lambda: self.run([
            "bash", str(ROOT / "scripts/openshell-saw-vm-ssh.sh"),
            "sudo cat /var/lib/saw/status.json"]), self.installer_ready)
        self.wait("gateway TLS CA", lambda: self.run([
            "bash", str(ROOT / "scripts/extract-gateway-ca.sh")],
            env={**self.env, "NS": self.namespace,
                 "OUT_FILE": str(self.gateway_dir / "mtls/ca.crt")}), ready=lambda output: True)
        self.write_gateway(host, issuer)
        self.wait("notebook sandbox execution", lambda: self.run([
            "openshell", "--gateway", self.name, "sandbox", "exec", "-n", "notebook",
            "--workspace", "default", "--no-tty", "--", "true"]), ready=lambda output: True)
        print("alice gateway authenticated; notebook is ready.", flush=True)

    def ensure_tools(self):
        """Stage missing clients in the test's temporary PATH, not the image."""
        missing = [tool for tool in ("virtctl", "openshell")
                   if not shutil.which(tool, path=self.env.get("PATH"))]
        if not missing:
            return
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        if platform.system() != "Linux" or not arch:
            raise SetupError("Automatic CI tool setup supports Linux amd64/arm64 runners")
        self.stage = "CI client installation"
        bindir = Path(self.env.get("CI_BIN_DIR") or self.gateway_dir.parents[1] / "bin")
        bindir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.env["PATH"] = str(bindir) + os.pathsep + self.env.get("PATH", os.defpath)
        if "virtctl" in missing:
            downloads = json.loads(self.wait("virtualization CLI download metadata", lambda: self.run([
                "oc", "get", "consoleclidownloads", "-o", "json"]),
                ready=lambda output: any(
                    f"/{arch}/linux/virtctl.tar.gz" in link.get("href", "")
                    for item in json.loads(output)["items"] for link in item["spec"].get("links", []))))
            url = next(link["href"] for item in downloads["items"]
                       for link in item["spec"].get("links", [])
                       if link.get("href", "").endswith(f"/{arch}/linux/virtctl.tar.gz"))
            # Trust the cluster's ingress CA obtained through the authenticated
            # API, rather than disabling TLS to download an executable.
            encoded_ca = self.checked([
                "oc", "get", "secret", "router-ca", "-n", "openshift-ingress-operator",
                "-o", r"jsonpath={.data.tls\.crt}"])
            ca_file = bindir / "ingress-ca.crt"
            ca_file.write_bytes(base64.b64decode(encoded_ca.strip(), validate=True))
            archive = bindir / "virtctl.tar.gz"
            self.checked(["curl", "-fsSL", "--cacert", str(ca_file),
                          "--connect-timeout", "10", "--max-time", "120", "-o", str(archive), url])
            with tarfile.open(archive) as bundle:
                member = next((entry for entry in bundle.getmembers()
                               if Path(entry.name).name == "virtctl" and entry.isfile()), None)
                if member is None:
                    raise SetupError("The virtualization CLI archive contains no virtctl binary")
                with bundle.extractfile(member) as source, (bindir / "virtctl").open("wb") as target:
                    shutil.copyfileobj(source, target)
            (bindir / "virtctl").chmod(0o700)
            archive.unlink()
        if "openshell" in missing:
            config = json.loads(self.wait("alice installer configuration", lambda: self.run([
                "oc", "get", "configmap", f"{self.name}-installer", "-n", self.namespace,
                "-o", "json"])))
            cli = yaml.safe_load(config["data"]["installer-bom.yaml"])["spec"]["openshell"]["cli"]
            image = cli["image"]
            if "@sha256:" not in image:
                raise SetupError("The deployed OpenShell CLI image must be pinned by digest")
            self.checked(["oc", "image", "extract", image,
                          f"--path={cli.get('path', '/usr/local/bin/openshell')}:{bindir}",
                          f"--filter-by-os=linux/{arch}", "--confirm"], limit=300)
            (bindir / "openshell").chmod(0o700)
            version = self.checked([str(bindir / "openshell"), "--version"]).strip()
            if version != f"openshell {cli['version']}":
                raise SetupError(f"Extracted CLI version {version} does not match deployed BOM {cli['version']}")
        self.stage = "preflight"

    def write_gateway(self, host, issuer):
        # CLI-owned contract (not the raw OAuth response):
        # NVIDIA/OpenShell crates/openshell-cli/src/oidc_auth.rs,
        # bundle_from_oauth2_response; metadata in openshell-bootstrap/src/metadata.rs.
        token_file = Path(self.env["OIDC_TOKEN_DIR"]) / "token.json"
        try:
            response = json.loads(token_file.read_text())
            token = {"access_token": response["access_token"],
                     "refresh_token": response.get("refresh_token"),
                     "expires_at": int(response["saved_at"]) + int(response["expires_in"]),
                     "issuer": issuer, "client_id": self.env.get("OIDC_CLIENT_ID") or "openshell-cli"}
            if not isinstance(token["access_token"], str) or not token["access_token"] or \
                    token["expires_at"] <= time.time():
                raise ValueError("invalid token")
        except (KeyError, ValueError, TypeError) as error:
            raise SetupError("Login returned an invalid or expired gateway token") from error
        metadata = {"name": self.name, "gateway_endpoint": f"https://{host}",
                    "is_remote": False, "gateway_port": 443, "auth_mode": "oidc",
                    "oidc_issuer": issuer, "oidc_client_id": token["client_id"]}
        self.gateway_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.gateway_dir.chmod(0o700)
        for filename, data in (("metadata.json", metadata), ("oidc_token.json", token)):
            path = self.gateway_dir / filename
            with open(path, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                json.dump(data, stream)
            path.chmod(0o600)

    def diagnostics(self):
        # No Secrets or tokens in diagnostics. Keep a separate small budget
        # after readiness expiry to collect the resources needed to triage it.
        self.deadline = time.monotonic() + 20
        for resources in ("pods,vm,vmi,route", "events"):
            result = self.run(["oc", "get", resources, "-n", self.namespace], limit=10)
            print(result.stdout + result.stderr, file=sys.stderr)


def main():
    bootstrap = None
    try:
        bootstrap = Bootstrap(os.environ)
        bootstrap.setup()
    except (SetupError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        if bootstrap and shutil.which("oc"):
            try:
                bootstrap.diagnostics()
            except (SetupError, OSError):
                pass
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
