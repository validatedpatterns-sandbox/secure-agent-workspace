"""Fixtures for the in-guest installer tests.

The installer is exercised for real (real subprocesses, real files) against
fake `podman`, `openshell`, `nemoclaw` and `sudo` executables placed first on
PATH. No cluster, VM, network or credentials are used.
"""

import base64
import hashlib
import importlib.util
import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshell-saw"
SCRIPT = CHART / "files" / "installer" / "apply_bom.py"
PROFILES = ROOT / "charts" / "saw-bom" / "profiles"
FAKES = Path(__file__).resolve().parent / "fakes"
GATEWAY_ENV = "OPENSHELL_SERVER_PORT=17670\nOPENSHELL_ENABLE_MTLS_AUTH=true\n"
GATEWAY_TOML = ('[openshell.drivers.podman]\nsupervisor_image = "quay.io/x/supervisor@sha256:abc"\n'
                'allow_driver_config = true\n')
TEST_PROXY = {"url": "http://proxy.test.svc.cluster.local:3128",
              "markerPrefix": "saw-cred", "secrets": [
                  {"name": "inference", "key": "api_key", "providers": ["nvidia", "build", "openai", "anthropic"]},
                  {"name": "web-search", "key": "api_key", "providers": ["brave"]}]}


def _load_module():
    spec = importlib.util.spec_from_file_location("apply_bom", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_bom"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def ab():
    return _load_module()


@pytest.fixture
def chart_bom():
    """The BOM shipped as the chart default."""
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    return values["bom"]


@pytest.fixture
def bom(chart_bom):
    """The chart BOM with only the three OpenShell components; tests that
    need the optional NemoClaw CLI add it themselves."""
    doc = json.loads(json.dumps(chart_bom))
    doc["spec"].pop("nemoclaw", None)
    return doc


def profile_files(profile="data-science"):
    """Flatten a saw-bom profile exactly like templates/configmap-bom.yaml."""
    files = {}
    for path in sorted((PROFILES / profile).rglob("*.yaml")):
        rel = path.relative_to(PROFILES.parent)  # profiles/<profile>/<ws>/<file>
        files[str(rel).replace("/", "__")] = path.read_text()
    return files


@pytest.fixture
def shipped_profile_files():
    return profile_files()


HARNESS = ROOT / "charts" / "saw-bom" / "harness"


def harness_files():
    """Flatten charts/saw-bom/harness exactly like templates/configmap-bom.yaml
    (content-addressed keys plus a path map per bundle), but as raw bytes (the
    ConfigMap value is the base64 of these bytes)."""
    files = {}
    maps = {}
    for path in sorted(HARNESS.rglob("*")):
        if path.is_file():
            parts = path.relative_to(HARNESS).parts
            bundle, rel = parts[0], "/".join(parts[1:])
            key = f"harness__{bundle}__{hashlib.sha256(rel.encode()).hexdigest()[:16]}"
            files[key] = path.read_bytes()
            maps.setdefault(bundle, {})[key.rsplit("__", 1)[1]] = rel
    for bundle, path_map in maps.items():
        files[f"harness__{bundle}__map"] = json.dumps(path_map).encode()
    return files


@pytest.fixture
def shipped_harness_files():
    return harness_files()


def tree_digest_of_shipped_bundle():
    """Independent reimplementation of the tree_digest contract, kept apart
    from the `ab` fixture (the module under test) so a bug in tree_digest
    cannot make this fixture agree with itself."""
    root = HARNESS / "ds-default"
    files = {str(p.relative_to(root)): p.read_bytes()
             for p in sorted(root.rglob("*")) if p.is_file()}
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(f"{rel}\x00{hashlib.sha256(files[rel]).hexdigest()}\n".encode())
    return "sha256:" + digest.hexdigest()


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    """Put fake executables first on PATH and give them a state directory."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    for fake in FAKES.iterdir():
        target = bin_dir / fake.name
        target.write_text(fake.read_text())
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    state = tmp_path / "fakestate"
    state.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_STATE", str(state))
    monkeypatch.setenv("FAKE_PYTHON", sys.executable)
    # Gateway PKI after the tmpfs generator: the CA private key is gone;
    # persistent client and relay certificates have only the user role.
    home = tmp_path / "home"
    ca_dir = home / ".local" / "state" / "openshell" / "tls"
    ca_dir.mkdir(parents=True)
    ca_key = tmp_path / "gateway-ca.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", str(ca_key), "-out", str(ca_dir / "ca.crt"),
                    "-subj", "/O=openshell/CN=openshell-ca", "-days", "30"],
                   check=True, capture_output=True)
    for name, subject, ext_text in (
        ("relay", "/O=openshell/OU=openshell-user/CN=saw-relay",
         "extendedKeyUsage=clientAuth\n"),
        ("client", "/O=openshell/OU=openshell-user/CN=local-client",
         "extendedKeyUsage=clientAuth\n"),
        ("server", "/O=openshell/CN=host.openshell.internal",
         "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:host.openshell.internal\n"),
    ):
        directory = ca_dir / name
        directory.mkdir()
        csr, ext = tmp_path / f"{name}.csr", tmp_path / f"{name}.ext"
        ext.write_text(ext_text)
        subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(directory / "tls.key"),
                        "-out", str(csr), "-subj", subject], check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_dir / "ca.crt"),
                        "-CAkey", str(ca_key), "-set_serial", "0x" + secrets.token_hex(16),
                        "-days", "30", "-extfile", str(ext), "-out", str(directory / "tls.crt")],
                       check=True, capture_output=True)
    (ca_dir / "client-ca.pem").write_bytes((ca_dir / "ca.crt").read_bytes())
    (ca_dir / "pki-generation").write_text("1\n")
    ca_key.unlink()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setenv("SAW_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("HOME", str(home))
    return FakeWorld(state, home)


class FakeWorld:
    """Helpers to configure and inspect the fakes."""

    def __init__(self, state, home=None):
        self.state = state
        self.home = home

    def rbac(self):
        """Gateway with OIDC RBAC: platform-admin calls need OU=openshell-admin."""
        (self.state / "rbac").write_text("on")

    def admin_cert(self):
        return self.admin_tls / "client" / "tls.crt"

    # podman -------------------------------------------------------------
    def set_images(self, images):
        (self.state / "images.json").write_text(json.dumps(images))

    def images_for_bom(self, bom, version=None, nemoclaw=True):
        images = {}
        paths = {"gateway": "/usr/local/bin/openshell-gateway",
                 "supervisor": "/openshell-supervisor",
                 "cli": "/usr/local/bin/openshell"}
        for comp, entry in bom["spec"]["openshell"].items():
            if comp not in paths:        # image-only component (sandbox runtime)
                images[entry["image"]] = {}
                continue
            images[entry["image"]] = {paths[comp]: {"type": "binary",
                                                    "version": version or entry["version"]}}
        if nemoclaw and "nemoclaw" in bom["spec"]:
            images[bom["spec"]["nemoclaw"]["cliImage"]] = {"/opt/nemoclaw": {"type": "nemoclaw"}}
        self.set_images(images)
        return images

    def podman_calls(self):
        log = self.state / "podman.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    # openshell ------------------------------------------------------------
    def openshell_state(self):
        path = self.state / "openshell.json"
        return json.loads(path.read_text()) if path.exists() else None

    def set_openshell_state(self, data):
        (self.state / "openshell.json").write_text(json.dumps(data))

    def openshell_calls(self):
        log = self.state / "openshell.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def openshell_env_calls(self):
        log = self.state / "openshell-env.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def deny(self, *operations):
        (self.state / "deny.json").write_text(json.dumps(list(operations)))

    def reject_json_output(self):
        """`sandbox get --output json` fails like a CLI that has no such flag."""
        (self.state / "reject-json").write_text("1")

    def exec_fails_in(self, *sandboxes):
        """`sandbox exec` into these sandboxes fails like a policy denial."""
        (self.state / "exec-fail.json").write_text(json.dumps(list(sandboxes)))

    def without_profiles(self, *types):
        """Gateway without these provider profiles (e.g. governance off)."""
        (self.state / "no-profiles.json").write_text(json.dumps(list(types)))

    def other_calls(self, name):
        log = self.state / f"{name}.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture
def secrets_dir(tmp_path):
    """Only metadata reaches /run/saw/secrets/<secret> on the VM."""
    base = tmp_path / "secrets"
    for secret, data in {"inference": {"provider": "build"},
                         "web-search": {"provider": "brave"}}.items():
        (base / secret).mkdir(parents=True)
        for key, value in data.items():
            (base / secret / key).write_text(value + "\n")
    return base


@pytest.fixture
def config(ab, fake_env):
    with ab.admin_session({}, fake_env.home, None, as_current_user=True) as (tls, config_home):
        fake_env.admin_tls = tls
        yield {"vmName": "saw-test", "namespace": "openshell-agents",
            "runtimeUser": "cloud-user", "mtlsGateway": "saw-installer",
            "relayGateway": "saw-relay", "adminTlsDir": str(tls),
            "adminConfigHome": str(config_home),
            "credentialProxy": TEST_PROXY,
            "gatewayPki": {"generation": 1, "caFingerprint": "test-gateway-ca"},
            "ownerSubject": "subject-alice", "oidcIssuer": "", "sandboxDashboardRoute": "",
            "dashboard": {"enabled": False, "owner": "alice"},
            "harness": {"cosign": {
                "cacheTtlSeconds": 0,
                "identity": "https://github.com/example/saw/.github/workflows/harness-bundles.yml@refs/heads/main",
                "issuer": "https://token.actions.githubusercontent.com"}}}


@pytest.fixture
def inputs_dir(tmp_path, bom, config, shipped_profile_files, secrets_dir, fake_env):
    """A complete /run/saw tree built from the real chart files."""
    root = tmp_path / "run-saw"
    installer = root / "installer"
    installer.mkdir(parents=True)
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/example/nemoclaw-cli@sha256:" + "e" * 64}
    (installer / "installer-bom.yaml").write_text(yaml.safe_dump(bom))
    (installer / "config.json").write_text(json.dumps(config))
    (installer / "apply_bom.py").write_text(SCRIPT.read_text())
    for name in ("tool-actions.yaml", "tool-gate.mjs", "tool-gate-plugin.mjs"):
        (installer / name).write_text((SCRIPT.parent / name).read_text())
    for name in ("saw-gateway-pki", "openshell-gateway-pki.conf"):
        (installer / name).write_text((CHART / "files" / "guest" / name).read_text())
    (installer / "gateway.env").write_text(GATEWAY_ENV)
    (installer / "gateway.toml").write_text(GATEWAY_TOML)
    (installer / "setup-dashboard.sh").write_text(
        (CHART / "files" / "installer" / "setup-dashboard.sh").read_text())
    proxy_ca = root / "proxy-ca"
    proxy_ca.mkdir()
    (proxy_ca / "ca.crt").write_bytes((fake_env.home / ".local/state/openshell/tls/ca.crt").read_bytes())
    profiles = root / "profiles"
    profiles.mkdir()
    for key, text in shipped_profile_files.items():
        (profiles / key).write_text(text)
    for key, raw in harness_files().items():
        (profiles / key).write_text(base64.b64encode(raw).decode())
    (profiles / "harness-index.yaml").write_text(yaml.safe_dump({
        "bundles": {"ds-default": tree_digest_of_shipped_bundle()}}))
    secrets_dir.rename(root / "secrets")
    return root
