"""OpenShell 0.1.x: what the installer does differently from 0.0.x.

- the BOM carries the sandbox runtime image (required, image only, nothing
  extracted), and every component comes from the same release;
- a 0.0.x -> 0.1.x gateway change recreates gateway state and sandboxes,
  because 0.1.0 cannot upgrade 0.0.x state in place, and a retry after an
  interrupted run still does it (tests/installer/test_cli.py);
- gateway.env drops keys 0.1.x no longer reads;
- the 0.1.x "profile was not found" error still skips the provider;
- a 0.0.x inference route left in the ledger is forgotten, not deleted.
"""
import json

import pytest

from test_apply_profiles import creds, make_applier, profiles  # noqa: F401 (fixtures)

SANDBOX_IMAGE = "quay.io/opendatahub/odh-openshell-sandbox@sha256:" + "5" * 64


@pytest.fixture
def installer(ab, tmp_path, fake_env):
    return ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state" / "installed.json",
                                 podman="podman", opt_dir=tmp_path / "opt")


def with_sandbox(bom):
    bom["spec"]["openshell"]["sandbox"] = {
        "version": bom["spec"]["openshell"]["gateway"]["version"], "image": SANDBOX_IMAGE}
    return bom


def test_the_sandbox_runtime_image_is_required(ab, bom):
    del bom["spec"]["openshell"]["sandbox"]
    with pytest.raises(ab.InstallerError, match="missing sandbox"):
        ab.validate_bom(bom)


def test_components_from_different_releases_are_refused(ab, bom):
    bom["spec"]["openshell"]["cli"]["version"] = "0.1.1"
    with pytest.raises(ab.InstallerError, match="same version"):
        ab.validate_bom(bom)


def test_the_sandbox_runtime_image_is_image_only(ab, installer, bom, fake_env):
    with_sandbox(bom)
    ab.validate_bom(bom)
    fake_env.images_for_bom(bom)
    assert "sandbox" in installer.install(bom)
    assert not (installer.bin_dir / "sandbox").exists()
    assert ["pull", "--quiet", SANDBOX_IMAGE] in fake_env.podman_calls()
    state = json.loads(installer.state_file.read_text())
    assert state["components"]["sandbox"]["image"] == SANDBOX_IMAGE
    assert "sandbox" not in installer.install(bom), "an unchanged image is not pulled again"


def test_the_sandbox_image_must_be_pinned(ab, bom):
    with_sandbox(bom)["spec"]["openshell"]["sandbox"]["image"] = "quay.io/x/sandbox:latest"
    with pytest.raises(ab.InstallerError, match="spec.openshell.sandbox.image must be pinned"):
        ab.validate_bom(bom)


@pytest.mark.parametrize("old,new,reset", [
    ("0.0.116-rhaiv.0", "0.1.2-rhaiv.0", True),
    ("0.1.1", "0.1.2-rhaiv.0", False),
    ("0.0.115", "0.0.116-rhaiv.0", False),
    (None, "0.1.2-rhaiv.0", False),            # first install: nothing to reset
])
def test_only_a_new_release_series_resets_state(ab, old, new, reset):
    assert ab.needs_state_reset(old, new) is reset


def test_reset_removes_sandboxes_and_keeps_a_backup(ab, tmp_path, fake_env, monkeypatch):
    home = tmp_path / "home"
    state = home / ".local" / "state" / "openshell" / "gateway"
    state.mkdir(parents=True, exist_ok=True)
    (state / "openshell.db").write_text("old")
    tls = home / ".local" / "state" / "openshell" / "tls"
    tls.mkdir(exist_ok=True)
    calls = []

    class Recorder(ab.Shell):
        def run(self, argv, **kw):
            calls.append(argv)
            if "ps" in argv:
                return ab.Result(0, "openshell-default--notebook-1\nopenshell-cuda-dev--cuda-sandbox-2\n")
            if "volume" in argv:
                return ab.Result(0, "openshell-sandbox-1-workspace\nother\n")
            return ab.Result(0)

    ab.reset_gateway_state(Recorder(), lambda argv: argv, home, "0.0.116-rhaiv.0", "0.1.2-rhaiv.0")
    assert ["systemctl", "--user", "stop", "openshell-gateway.service"] in calls
    assert ["podman", "rm", "-f", "openshell-default--notebook-1",
            "openshell-cuda-dev--cuda-sandbox-2"] in calls
    ps = next(c for c in calls if "ps" in c)
    assert "label=openshell.ai/sandbox-name" in ps
    assert not state.exists() and tls.exists()
    backups = list(state.parent.glob("gateway.0.0.116-rhaiv.0.*"))
    assert len(backups) == 1 and (backups[0] / "openshell.db").read_text() == "old"


def test_retired_env_keys_are_dropped(ab):
    chart = "OPENSHELL_COMPUTE_DRIVER=podman\nOPENSHELL_SERVER_PORT=17670\n"
    current = ("OPENSHELL_DRIVERS=podman\nOPENSHELL_SERVER_PORT=17670\n"
               "OPENSHELL_CONFIG_FILE=/etc/openshell/gateway.toml\nOPENSHELL_SSH_GATEWAY_PORT=17670\n"
               "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock\n")
    merged = ab.merge_user_env(chart, current)
    assert "OPENSHELL_DRIVERS" not in merged and "OPENSHELL_CONFIG_FILE" not in merged
    assert "OPENSHELL_SSH_GATEWAY_PORT" not in merged
    assert "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock" in merged


def test_the_01_missing_profile_message_is_recognized(ab):
    assert ab.NO_PROFILE_RE.search(
        "provider profile 'brave' was not found in the requested scope; import a matching "
        "profile before creating this provider")


def test_a_00x_inference_route_in_the_ledger_is_forgotten(ab, tmp_path):
    path = tmp_path / "managed.json"
    path.write_text(json.dumps({"version": 1, "adopted": True, "objects": [
        {"kind": "inference", "workspace": "default", "name": "route", "profile": "p"},
        {"kind": "provider", "workspace": "default", "name": "nvidia", "profile": "p"}]}))
    ledger = ab.Ledger(path)
    assert [o["kind"] for o in ledger.data["objects"]] == ["provider"]


@pytest.mark.parametrize("url", ['http://h/v1$(id)', 'http://h/v1"`id`"', "http://h/v1;id"])
def test_a_base_url_with_shell_characters_is_refused(ab, url):
    with pytest.raises(ValueError):
        ab.check_base_url(url)


def test_onboarding_quotes_what_comes_from_profiles(ab, fake_env, config, profiles, creds):
    for _, ws in ab.enabled_workspaces(profiles):
        for sb in ws.sandboxes:
            if sb.name == "notebook":
                sb.model = "my model's/v1"
    make_applier(ab, config, creds).apply(profiles)
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "onboard" in c[-1] and "notebook" in c)
    assert "--custom-model-id 'my model'\"'\"'s/v1'" in onboard


def test_an_unknown_provider_type_still_gets_the_keepalive(ab, fake_env, config, profiles, creds):
    for _, ws in ab.enabled_workspaces(profiles):
        for p in ws.providers:
            if p.name == "nvidia":
                p.type = "gemini"
    creds = {ws: {n: v for n, v in c.items()} for ws, c in creds.items()}
    make_applier(ab, config, creds).apply(profiles)
    units = [c for c in fake_env.other_calls("sudo") if "tee" in c["args"]]
    assert any("openshell-sandbox-notebook" in " ".join(c["args"]) for c in units)


# -- caBundle: the issuer CA, for the gateway and the oauth2-proxies only ------------

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    """A real CA, a leaf it signed, and the leaf's key (openssl)."""
    import subprocess
    d = tmp_path_factory.mktemp("certs")

    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=d)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-days", "2", "-subj", "/CN=ingress-operator@1", "-addext", "basicConstraints=critical,CA:TRUE")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
        "-subj", "/CN=*.apps.example.com")
    (d / "ext").write_text("basicConstraints=CA:FALSE\nsubjectAltName=DNS:*.apps.example.com\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "leaf.pem", "-days", "2", "-extfile", "ext")
    return {n: (d / f).read_text().strip() for n, f in
            (("ca", "ca.pem"), ("leaf", "leaf.pem"), ("key", "leaf.key"))}


def _ca_shell(ab, calls):
    class Recorder(ab.Shell):
        def run(self, argv, **kw):
            calls.append(argv)
            return ab.Result(0)
    return Recorder()


@pytest.fixture
def trust_env(ab, tmp_path, monkeypatch):
    """The system trust paths of a VM, under tmp_path."""
    system = tmp_path / "system" / "tls-ca-bundle.pem"
    system.parent.mkdir()
    system.write_text("-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(ab, "SYSTEM_CA_BUNDLE", system)
    monkeypatch.setattr(ab, "LEGACY_CA_ANCHOR", tmp_path / "anchors" / "saw-ca-bundle.crt")
    home = tmp_path / "home"
    return home, system


def test_the_issuer_ca_reaches_the_gateway_but_not_the_system_store(ab, certs, trust_env):
    """The ingress CA has no name constraints: in the system store a
    certificate it signed for quay.io would verify for podman. Only the
    gateway (SSL_CERT_FILE, in a drop-in) and the proxies get it."""
    home, system = trust_env
    calls = []
    bundle = certs["leaf"] + "\n" + certs["ca"]        # what default-ingress-cert holds
    assert ab.trust_issuer_ca(_ca_shell(ab, calls), bundle, home) is True
    ca_file, trust_file = ab.issuer_trust_paths(home)
    assert ca_file.read_text() == certs["ca"] + "\n"      # the leaf is dropped
    assert trust_file.read_text() == system.read_text() + certs["ca"] + "\n"
    assert (home / ab.TRUST_DROPIN).read_text() == \
        f"[Service]\nEnvironment=SSL_CERT_FILE={trust_file}\n"
    assert calls == []                                  # the system store is untouched
    assert not ab.LEGACY_CA_ANCHOR.exists()
    # Unchanged: nothing to do, no restart owed.
    assert ab.trust_issuer_ca(_ca_shell(ab, calls), bundle, home) is False


def test_an_emptied_bundle_removes_the_gateways_trust(ab, certs, trust_env):
    home, _ = trust_env
    ab.trust_issuer_ca(_ca_shell(ab, []), certs["ca"], home)
    assert ab.trust_issuer_ca(_ca_shell(ab, []), "", home) is True
    assert not any(p.exists() for p in (*ab.issuer_trust_paths(home), home / ab.TRUST_DROPIN))
    assert ab.trust_issuer_ca(_ca_shell(ab, []), "", home) is False


def test_the_system_wide_anchor_of_older_releases_is_removed(ab, certs, trust_env):
    home, _ = trust_env
    ab.LEGACY_CA_ANCHOR.parent.mkdir(parents=True)
    ab.LEGACY_CA_ANCHOR.write_text(certs["ca"] + "\n")
    calls = []
    assert ab.trust_issuer_ca(_ca_shell(ab, calls), certs["ca"], home) is True
    assert not ab.LEGACY_CA_ANCHOR.exists()
    assert calls == [["update-ca-trust", "extract"]]


def test_a_bundle_with_a_private_key_is_refused(ab, certs, trust_env):
    """Pasting the ingress TLS Secret instead of its ca-bundle.crt would put
    the key into config.json and a world-readable file."""
    home, _ = trust_env
    with pytest.raises(ab.InstallerError, match="private key"):
        ab.trust_issuer_ca(_ca_shell(ab, []), certs["ca"] + "\n" + certs["key"], home)
    assert not ab.issuer_trust_paths(home)[0].exists()


def test_a_bundle_without_a_ca_is_refused(ab, certs, trust_env):
    home, _ = trust_env
    with pytest.raises(ab.InstallerError, match="no CA certificate"):
        ab.trust_issuer_ca(_ca_shell(ab, []), certs["leaf"], home)
    with pytest.raises(ab.InstallerError, match="not a PEM"):
        ab.trust_issuer_ca(_ca_shell(ab, []), "not a cert", home)
    with pytest.raises(ab.InstallerError, match="cannot be parsed"):
        ab.trust_issuer_ca(_ca_shell(ab, []), PEM, home)


def test_the_ca_bundle_comes_from_config_or_the_cluster_ca_secret(ab, tmp_path):
    """caBundle wins; else caBundleSecret's ca-bundle.crt (the cluster's
    ingress CA, mounted like a provider Secret); else nothing."""
    secrets = tmp_path / "secrets"
    (secrets / "saw-ingress-ca").mkdir(parents=True)
    (secrets / "saw-ingress-ca" / "ca-bundle.crt").write_text(PEM + "\n")
    assert ab.configured_ca_bundle({"caBundleSecret": "saw-ingress-ca"}, secrets) == PEM
    assert ab.configured_ca_bundle({"caBundle": "X", "caBundleSecret": "saw-ingress-ca"}, secrets) == "X"
    assert ab.configured_ca_bundle({}, secrets) == ""


def test_a_missing_cluster_ca_secret_fails_install(ab, tmp_path):
    """Not mounted yet: fail (install retries at the next boot) rather than
    start a gateway that cannot verify the issuer."""
    with pytest.raises(ab.InstallerError, match="saw-ingress-ca is not mounted"):
        ab.configured_ca_bundle({"caBundleSecret": "saw-ingress-ca"}, tmp_path)
    with pytest.raises(ab.InstallerError, match="invalid caBundleSecret"):
        ab.configured_ca_bundle({"caBundleSecret": "../etc"}, tmp_path)


def test_sandbox_ui_proxies_verify_the_issuer_with_the_issuer_ca_only(ab, tmp_path):
    """The proxy's calls to the issuer use the CA (provider CA files); its
    system store stays the image's public CAs. Without a CA: neither."""
    cfg = {"oidcIssuer": "https://kc.example.com/realms/openshell",
           "sandboxUi": [{"workspace": "ws", "sandbox": "sb", "host": "h.example.com",
                          "proxyPort": 18800, "forwardPort": 18900, "portName": "ui-0"}],
           "sandboxUiProxy": {"allowedUsers": ["alice"]}}
    ca = tmp_path / "issuer-ca.pem"
    units, files = ab.sandbox_ui_units(cfg, tmp_path, "cookie", "saw-installer", ca)
    (proxy,) = [t for n, t in units.items() if n.startswith("saw-ui-proxy-")]
    (env,) = [t for p, t in files.items() if str(p).endswith(".env")]
    assert f"-v {ca}:/etc/saw/issuer-ca.pem:ro,z " in proxy
    assert "/etc/ssl/certs" not in proxy
    assert "OAUTH2_PROXY_PROVIDER_CA_FILES=/etc/saw/issuer-ca.pem" in env
    units, files = ab.sandbox_ui_units(cfg, tmp_path, "cookie", "saw-installer")
    (proxy,) = [t for n, t in units.items() if n.startswith("saw-ui-proxy-")]
    (env,) = [t for p, t in files.items() if str(p).endswith(".env")]
    assert "issuer-ca" not in proxy and "PROVIDER_CA_FILES" not in env


def test_an_untrusted_issuer_fails_install_with_the_fix(ab):
    """The gateway only says "OIDC discovery request failed" and exits, and
    install then times out on its port. Check first and name the fix."""
    import ssl
    from urllib.error import URLError

    def untrusted(url, timeout, context=None):
        err = ssl.SSLCertVerificationError(1, "certificate verify failed")
        err.verify_message = "self-signed certificate in certificate chain"
        raise URLError(err)

    with pytest.raises(ab.InstallerError) as exc:
        ab.check_issuer_trusted("https://kc.apps.example.com/realms/openshell", opener=untrusted)
    msg = str(exc.value)
    assert "\n" not in msg      # install's status keeps the first line only
    assert "self-signed certificate in certificate chain" in msg
    assert "oidc.caBundle" in msg and "default-ingress-cert" in msg


def test_other_issuer_failures_only_warn(ab, capsys):
    from urllib.error import URLError

    def unreachable(url, timeout, context=None):
        raise URLError("Name or service not known")

    class Ok:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"{"

    ab.check_issuer_trusted("https://kc.example.com/realms/openshell", opener=unreachable)
    assert "WARN: cannot reach the OIDC issuer" in capsys.readouterr().out
    seen = []
    ab.check_issuer_trusted("https://kc.example.com/realms/openshell/",
                            opener=lambda url, timeout, context=None: seen.append(url) or Ok())
    assert seen == ["https://kc.example.com/realms/openshell/.well-known/openid-configuration"]
    ab.check_issuer_trusted("", opener=unreachable)     # no issuer: nothing to check


@pytest.fixture(scope="module")
def issuer(tmp_path_factory):
    """A real HTTPS issuer on 127.0.0.1 whose certificate a test CA signed,
    plus an unrelated CA. Yields (issuer URL, its CA, the other CA)."""
    import http.server
    import ssl
    import subprocess
    import threading
    d = tmp_path_factory.mktemp("issuer")

    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=d)
    # Shaped like OpenShift's ingress CA and certificate: Python 3.13+
    # verifies with VERIFY_X509_STRICT, which wants key usage on the CA and
    # an authority key identifier on the leaf.
    for name in ("ca", "other"):
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
            "-out", f"{name}.pem", "-days", "2", "-subj", f"/CN={name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
            "-addext", "subjectKeyIdentifier=hash")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr",
        "-subj", "/CN=127.0.0.1")
    (d / "ext").write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                           "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
                           "authorityKeyIdentifier=keyid\nsubjectAltName=IP:127.0.0.1\n")
    run("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "srv.pem", "-days", "2", "-extfile", "ext")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "srv.pem", d / "srv.key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield (f"https://127.0.0.1:{server.server_address[1]}/realms/openshell",
           (d / "ca.pem").read_text(), (d / "other.pem").read_text())
    server.shutdown()


def test_the_issuer_ca_is_installed_only_when_it_signs_the_issuer(ab, issuer, tmp_path):
    """Verified with the extra CA alone, over a real TLS connection."""
    url, ca, other = issuer
    assert ab.select_issuer_ca(url, ca) == ca
    # Neither the extra CA nor the public CAs verify it: fail with the fix.
    with pytest.raises(ab.InstallerError, match="does not sign the OIDC issuer"):
        ab.select_issuer_ca(url, other)


def test_a_publicly_trusted_issuer_gets_no_extra_ca(ab, issuer, tmp_path):
    """The automatic cluster CA on a cluster whose *.apps certificate is
    public: the extra CA signs nothing there and would only widen the
    gateway's trust, so it is not installed. ("Public" is the test CA here.)"""
    url, ca, other = issuer
    public = tmp_path / "public.pem"
    public.write_text(ca)
    assert ab.select_issuer_ca(url, other, public_cafile=public) == ""


def test_the_gateway_check_connects_with_the_installed_trust(ab, issuer, tmp_path):
    url, ca, other = issuer
    trust = tmp_path / "issuer-trust.pem"
    trust.write_text(ca)
    ab.check_issuer_trusted(url, cafile=trust)          # verifies
    trust.write_text(other)
    with pytest.raises(ab.InstallerError, match="cannot verify the OIDC issuer"):
        ab.check_issuer_trusted(url, cafile=trust)


def test_an_unreachable_issuer_keeps_the_configured_ca(ab, issuer, capsys):
    from urllib.error import URLError
    _, ca, _ = issuer

    def unreachable(url, timeout, context=None):
        raise URLError("Name or service not known")
    assert ab.select_issuer_ca("https://kc.example.com/realms/x", ca, opener=unreachable) == ca
    assert "cannot reach the OIDC issuer" in capsys.readouterr().out
    assert ab.select_issuer_ca("", ca) == ca
