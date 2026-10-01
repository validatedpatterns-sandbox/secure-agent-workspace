"""scripts/apf-bundle.py: translation, signing and the bundle layout APF reads."""
import base64
import hashlib
import importlib.util
import io
import shutil
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "apf-bundle.py"

pytest.importorskip("cryptography")


def load_script(policy_dir=None, apf_dir=None, seed=None):
    """The script as a module; with paths, it works on copies under tmp."""
    spec = importlib.util.spec_from_file_location(f"apf_bundle_{id(seed)}", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if policy_dir is not None:
        if not Path(policy_dir).exists():
            shutil.copytree(ROOT / "charts" / "governance-policy", policy_dir)
        mod.ROOT = Path(policy_dir).parent
        mod.POLICY_DIR = Path(policy_dir)
        mod.APF_DIR = Path(apf_dir)
        mod.BUNDLE = mod.APF_DIR / "bundle.tar.gz"
        mod.PUBKEY = mod.APF_DIR / "apf.pub"
        mod.SEED = Path(seed)
    return mod


class Args:
    def __init__(self, **kw):
        self.force = self.bump = self.integrity_only = False
        self.__dict__.update(kw)


@pytest.fixture
def work(tmp_path):
    mod = load_script(tmp_path / "governance-policy", tmp_path / "chart" / "files" / "apf",
                      tmp_path / "keys" / "apf.seed")
    mod.cmd_keygen(Args())
    return mod


def members(mod):
    return mod.unpack(mod.BUNDLE)


def manifest(mod):
    body, sig = mod.split_signed(members(mod)["bundle.yaml"].decode())
    return yaml.safe_load(body), sig, body


def test_keygen_keeps_the_seed_out_of_the_chart(work):
    assert work.SEED.stat().st_mode & 0o777 == 0o600
    assert not list(work.APF_DIR.glob("*.seed"))
    assert work.PUBKEY.read_text().splitlines()[-1].startswith("ed25519:")
    with pytest.raises(SystemExit):
        work.cmd_keygen(Args())          # no silent key replacement


def test_bundle_layout_matches_the_apf_chart(work):
    work.cmd_build(Args())
    with tarfile.open(work.BUNDLE, "r:gz") as tar:
        names = tar.getnames()
    # The chart's init container untars as non-root: no "./" entries.
    assert not [n for n in names if n.startswith(("./", "/"))]
    profiles = sorted(p.name for p in (work.POLICY_DIR / "profiles").glob("*.yaml")
                      if not work.unsupported(yaml.safe_load(p.read_text())))
    assert sorted(names) == sorted(["bundle.yaml", "sandbox/default-policy.yaml"]
                                   + [f"provider-profiles/{p}" for p in profiles])


def test_manifest_lists_every_member_with_its_digest(work):
    work.cmd_build(Args())
    files = members(work)
    doc, sig, _ = manifest(work)
    assert doc["apiVersion"] == "nvidia.agent-policy-fabric.policy/v1alpha1"
    assert doc["kind"] == "PolicyBundle" and doc["policy_revision"] == 1
    listed = {m["path"]: m["sha256"] for m in doc["manifest"]}
    assert set(listed) == set(files) - {"bundle.yaml"}
    for path, digest in listed.items():
        assert hashlib.sha256(files[path]).hexdigest() == digest
    assert sig["schema"] == "YamlSigilSignature.v1alpha1"
    assert sig["alg"] == "ED25519_PUREEDDSA_RAW_RS64_CANONICAL"
    assert sig["keyid"] == "apf-dev"


def test_signature_covers_the_manifest_bytes(work):
    """apf-compile genfixture signs the manifest document's bytes (up to and
    including its last newline) and appends the signature document."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    work.cmd_build(Args())
    _, sig, body = manifest(work)
    assert body.endswith("\n")
    pub = Ed25519PublicKey.from_public_bytes(work.read_key(work.PUBKEY))
    raw = base64.urlsafe_b64decode(sig["signature"] + "==")
    pub.verify(raw, body.encode())
    assert "=" not in sig["signature"]      # unpadded base64url
    assert work.verify(policy_dir=work.POLICY_DIR) == []


def test_translation_keeps_what_openshell_needs(work):
    work.cmd_build(Args())
    files = members(work)
    policy = yaml.safe_load(files["sandbox/default-policy.yaml"])
    source = yaml.safe_load((work.POLICY_DIR / "policy.yaml").read_text())
    assert (policy["apiVersion"], policy["kind"]) == ("nvidia.agent-policy-fabric.sandbox/v1alpha1", "SandboxPolicy")
    assert policy["spec"]["filesystem"] == source["filesystem_policy"]
    assert policy["spec"]["process"] == source["process"]
    assert policy["spec"]["landlock"] == source["landlock"]
    # No network_middlewares: that is tier 2, which SAW does not run.
    assert "network_middlewares" not in policy["spec"]

    openai = yaml.safe_load(files["provider-profiles/openai.yaml"])
    assert openai["kind"] == "Provider" and openai["metadata"]["name"] == "openai"
    assert openai["spec"]["type"] == "openai"
    # OpenShell 0.1.x: no inference routing, so the profile names the host and
    # the binaries that may call it.
    assert [e["host"] for e in openai["spec"]["endpoints"]] == ["api.openai.com"]
    assert "/usr/bin/node-*" in openai["spec"]["binaries"]
    assert openai["spec"]["credentials"][0] == {
        "name": "api_key", "envVars": ["OPENAI_API_KEY"], "required": True,
        "style": "bearer", "header": "authorization"}
    # A profile without provider_type: its id is the type users create.
    brave = yaml.safe_load(files["provider-profiles/brave.yaml"])
    assert brave["spec"]["type"] == "brave"
    assert brave["spec"]["binaries"][0] == "/usr/bin/curl"


def test_profiles_apf_cannot_express_stay_out(work, capsys):
    """Query-auth credentials have no place for the parameter name in APF, and
    OpenShell rejects the whole catalog without it (seen live with gemini)."""
    work.cmd_build(Args())
    assert "provider-profiles/gemini.yaml" not in members(work)
    assert "leaving out gemini.yaml: credential 'api_key' uses query auth" in capsys.readouterr().err
    assert "provider-profiles/nvidia.yaml" in members(work)
    assert work.verify(policy_dir=work.POLICY_DIR) == []


def test_providers_use_only_fields_apf_accepts(work):
    """APF 0.2.0 refuses the whole bundle on an unknown field, e.g.
    'spec: unknown field `category`, expected one of type, endpoints,
    binaries, credentials' (seen live)."""
    work.cmd_build(Args())
    files = members(work)
    for path, data in files.items():
        if not path.startswith("provider-profiles/"):
            continue
        doc = yaml.safe_load(data)
        assert set(doc) == {"apiVersion", "kind", "metadata", "spec"}, path
        assert set(doc["metadata"]) <= {"name", "title", "description"}, path
        assert set(doc["spec"]) <= {"type", "endpoints", "binaries", "credentials"}, path
        for cred in doc["spec"].get("credentials", []):
            assert set(cred) <= {"name", "envVars", "required", "style", "header"}, path


def test_rebuild_is_idempotent_and_bumps_the_revision_on_change(work, capsys):
    work.cmd_build(Args())
    first = work.BUNDLE.read_bytes()
    work.cmd_build(Args())
    assert work.BUNDLE.read_bytes() == first
    assert "up to date" in capsys.readouterr().out
    (work.POLICY_DIR / "profiles" / "brave.yaml").write_text(
        (work.POLICY_DIR / "profiles" / "brave.yaml").read_text().replace("display_name: Brave Search", "display_name: Brave"))
    assert work.verify(policy_dir=work.POLICY_DIR) == [
        "out of date with charts/governance-policy; run `make apf-bundle`"]
    work.cmd_build(Args())
    assert manifest(work)[0]["policy_revision"] == 2
    assert work.verify(policy_dir=work.POLICY_DIR) == []


def test_verify_catches_tampering(work):
    work.cmd_build(Args())
    files = members(work)
    files["provider-profiles/github.yaml"] = files["provider-profiles/github.yaml"].replace(
        b"access: read-only", b"access: read-write", 1)
    work.BUNDLE.write_bytes(work.pack(files))
    assert work.verify(policy_dir=work.POLICY_DIR, check_current=False) == [
        "provider-profiles/github.yaml: sha256 mismatch"]


def test_build_refuses_a_seed_for_another_public_key(work, tmp_path):
    other = load_script(tmp_path / "governance-policy", tmp_path / "other", tmp_path / "keys" / "other.seed")
    other.cmd_keygen(Args())
    work.SEED = other.SEED
    with pytest.raises(SystemExit, match="does not match"):
        work.cmd_build(Args())


def test_profile_ids_must_match_file_names(work):
    path = work.POLICY_DIR / "profiles" / "brave.yaml"
    path.write_text(path.read_text().replace("id: brave", "id: brave-search"))
    with pytest.raises(SystemExit, match="id must match"):
        work.cmd_build(Args())


# -- scripts/governance-apf.sh (quickstart) ---------------------------------------

import os  # noqa: E402
import subprocess  # noqa: E402


def run_quickstart(tmp_path, **env):
    full = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), **env}
    return subprocess.run(["bash", str(ROOT / "scripts" / "governance-apf.sh")],
                          capture_output=True, text=True, env=full)


def test_quickstart_needs_ghcr_credentials(tmp_path):
    result = run_quickstart(tmp_path)
    assert result.returncode != 0
    assert "GHCR_USER and GHCR_TOKEN" in result.stderr


def test_quickstart_needs_the_signing_seed(tmp_path):
    result = run_quickstart(tmp_path, GHCR_USER="u", GHCR_TOKEN="t")
    assert result.returncode != 0
    assert "make apf-keys" in result.stderr
