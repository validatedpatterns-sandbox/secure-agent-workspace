"""Render the openshell-gateway-image BuildConfig and check what gets baked
into the golden image for signing (PR #54 review)."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "image-builder-charts" / "helm" / "openshell-gateway-image"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def render(*args):
    result = subprocess.run(
        [HELM, "template", "gw-test", str(CHART), "--namespace", "openshell-agents", *args],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return list(yaml.safe_load_all(result.stdout))


def dockerfile(*args):
    docs = render(*args)
    build = next(d for d in docs if d["kind"] == "BuildConfig")
    return build["spec"]["source"]["dockerfile"]


def test_cosign_download_is_checksum_verified():
    """A curl with no integrity check would let a compromised release URL
    bake a malicious cosign into every image; cosign is what verify-bundle
    trusts to say the installer is genuine (PR #54 review, 7)."""
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    sha256 = values["cosign"]["sha256"]
    assert len(sha256) == 64
    text = dockerfile()
    assert "curl -fsSL -o /build/saw/cosign" in text
    assert f"echo \"{sha256}  /build/saw/cosign\" | sha256sum -c -" in text
    # The checksum check must run before the binary is trusted/used.
    assert text.index("sha256sum -c") > text.index("curl -fsSL -o /build/saw/cosign")


def test_podman_signed_pull_and_static_enforce_policy_are_gone():
    """Replaced by apply_bom.py generating a per-pull policy.json from the
    BOM's own signature field: the old static, single-registry enforce.json
    and the global-policy-swapping podman-signed-pull helper are no longer
    baked into the image at all (PR #54 review, 4, 5)."""
    text = dockerfile()
    assert "podman-signed-pull" not in text
    assert "enforce.json" not in text
    assert "/etc/saw/policy" not in text


def test_verify_bundle_and_trust_dir_are_still_baked_in():
    text = dockerfile()
    assert "/usr/libexec/saw/verify-bundle" in text
    assert "/etc/saw/trust" in text
    assert "/etc/containers/registries.d" in text


def test_no_signing_floor_by_default():
    """Empty signing.floor (the chart default) must not bake anything into
    /etc/saw/signing-mode: absent = no floor, matching config.json alone
    deciding the mode, which is today's documented behavior."""
    text = dockerfile()
    assert "signing-mode" not in text


def test_signing_floor_is_baked_in_when_set():
    """The golden image can pin a minimum signing.mode at
    /etc/saw/signing-mode; config.json (in the namespace-editable installer
    ConfigMap) can only tighten it, never loosen it below this floor
    (PR #54 review round 2, 1: nothing used to write this file at all)."""
    text = dockerfile("--set", "signing.floor=enforce")
    assert "printf '%s' \"enforce\" > /build/saw/signing-mode" in text
    assert "--copy-in /build/saw/signing-mode:/etc/saw/" in text
    # The floor is written before it is copied into the image.
    assert text.index("signing-mode") < text.index("--copy-in /build/saw/signing-mode")


def test_invalid_signing_floor_fails_the_render():
    result = subprocess.run(
        [HELM, "template", "gw-test", str(CHART), "--namespace", "openshell-agents",
         "--set", "containerRuntime=podman", "--set", "signing.floor=bogus"],
        capture_output=True, text=True)
    assert result.returncode != 0
    assert "signing.floor must be off, warn, enforce, or empty" in result.stderr


def test_public_key_is_baked_into_the_trust_directory(tmp_path):
    key = tmp_path / "test.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n")
    text = dockerfile("--set-file", f"signing.publicKeys.test={key}")
    assert "RUN mkdir -p /build/saw/trust" in text
    assert "> /build/saw/trust/test.pub" in text
    assert "--copy-in /build/saw/trust:/etc/saw/" in text
    assert text.index("/build/saw/trust/test.pub") < text.index("--copy-in /build/saw/trust:/etc/saw/")


def test_public_key_name_is_validated(tmp_path):
    key = tmp_path / "test.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n")
    result = subprocess.run(
        [HELM, "template", "gw-test", str(CHART), "--set-file", f"signing.publicKeys.bad_name={key}"],
        capture_output=True, text=True)
    assert result.returncode != 0
    assert "must be a lowercase key label" in result.stderr


def test_build_can_request_disk_and_select_a_worker():
    docs = render("--set", "build.ephemeralStorageRequest=12Gi",
                  "--set", "build.nodeSelector.kubernetes\\.io/hostname=worker-example")
    build = next(d for d in docs if d["kind"] == "BuildConfig")
    assert build["spec"]["resources"]["requests"]["ephemeral-storage"] == "12Gi"
    assert build["spec"]["nodeSelector"] == {"kubernetes.io/hostname": "worker-example"}


def test_the_two_verify_bundle_copies_are_identical():
    """verify-bundle exists twice: charts/openshell-saw/files/guest (cloud-init
    delivered, used by the offline installer tests) and this chart's files/
    (baked into the golden image at build time -- what actually runs). A fix
    applied to only one silently never reaches a real VM: found live during
    PR #54's review response, where signing.mode: warn correctly ran
    verify-bundle but the golden image still had the pre-fix script, so the
    staged copy apply_bom.py was supposed to run from was never published."""
    saw_copy = (ROOT / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle").read_text()
    image_copy = (CHART / "files" / "verify-bundle").read_text()
    assert saw_copy == image_copy, (
        "charts/openshell-saw/files/guest/verify-bundle and "
        "image-builder-charts/helm/openshell-gateway-image/files/verify-bundle "
        "have drifted; the golden image bakes in the second one, so a fix to "
        "only the first never actually ships")
