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
    text = dockerfile()
    # One URL and checksum per architecture; the build picks by `uname -m`.
    for arch, entry in (("x86_64", values["cosign"]), ("aarch64", values["cosign"]["aarch64"])):
        assert len(entry["sha256"]) == 64
        assert f'{arch}) url="{entry["url"]}"; sum="{entry["sha256"]}" ;;' in text
    assert 'curl -fsSL -o /build/saw/cosign "$url"' in text
    assert 'echo "$sum  /build/saw/cosign" | sha256sum -c -' in text
    # The checksum check must run before the binary is trusted/used.
    assert text.index("sha256sum -c") > text.index("curl -fsSL -o /build/saw/cosign")
    assert text.index("sha256sum -c") < text.index("/build/saw/cosign:/usr/local/bin/")


def test_the_base_image_matches_the_build_architecture():
    """KubeVirt runs only guests of the host's architecture: an arm64 cluster
    builds from the aarch64 Fedora Cloud image."""
    values = yaml.safe_load((CHART / "values.yaml").read_text())["build"]
    text = dockerfile()
    assert "/x86_64/" in values["fedoraCloud"] and "/aarch64/" in values["fedoraCloudAarch64"]
    assert f'x86_64) url="{values["fedoraCloud"]}" ;;' in text
    assert f'aarch64) url="{values["fedoraCloudAarch64"]}" ;;' in text
    assert 'unsupported architecture' in text


def test_ci_picks_fedora_and_cosign_by_runner_architecture():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-openshell-gateway.yml").read_text())
    params = next(s["run"] for s in workflow["jobs"]["build"]["steps"] if s.get("id") == "params")
    assert 'case "$(uname -m)" in' in params and "unsupported architecture" in params
    for key in (".build.fedoraCloud'", ".build.fedoraCloudAarch64'", ".cosign.url'",
                ".cosign.sha256'", ".cosign.aarch64.url'", ".cosign.aarch64.sha256'"):
        assert key in params


def test_ci_builds_podman_on_both_architectures_and_docker_on_amd64():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-openshell-gateway.yml").read_text())
    build = workflow["jobs"]["build"]
    matrix = build["strategy"]["matrix"]
    assert matrix["container_runtime"] == ["docker", "podman"]
    assert matrix["platform"] == ["linux/amd64", "linux/arm64"]
    excluded = {(e["container_runtime"], e["platform"]) for e in matrix["exclude"]}
    combinations = {(runtime, platform) for runtime in matrix["container_runtime"]
                    for platform in matrix["platform"]} - excluded
    assert combinations == {("docker", "linux/amd64"), ("podman", "linux/amd64"),
                            ("podman", "linux/arm64")}
    assert "ubuntu-24.04-arm" in build["runs-on"]
    push = next(s for s in build["steps"] if s.get("uses") == "./.github/actions/build-push-image")
    assert push["with"]["platform"] == "${{ matrix.container_runtime == 'podman' && matrix.platform || '' }}"
    assert "openshell-gateway-docker" in push["with"]["image_name"]
    assert "openshell-gateway'" in push["with"]["image_name"]
    assert workflow["jobs"]["merge"]["strategy"]["matrix"]["image_name"] == ["openshell-gateway"]


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


def test_ci_installs_verification_tools_in_both_runtime_images():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-openshell-gateway.yml").read_text())
    customizers = [s for s in workflow["jobs"]["build"]["steps"]
                   if s.get("name", "").startswith("Customize guest image")]
    assert len(customizers) == 2
    for step in customizers:
        assert "bash scripts/install-gateway-verification.sh" in step["run"]
        assert "SIGNING_FLOOR" in step["env"] and "COSIGN_SHA256" in step["env"]
        assert step["run"].index("install-gateway-verification.sh") < step["run"].index("sudo guestunmount")
