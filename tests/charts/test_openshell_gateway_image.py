"""Render the openshell-gateway-image BuildConfig and check what gets baked
into the golden image for signing (PR #54 review)."""

import importlib.util
import os
import shutil
import stat
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


def test_nvidia_repos_are_omitted_unless_gpu_enabled():
    text = dockerfile()
    assert "nvidia-container-toolkit" not in text
    assert "nvidia-ctk" not in text
    assert "kmod-nvidia-open-dkms" not in text


def test_gpu_enabled_bakes_podman_cdi_not_a_docker_runtime():
    text = dockerfile("--set", "gpu.enabled=true")
    assert "kmod-nvidia-open-dkms-610.57.04 nvidia-driver-610.57.04 nvidia-driver-cuda-610.57.04 nvidia-container-toolkit" in text
    assert "cuda-fedora44.repo" in text and "cuda-rhel10.repo" in text
    assert "systemctl enable nvidia-driver-setup.service" in text
    assert "saw-gpu-devices.service" in text
    assert "nvidia-ctk runtime configure" not in text


def test_gpu_image_variant_has_distinct_objects():
    docs = render("--set", "gpu.enabled=true")
    names = {(d["kind"], d["metadata"]["name"]) for d in docs}
    assert ("ImageStream", "openshell-gateway-gpu") in names
    assert ("BuildConfig", "openshell-gateway-gpu") in names
    assert ("DataVolume", "openshell-gateway-gpu-golden") in names
    assert ("DataSource", "openshell-gateway-gpu") in names
    assert ("ImageStream", "openshell-gateway") not in names


def test_capability_cdi_numbers_come_from_live_device():
    path = CHART / "files" / "saw-patch-cdi-caps.py"
    spec = importlib.util.spec_from_file_location("saw_patch_cdi_caps", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Device:
        st_mode = stat.S_IFCHR | 0o666
        st_rdev = os.makedev(508, 7)

    class Cap:
        def __str__(self):
            return "/dev/nvidia-caps/nvidia-cap1"

        def stat(self):
            return Device()

    cap = Cap()
    original = "containerEdits:\n  deviceNodes:\n    - path: /dev/nvidiactl\n      major: 195\n      minor: 255\n"
    patched = module.patch_cdi(original, [cap])
    assert "major: 508" in patched and "minor: 7" in patched
    assert module.patch_cdi(patched, [cap]) == patched


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
