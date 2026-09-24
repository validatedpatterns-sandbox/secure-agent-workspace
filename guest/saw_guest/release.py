"""Verify and stage the platform-selected signed guest release bundle.

This module is image-owned bootstrap code.  It never executes files from a
virtiofs mount or a container layer directly: the bundle is pulled by digest,
verified, copied into a root-owned release directory, and only then activated.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import yaml


RELEASE_INPUT = Path("/run/saw/installer/release.yaml")
RELEASE_ROOT = Path("/var/lib/saw/releases")
CURRENT = RELEASE_ROOT / "current"
TRUSTED_KEY = Path("/etc/saw/release-signing-public-key.pem")
MAX_MANIFEST = 128 * 1024


class ReleaseError(ValueError):
    """Safe, non-secret release bootstrap failure."""


def _digest(value):
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise ReleaseError("InvalidReleaseDigest")
    try:
        int(value[7:], 16)
    except ValueError:
        raise ReleaseError("InvalidReleaseDigest") from None
    return value


def load_release(path=RELEASE_INPUT):
    try:
        document = yaml.safe_load(Path(path).read_text())
        if not isinstance(document, dict) or set(document) != {"name", "bundleRef", "bundleDigest", "bom"}:
            raise ValueError
        digest = _digest(document["bundleDigest"])
        if not isinstance(document["bundleRef"], str) or "@" not in document["bundleRef"]:
            raise ValueError
        if document["bundleRef"].rsplit("@", 1)[1] != digest:
            raise ValueError
        if not isinstance(document["bom"], dict):
            raise ValueError
        return document
    except (OSError, ValueError, yaml.YAMLError):
        raise ReleaseError("InvalidReleaseInput") from None


def _safe(path):
    info = path.lstat()
    return info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode)


def _verify_signature(manifest, signature):
    if not TRUSTED_KEY.is_file() or not _safe(TRUSTED_KEY):
        raise ReleaseError("ReleaseTrustKeyUnavailable")
    result = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(TRUSTED_KEY),
         "-signature", str(signature), str(manifest)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15,
    )
    if result.returncode != 0:
        raise ReleaseError("ReleaseSignatureInvalid")


def _verify_tree(root, release):
    manifest = root / "release.json"
    signature = root / "release.json.sig"
    if (root.is_symlink() or not root.is_dir() or not _safe(root) or
            not manifest.is_file() or not signature.is_file() or
            not _safe(manifest) or not _safe(signature) or
            manifest.stat().st_size > MAX_MANIFEST):
        raise ReleaseError("ReleaseManifestMissing")
    _verify_signature(manifest, signature)
    try:
        data = json.loads(manifest.read_text())
        if (not isinstance(data, dict) or set(data) != {"format", "name", "bom", "files"} or
                data.get("format") != 1 or
                data.get("name") != release["name"] or data.get("bom") != release["bom"]):
            raise ValueError
        files = data["files"]
        required = {"openshell", "openshell-gateway", "openshell-supervisor"}
        if not isinstance(files, dict) or set(files) != {"apply_bom.py", "installer-bom.yaml"}:
            raise ValueError
        for name, expected in files.items():
            if (not isinstance(expected, str) or len(expected) != 64 or
                    any(char not in "0123456789abcdef" for char in expected)):
                raise ValueError
            path = root / name
            if not path.is_file() or not _safe(path) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError
        for name in required:
            path = root / name
            if not path.is_file() or not _safe(path):
                raise ValueError
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        raise ReleaseError("ReleaseManifestInvalid") from None


def _pull_bundle(reference, destination):
    # The image has no rootful fallback.  Pull through cloud-user's rootless
    # Podman store, then copy only the verified bundle files as root.
    name = "saw-release-" + reference.rsplit("@", 1)[1][7:19]
    podman_home = Path("/var/lib/saw/release-podman")
    podman_runtime = podman_home / "runtime"
    podman_runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(podman_home, 1000, 1000)
    os.chown(podman_runtime, 1000, 1000)
    env = {"HOME": str(podman_home), "XDG_RUNTIME_DIR": str(podman_runtime),
           "PATH": "/usr/bin:/usr/sbin:/usr/local/bin", "LANG": "C.UTF-8"}
    def run(args):
        return subprocess.run(["/usr/bin/runuser", "-u", "cloud-user", "--", *args],
                              env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False, timeout=300)
    if run(["/usr/bin/podman", "pull", "--quiet", reference]).returncode:
        raise ReleaseError("ReleasePullFailed")
    created = subprocess.run(["/usr/bin/runuser", "-u", "cloud-user", "--", "/usr/bin/podman",
                              "create", "--name", name, reference], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, check=False, timeout=30,
                             env=env)
    if created.returncode:
        raise ReleaseError("ReleaseContainerCreateFailed")
    try:
        # TemporaryDirectory already created this root-owned 0700 path.  The
        # rootless Podman process needs an existing writable destination.
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(destination, 0o700)
        os.chown(destination, 1000, 1000)
        result = subprocess.run(["/usr/bin/runuser", "-u", "cloud-user", "--", "/usr/bin/podman",
                                 "cp", f"{name}:/bundle/.", str(destination)],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                check=False, timeout=60)
        if result.returncode:
            raise ReleaseError("ReleaseExtractFailed")
        for path in destination.rglob("*"):
            info = path.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ReleaseError("ReleaseExtractUnsafePath")
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o755 if stat.S_ISDIR(info.st_mode) or path.name in {
                "apply_bom.py", "openshell", "openshell-gateway", "openshell-supervisor"
            } else 0o644, follow_symlinks=False)
        os.chown(destination, 0, 0)
        os.chmod(destination, 0o755)
    finally:
        subprocess.run(["/usr/bin/runuser", "-u", "cloud-user", "--", "/usr/bin/podman",
                        "rm", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False, timeout=30)


def ensure_release(release=None):
    release = release or load_release()
    target = RELEASE_ROOT / release["bundleDigest"][7:]
    if target.is_dir():
        _verify_tree(target, release)
    else:
        RELEASE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Stage beside RELEASE_ROOT so cloud-user can traverse the parent while
        # podman cp runs. RELEASE_ROOT itself is intentionally root-only.
        with tempfile.TemporaryDirectory(prefix=".saw-release-", dir=RELEASE_ROOT.parent) as staging:
            _pull_bundle(release["bundleRef"], Path(staging))
            _verify_tree(Path(staging), release)
            os.chmod(staging, 0o755)
            os.replace(staging, target)
    if CURRENT.is_symlink() or CURRENT.exists():
        if CURRENT.resolve() != target:
            CURRENT.unlink()
    if not CURRENT.exists():
        CURRENT.symlink_to(target)
    if os.geteuid() == 0:
        _activate_compatibility_paths(target)
    return target


def _activate_compatibility_paths(target):
    """Expose only root-owned links required by the existing installer code."""
    for link, relative in ((Path("/opt/saw/installer"), "."),
                           (Path("/usr/local/bin/openshell"), "openshell"),
                           (Path("/usr/local/bin/openshell-gateway"), "openshell-gateway"),
                           (Path("/usr/local/bin/openshell-supervisor"), "openshell-supervisor")):
        link.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        desired = target if relative == "." else target / relative
        if link.is_symlink() and link.resolve() == desired:
            continue
        if link.exists() or link.is_symlink():
            if not link.is_symlink() or not link.resolve().is_relative_to(RELEASE_ROOT) or link.lstat().st_uid != 0:
                raise ReleaseError("UnsafeReleasePath")
            link.unlink()
        link.symlink_to(desired)
    manifest = target / "build.json"
    if not manifest.exists():
        manifest.write_text(json.dumps({
            "installerBOM": load_release()["bom"],
            "applyBomSha256": hashlib.sha256((target / "apply_bom.py").read_bytes()).hexdigest(),
            "gatewayUnitSha256": hashlib.sha256(Path("/etc/systemd/system/saw-openshell-gateway.service").read_bytes()).hexdigest(),
        }, sort_keys=True, indent=2) + "\n")
        os.chmod(manifest, 0o644)


if __name__ == "__main__":
    ensure_release()
