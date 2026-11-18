"""Temporary OpenShell administrator identity shared by both SAW backends.

The caller owns gateway trust publication and serialization. Private material
exists only for this context; its CA key is destroyed immediately after signing.
The VM embeds this module in its signed installer, as it does saw_core.py.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid


class AdminSessionError(RuntimeError):
    pass


def require_memory(runtime):
    probe = subprocess.run(["stat", "-f", "-c", "%T", str(runtime)],
                           capture_output=True, text=True, timeout=10)
    if probe.returncode or probe.stdout.strip() != "tmpfs":
        raise AdminSessionError("administrator session directory is not tmpfs")


def remove_abandoned(runtime):
    """Caller must hold its session lock; emptyDir survives container restarts."""
    root = Path(runtime)
    if (root / "saw-authorities").is_symlink():
        raise AdminSessionError("administrator authority path is a symlink")
    for pattern in ("saw-admin.*", "saw-authorities/session.*"):
        for path in root.glob(pattern):
            if path.is_symlink():
                raise AdminSessionError("administrator session path is a symlink")
            shutil.rmtree(path)


def openssl(*args):
    try:
        result = subprocess.run(["openssl", *map(str, args)], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        raise AdminSessionError("administrator identity cryptographic tool unavailable") from None
    if result.returncode:
        raise AdminSessionError("administrator identity cryptographic operation failed")
    return result.stdout


def erase_ca_key(path):
    try:
        result = subprocess.run(["shred", "-u", "--", str(path)], capture_output=True, timeout=20)
        if result.returncode:
            raise AdminSessionError("could not shred the per-run admin CA key")
    finally:
        path.unlink(missing_ok=True)


def issue(authority, client, *, subject, crypto=openssl, erase=erase_ca_key):
    """Issue the VM's one-day P-256 CA/client pair, with the admin role in OU."""
    ca, ca_key = authority / "ca.crt", authority / "ca.key"
    csr, key, cert = authority / "client.csr", client / "tls.key", client / "tls.crt"
    try:
        crypto("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
               "-nodes", "-keyout", ca_key, "-out", ca, "-days", "1",
               "-subj", "/O=openshell/OU=SAW-apply/CN=saw-apply-ca",
               "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
        crypto("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
               "-nodes", "-keyout", key, "-subj", subject, "-out", csr)
        ext = authority / "ext.cnf"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       "extendedKeyUsage=clientAuth\n", encoding="utf-8")
        crypto("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
               "-set_serial", "0x"+secrets.token_hex(16), "-days", "1", "-extfile", ext, "-out", cert)
    finally:
        if ca_key.exists():
            erase(ca_key)
    return ca.read_text(encoding="utf-8")


@contextmanager
def identity(server_ca, runtime, *, authority_base=None, subject="/O=openshell/OU=openshell-admin/CN=saw-installer",
             owner=None, require_tmpfs=True, crypto=openssl, erase=erase_ca_key):
    """Create the same private directory layout and cleanup contract as the VM."""
    runtime = Path(runtime)
    if not runtime.is_dir():
        raise AdminSessionError("runtime tmpfs is unavailable")
    if require_tmpfs:
        require_memory(runtime)
    authority_base = Path(authority_base) if authority_base else runtime / "saw-authorities"
    session_dir = root_dir = None
    try:
        session_dir = Path(tempfile.mkdtemp(prefix="saw-admin.", dir=runtime))
        authority_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(authority_base, 0o700)
        root_dir = Path(tempfile.mkdtemp(prefix="session.", dir=authority_base))
        tls, config = session_dir / "tls", session_dir / "config"
        client = tls / "client"
        client.mkdir(parents=True)
        config.mkdir()
        for path in (session_dir, tls, client, config):
            os.chmod(path, 0o700)
            if owner and os.geteuid() == 0:
                os.chown(path, *owner)
        ca_pem = issue(root_dir, client, subject=subject, crypto=crypto, erase=erase)
        (tls / "ca.crt").write_bytes(server_ca)
        for path in (client / "tls.crt", client / "tls.key", tls / "ca.crt"):
            os.chmod(path, 0o600)
            if owner and os.geteuid() == 0:
                os.chown(path, *owner)
        yield {"id": str(uuid.uuid4()), "ca": ca_pem, "tls": tls, "config": config,
               "expires": int(time.time())+86400}
    finally:
        for path in (session_dir, root_dir):
            if path is not None:
                shutil.rmtree(path, ignore_errors=True)


def wait_for_trust(probe, *, timeout=180, sleep=time.sleep, monotonic=time.monotonic):
    """Observe authenticated acceptance, rather than assuming an API write reloaded TLS."""
    deadline = monotonic()+timeout
    while True:
        if probe():
            return
        if monotonic() >= deadline:
            raise AdminSessionError("gateway did not accept the per-run admin CA before the deadline")
        sleep(1)
