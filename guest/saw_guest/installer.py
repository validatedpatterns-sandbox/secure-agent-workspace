"""Invoke only the verified platform release bundle."""

import json
import os
import signal
import stat
import subprocess
import tempfile
from pathlib import Path

from .inputs import canonical
from .errors import InstallerFailed
from .release import ReleaseError, ensure_release

SCRIPT = Path("/var/lib/saw/releases/current/apply_bom.py")


class BomInstaller:
    def call(self, phase, revision):
        try:
            script = (ensure_release() / "apply_bom.py"
                      if SCRIPT == Path("/var/lib/saw/releases/current/apply_bom.py") else SCRIPT)
            for path in [script, *script.parents]:
                info = path.lstat()
                if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                    raise InstallerFailed()
            if not script.is_file():
                raise InstallerFailed()
            with tempfile.TemporaryFile() as output:
                with subprocess.Popen(
                    ["/usr/bin/python3", "-I", str(script), "--guest-phase", phase],
                    stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                    text=True, start_new_session=True,
                    env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
                ) as process:
                    try:
                        process.communicate(canonical({"version": 1, "revision": revision}), timeout=120)
                    except BaseException:
                        # Kill the CLI descendants too, before releasing the
                        # single-writer lock or allowing another reconciliation.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.communicate()
                        raise
                    returncode = process.returncode
                output.seek(0)
                raw = output.read(8193)
            if len(raw) > 8192:
                raise InstallerFailed()
            reply = json.loads(raw)
            if reply.get("version") != 1 or reply.get("revision") != revision["id"]:
                raise InstallerFailed()
            ok = reply.get("ok")
            if type(ok) is not bool or returncode != (0 if ok else 1):
                raise InstallerFailed()
            # A valid negative verification lets the reconciler preflight and
            # repair drift. Invalid replies/process failures never do.
            if not ok and phase != 'verify':
                raise InstallerFailed(reply.get('reason'), phase)
            return ok
        except (OSError, subprocess.SubprocessError, ValueError, AttributeError, ReleaseError):
            raise InstallerFailed() from None

    def preflight(self, revision):
        if not self.call("validate", revision):
            raise InstallerFailed()

    def apply(self, revision):
        if not self.call("apply", revision):
            raise InstallerFailed()

    def verify(self, revision):
        return self.call("verify", revision)
