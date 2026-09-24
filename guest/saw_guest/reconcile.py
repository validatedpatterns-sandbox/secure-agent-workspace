"""Durable guest-local state machine, shared by first boot and continuous updates."""

import fcntl
import json
import logging
import os
import secrets
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from openshell_saw.blueprints import ValidationError

from .inputs import LIMIT, canonical
from .errors import InstallerFailed, safe_reason


class Busy(Exception):
    pass


def resource_map(snapshot):
    result = {}
    for ws in snapshot.get("workspaces", []):
        result["workspace/" + ws["name"]] = ws["workspace"]
        for kind, items in (("provider", ws["providers"]), ("sandbox", ws["sandboxes"])):
            for item in items:
                result[f"{kind}/{ws['name']}/{item['name']}"] = item
    return result


def plan(previous, desired):
    """Never silently delete workloads or repoint their persistent data."""
    old, new = resource_map(previous or {}), resource_map(desired)
    if old.keys() - new.keys():
        raise ValidationError("resource removal requires explicit migration/decommission")
    for key, item in new.items():
        if key in old:
            before = old[key].get("spec", {}) if key.startswith("workspace/") else old[key]
            after = item.get("spec", {}) if key.startswith("workspace/") else item
            if before.get("enabled", True) and not after.get("enabled", True):
                raise ValidationError("resource disable requires explicit migration/decommission")
            if key.startswith("workspace/") and "inference" in before and "inference" not in after:
                raise ValidationError("inference removal requires explicit decommission")
        if key in old and key.startswith("sandbox/") and old[key].get("data") != item.get("data"):
            raise ValidationError("persistent data identity changes require migration")
    data_ids = set()
    for ws in desired.get("workspaces", []):
        for sandbox in ws["sandboxes"]:
            if "data" in sandbox:
                identity = (ws["name"], sandbox["data"]["name"])
                if identity in data_ids:
                    raise ValidationError("shared sandbox data requires an explicit sharing contract")
                data_ids.add(identity)
    actions = [{"resource": key, "action": "create" if key not in old else "update"}
               for key, item in sorted(new.items()) if old.get(key) != item]
    for key, item in sorted(new.items()):
        if key.startswith("provider/") and key in old and item.get("secretRef"):
            ref = item["secretRef"]
            before = (previous or {}).get("credentials", {}).get(ref["name"], {}).get(ref["key"])
            after = desired.get("credentials", {}).get(ref["name"], {}).get(ref["key"])
            if before != after:
                actions.append({"resource": key, "action": "rotate-credentials"})
    return actions


class State:
    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise ValidationError("state directory cannot be a symlink")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stat = self.directory.stat()
        if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
            raise ValidationError("state directory must be private and owned by the service")

    @contextmanager
    def lock(self):
        fd = os.open(self.directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy() from None
            yield
        finally:
            os.close(fd)

    def read(self):
        path = self.directory / "state.json"
        if not path.exists():
            if path.is_symlink():
                raise ValidationError("invalid state file")
            return {"version": 1, "accepted": None, "pending": None}
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise ValidationError("state file must be private")
        with path.open("rb") as source:
            raw = source.read(3 * LIMIT + 1)
        if len(raw) > 3 * LIMIT:
            raise ValidationError("state file exceeds limit")
        state = json.loads(raw)
        if set(state) != {"version", "accepted", "pending"} or state["version"] != 1:
            raise ValidationError("invalid state format")
        return state

    def write(self, filename, data):
        payload = canonical(data).encode()
        if len(payload) > 3 * LIMIT:
            raise ValidationError("state exceeds limit")
        fd, temporary = tempfile.mkstemp(prefix=".saw-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.directory / filename)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class Reconciler:
    def __init__(self, inputs, state, installer):
        self.inputs, self.state, self.installer = inputs, state, installer

    def status(self, phase, revision=None, reason=None, operation=None):
        # Public-safe fields only; no secret-derived fingerprint or exception text.
        result = {"phase": phase, "revision": revision,
                  "checkedAt": datetime.now(timezone.utc).isoformat()}
        if reason is not None:
            result['reason'] = safe_reason(reason)
            result['operation'] = operation if operation in ('validate', 'apply', 'verify') else None
        self.state.write("status.json", result)

    def run(self):
        with self.state.lock():
            try:
                return self._run()
            except InstallerFailed as error:
                self.status("InstallerFailed", reason=error.reason, operation=error.phase)
                logging.warning('installer failed: operation=%s reason=%s',
                                error.phase, safe_reason(error.reason))
                return False
            except Exception:
                self.status("Blocked")
                return False

    def _run(self):
        state = self.state.read()
        desired = self.inputs.capture()
        accepted, pending = state["accepted"], state["pending"]
        for revision in (accepted, pending):
            if revision and revision["snapshot"]["enrollmentIdentity"] != desired["enrollmentIdentity"]:
                raise ValidationError("state belongs to another enrollment")
        if pending and pending["snapshot"] != desired:
            # Never replay revoked credentials or stack a new rollout over a
            # partially executed one. Installer/operator recovery is required.
            raise ValidationError("pending rollout differs from current inputs")
        actions = plan(accepted["snapshot"] if accepted else None, desired)
        if not pending and accepted and accepted["snapshot"] == desired:
            if self.installer.verify(accepted):
                if self.inputs.capture() != desired:
                    raise ValidationError("inputs changed while verifying")
                self.status("Converged", accepted["id"])
                return True
        if not pending:
            pending = {"id": secrets.token_hex(16), "snapshot": desired, "actions": actions}
        # Preflight is mandatory before persisting a new rollout or touching runtime.
        self.installer.preflight(pending)
        if state["pending"] is None:
            state["pending"] = pending
            self.state.write("state.json", state)
        self.status("Applying", pending["id"])
        self.installer.apply(pending)  # Idempotency key survives crash/restart.
        if not self.installer.verify(pending):
            raise ValidationError("runtime did not verify")
        # If inputs changed during apply, retain pending state and do not claim
        # convergence. No automatic rollback with stale/revoked credentials.
        if self.inputs.capture() != desired:
            raise ValidationError("inputs changed while applying")
        state.update(accepted=pending, pending=None)
        self.state.write("state.json", state)
        self.status("Converged", pending["id"])
        return True
