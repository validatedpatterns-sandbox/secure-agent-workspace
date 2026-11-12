"""Single-writer ConfigMap frontend; no cluster connection at import time.

The host application must supply the profile compiler, core pass and a real
boundary verifier. No default verifier or implicit resource deletion is provided.
Use a retained private state directory distinct from the core reconciler's state.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from pathlib import Path
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
import uuid

from .compiler import ContractError, OWNER, canonical, digest
from .reconcile import MissingSandboxReceipt, RpcError, StateStore

MAX_BODY = 2 * 1024 * 1024
MAX_DATA = 900 * 1024
MANAGED = "saw.redhat.com/managed-by"
CONTROLLER = "kubernetes-runtime-controller"
# Kubernetes DNS subdomains require every dot-separated label, not only the
# entire name, to start and end with an alphanumeric character.
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*\Z")
KEY = re.compile(r"[A-Za-z0-9_.-]+\Z")
CORE_PHASES = {"Pending", "Retry", "GenericReady", "Stopped"}


class ApiError(Exception):
    """Only the numeric HTTP code crosses the client boundary."""

    def __init__(self, code=0):
        self.code = code if type(code) is int and 0 <= code <= 599 else 0
        super().__init__(f"Kubernetes API failure ({self.code})")


class InputError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def valid_lifecycle_intent(intent):
    """Envelope shared by the controller and the local intent generator."""
    fields = {"schemaVersion", "generation", "desiredState", "profileRef", "bindings"}
    if not isinstance(intent, dict) or set(intent) - {"restartGeneration"} != fields:
        return False
    generation = intent["generation"]
    restart = intent.get("restartGeneration", 0)
    return (type(intent["schemaVersion"]) is int and intent["schemaVersion"] == 1
            and type(generation) is int and generation >= 1 and type(restart) is int
            and 0 <= restart <= generation and intent["desiredState"] in ("Running", "Stopped"))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the projected bearer token to another URL.


@dataclass(frozen=True)
class Scope:
    namespace: str
    profile_name: str
    bindings_name: str
    status_name: str
    owner_id: str

    def __post_init__(self):
        for value in [self.namespace, self.profile_name, self.bindings_name, self.status_name]:
            if not isinstance(value, str) or len(value) > 253 or not NAME.fullmatch(value) or ".." in value:
                raise ContractError("controller scope requires explicit Kubernetes names")
        if len(self.namespace) > 63 or "." in self.namespace:
            raise ContractError("controller namespace must be a DNS label")
        if len({self.profile_name, self.bindings_name, self.status_name}) != 3:
            raise ContractError("profile, bindings and status ConfigMaps must be distinct")
        try:
            if str(uuid.UUID(self.owner_id)) != self.owner_id or uuid.UUID(self.owner_id).int == 0:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ContractError("controller owner must be a canonical nonzero UUID") from None


class KubernetesClient:
    """Verified HTTPS with a rotating projected token and no redirects.

    Callers constrain resource paths; Kubernetes RBAC constrains authorization.
    API responses/error bodies and bearer tokens are never included in errors.
    """

    def __init__(self, server, ca_file, token_file, *, timeout=20, opener=None):
        try:
            url = urlsplit(server)
            port = url.port
        except (TypeError, ValueError):
            raise ContractError("Kubernetes API server must be an HTTPS authority") from None
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in {"", "/"} or url.query or url.fragment or port == 0
                or any(c.isspace() for c in server)):
            raise ContractError("Kubernetes API server must be an HTTPS authority")
        if type(timeout) not in {int, float} or not 0 < timeout <= 45:
            raise ContractError("API timeout must be between zero and 45 seconds")
        try:
            self.context = ssl.create_default_context(cafile=str(ca_file))
        except (OSError, ssl.SSLError):
            raise ContractError("a valid Kubernetes CA file is required") from None
        self.server = server.rstrip("/")
        self.token_file, self.timeout = Path(token_file), timeout
        if opener is None:
            verified = build_opener(HTTPSHandler(context=self.context), _NoRedirect())
            opener = lambda request, **kwargs: verified.open(request, timeout=kwargs["timeout"])
        self.opener = opener

    def _open(self, method, path, body=None, *, timeout=None):
        try:
            token = self.token_file.read_text().strip()
            if not token or any(c.isspace() for c in token):
                raise ValueError()
        except (OSError, ValueError):
            raise ApiError() from None
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        raw = None if body is None else canonical(body).encode()
        if raw is not None:
            if len(raw) > MAX_BODY:
                raise ApiError()
            headers["Content-Type"] = "application/json"
        request = Request(self.server + path, data=raw, headers=headers, method=method)
        try:
            return self.opener(request, context=self.context, timeout=timeout or self.timeout)
        except HTTPError as exc:
            code = exc.code
            exc.close()
            raise ApiError(code) from None
        except (OSError, URLError, ValueError):
            raise ApiError() from None

    @staticmethod
    def _json(response):
        try:
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise ApiError() from None

    def request(self, method, path, body=None):
        with self._open(method, path, body) as response:
            return self._json(response)


class ConfigMapClient(KubernetesClient):
    """Named ConfigMap reads and status-only writes over the shared HTTP client."""
    def __init__(self, server, scope, ca_file, token_file, *, timeout=20, opener=None):
        super().__init__(server, ca_file, token_file, timeout=timeout, opener=opener)
        self.scope = scope

    def _path(self, name):
        if name not in {self.scope.profile_name, self.scope.bindings_name, self.scope.status_name}:
            raise ContractError("ConfigMap access is outside the controller allowlist")
        return f"/api/v1/namespaces/{self.scope.namespace}/configmaps/{name}"

    def get(self, name):
        try:
            with self._open("GET", self._path(name)) as response:
                return self._json(response)
        except ApiError as exc:
            if exc.code == 404:
                return None
            raise

    def write_status(self, body, *, resource_version=None):
        name = self.scope.status_name
        metadata = body.get("metadata", {})
        if metadata.get("name") != name or metadata.get("namespace") != self.scope.namespace:
            raise ContractError("only the controller status ConfigMap may be written")
        if resource_version is None:
            path, method = self._path(name).rsplit("/", 1)[0], "POST"
        else:
            if metadata.get("resourceVersion") != resource_version:
                raise ContractError("status update must preserve its observed resourceVersion")
            path, method = self._path(name), "PUT"
        with self._open(method, path, body) as response:
            return self._json(response)

    def watch(self, name, resource_version, *, timeout_seconds=20):
        self._path(name)
        if name != self.scope.bindings_name or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
            raise ContractError("only a bounded admin-intent watch is permitted")
        query = urlencode({"fieldSelector": f"metadata.name={name}", "watch": "true",
                           "resourceVersion": resource_version, "timeoutSeconds": timeout_seconds,
                           "allowWatchBookmarks": "true"})
        path = self._path(name).rsplit("/", 1)[0] + "?" + query
        try:
            with self._open("GET", path, timeout=timeout_seconds + 5) as response:
                deadline = time.monotonic() + timeout_seconds
                for _ in range(100):
                    if time.monotonic() >= deadline:
                        return
                    raw = response.readline(MAX_BODY + 1)
                    if not raw:
                        return
                    if len(raw) > MAX_BODY:
                        raise ApiError()
                    event = json.loads(raw)
                    if not isinstance(event, dict):
                        raise ApiError()
                    if event.get("type") == "ERROR":
                        error = event.get("object")
                        if not isinstance(error, dict):
                            raise ApiError()
                        raise ApiError(error.get("code", 0))
                    yield event
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise ApiError() from None


class Controller:
    """One process/replica with retained state; not a distributed lease or HA.

    `compile_files(flat_data, bindings)` and `core_pass(plan, generation=...,
    desired_state=...)` are injected. `verify_boundary(plan)` is mandatory and
    must actually validate the installation's trust and enforcement prerequisites.
    A separate state subdirectory makes the lifetime lock compose with the core's
    per-pass lock. Missing/deleted inputs only block; they never mean purge/stop.
    """

    def __init__(self, api, scope, state_directory, compile_files, core_pass, verify_boundary):
        if not all(callable(f) for f in [compile_files, core_pass, verify_boundary]):
            raise ContractError("compiler, core pass and real boundary verifier are required")
        self.api, self.scope = api, scope
        self.compile_files, self.core_pass, self.verify_boundary = compile_files, core_pass, verify_boundary
        self.store = StateStore(Path(state_directory) / "controller-frontend")
        self.watch_version = ""

    def _metadata(self, obj, name):
        if obj is None:
            raise InputError("MissingInputs")
        meta = obj.get("metadata", {})
        if (obj.get("kind") != "ConfigMap" or meta.get("name") != name
                or meta.get("namespace") != self.scope.namespace
                or not isinstance(meta.get("uid"), str) or not meta["uid"]
                or not isinstance(meta.get("resourceVersion"), str) or not meta["resourceVersion"]):
            raise InputError("InvalidInputs")
        if meta.get("deletionTimestamp"):
            raise InputError("DeletingInputs")
        return meta

    @staticmethod
    def _data(obj):
        data = obj.get("data", {})
        if (obj.get("binaryData") or not isinstance(data, dict) or not data
                or any(not isinstance(k, str) or not KEY.fullmatch(k) or k in {".", ".."}
                       or not isinstance(v, str) for k, v in data.items())
                or len(canonical(data).encode()) > MAX_DATA):
            raise InputError("InvalidInputs")
        return data

    def _snapshot(self):
        bindings = self.api.get(self.scope.bindings_name)
        bm = self._metadata(bindings, self.scope.bindings_name)
        self.watch_version = bm["resourceVersion"]
        if bm.get("labels", {}).get(OWNER) != self.scope.owner_id:
            raise InputError("IdentityMismatch")
        data = self._data(bindings)
        if set(data) != {"intent.json"}:
            raise InputError("InvalidInputs")
        try:
            intent = json.loads(data["intent.json"])
        except ValueError:
            raise InputError("InvalidInputs") from None
        if (not valid_lifecycle_intent(intent)
                or not isinstance(intent["bindings"], dict)
                or intent["bindings"].get("ownerID") != self.scope.owner_id
                or intent["bindings"].get("namespace") != self.scope.namespace):
            raise InputError("InvalidInputs")
        reference = intent["profileRef"]
        if (not isinstance(reference, dict) or set(reference) not in ({"name", "uid", "sha256"}, {"name", "uid", "sha256", "planSHA256"})
                or reference["name"] != self.scope.profile_name):
            raise InputError("InvalidInputs")
        profile = self.api.get(self.scope.profile_name)
        pm = self._metadata(profile, self.scope.profile_name)
        files = self._data(profile)
        if reference["uid"] != pm["uid"] or reference["sha256"] != digest(files):
            raise InputError("InputRevisionMismatch")
        # K8s resourceVersions are opaque; equality, not numeric ordering.
        for name, first in [(self.scope.bindings_name, bindings), (self.scope.profile_name, profile)]:
            again = self.api.get(name)
            self._metadata(again, name)
            if again != first:
                raise InputError("InputsChangedDuringRead")
        return intent, files, {"bindings": bm["uid"], "profile": pm["uid"]}, digest({"intent": intent, "files": files})

    def _status_object(self):
        existing = self.api.get(self.scope.status_name)
        if existing is not None:
            meta = self._metadata(existing, self.scope.status_name)
            labels = meta.get("labels", {})
            if labels.get(OWNER) != self.scope.owner_id or labels.get(MANAGED) != CONTROLLER:
                raise InputError("StatusOwnershipMismatch")
        return existing

    def _publish(self, status):
        for _ in range(3):
            existing = self._status_object()
            resource_version = None
            if existing is not None:
                resource_version = existing["metadata"]["resourceVersion"]
                if existing.get("data") == {"status.json": canonical(status)}:
                    return
            body = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
                "name": self.scope.status_name, "namespace": self.scope.namespace,
                "labels": {OWNER: self.scope.owner_id, MANAGED: CONTROLLER}},
                "data": {"status.json": canonical(status)}}
            if resource_version:
                body["metadata"] = copy.deepcopy(existing["metadata"])
            try:
                self.api.write_status(body, resource_version=resource_version)
                return
            except ApiError as exc:
                if exc.code != 409:
                    raise
        raise InputError("StatusConflict")

    def _once(self):
        state = self.store.load()
        identity = vars(self.scope)
        if state and state.get("scope") != identity:
            raise ContractError("retained controller scope differs; explicit recovery is required")
        state["scope"] = identity
        status = {"schemaVersion": 1, "phase": "Blocked", "reason": "InvalidInputs"}
        retry = 5
        try:
            self._status_object()  # Refuse known foreign status ownership before core mutations.
            intent, files, uids, revision = self._snapshot()
            status.update(observedGeneration=intent["generation"], inputRevision=revision)
            previous = state.get("intent", {})
            if state.get("inputUIDs", uids) != uids:
                raise InputError("InputIdentityReplaced")
            if (previous.get("generation", 0) > intent["generation"]
                    or previous.get("generation") == intent["generation"] and previous.get("revision") != revision):
                raise InputError("StaleOrConflictingGeneration")
            plan = self.compile_files(copy.deepcopy(files), copy.deepcopy(intent["bindings"]))
            if "planSHA256" in intent["profileRef"] and plan["revision"] != intent["profileRef"]["planSHA256"]:
                raise InputError("CompiledPlanMismatch")
            if intent["desiredState"] == "Running":
                try:
                    self.verify_boundary(plan)
                except Exception:
                    raise InputError("BoundaryRejected") from None
            # Stopped delegates to the core's identity-checked shutdown path.
            # Renewed network/attachment approval must not prevent stopping an
            # already recorded sandbox. Input fencing above remains mandatory.
            state.update(inputUIDs=uids, intent={"generation": intent["generation"], "revision": revision})
            self.store.save(state)  # Fence identities and intent before any core mutation.
            restart = intent.get("restartGeneration",0)
            # Reserve two monotonically ordered core passes per owner generation
            # for registrations opted into model rollover. Owner status keeps
            # the externally visible generation and revision.
            core_generation = intent["generation"] * (2 if "restartGeneration" in intent else 1)
            applied = state.get("restartGeneration",0)
            if restart < applied:
                raise InputError("StaleOrConflictingGeneration")
            if restart > applied:
                # A confirmed Stopped phase is the durable barrier. Persist it
                # before starting so retries cannot repeatedly stop a fresh Pod.
                result = self.core_pass(plan,generation=core_generation - 1,desired_state="Stopped")
                if result.get("phase") == "Stopped":
                    state["restartGeneration"] = restart
                    self.store.save(state)
                if intent["desiredState"] == "Running":
                    result = {"phase":"Pending","retry_after_seconds":1}
            else:
                result = self.core_pass(plan, generation=core_generation, desired_state=intent["desiredState"])
            if not isinstance(result, dict) or result.get("phase") not in CORE_PHASES:
                raise InputError("InvalidCoreStatus")
            status.update(phase=result["phase"], reason="CoreObserved")
            delay = result.get("retry_after_seconds", 5)
            retry = min(max(delay, 1), 30) if type(delay) is int else 5
            if result["phase"] in {"GenericReady", "Stopped"}:
                retry = 30  # Full input/ownership resync, even without watch events.
            state["apiFailures"] = 0
            self.store.save(state)
        except InputError as exc:
            status["reason"] = exc.reason
        except MissingSandboxReceipt:
            status["reason"] = "StartToRecoverSandboxReceipt"
        except ContractError:
            status["reason"] = "CoreRejected"
        except RpcError as exc:
            if exc.code in {"UNAVAILABLE", "DEADLINE_EXCEEDED", "ABORTED", "RESOURCE_EXHAUSTED"}:
                status.update(phase="Retry", reason="CoreUnavailable")
            else:
                status["reason"] = "CoreRejected"
        except ApiError:
            failures = min(state.get("apiFailures", 0) + 1, 5)
            state["apiFailures"] = failures
            self.store.save(state)
            retry = min(2 ** failures, 30)
            status.update(phase="Retry", reason="ApiUnavailable")
        except Exception:
            # A caller's compiler/core exception may contain credentials. Never
            # serialize str(exc), traceback, requests or returned RPC details.
            status["reason"] = "CoreFailure"
        status["retryAfterSeconds"] = retry
        try:
            self._publish(status)
        except (ApiError, InputError):
            # Desired state is never rewritten to recover a status conflict.
            status["statusPublished"] = False
        return status

    def reconcile_once(self):
        with self.store.locked():
            return self._once()

    def run(self, *, stop=lambda: False, max_cycles=None, sleep=time.sleep, monotonic=time.monotonic):
        """Lifetime lock, bounded watch, relist/resync after every event or 410.

        The injected watch must honor its timeout; the HTTPS client above does.
        Only intent is watched; profile-only edits are caught by <=30s resync.
        """
        cycles = 0
        with self.store.locked():
            while not stop() and (max_cycles is None or cycles < max_cycles):
                status = self._once()
                cycles += 1
                if stop() or max_cycles is not None and cycles >= max_cycles:
                    return status
                delay = status["retryAfterSeconds"]
                start = monotonic()
                changed = False
                try:
                    for event in self.api.watch(self.scope.bindings_name, self.watch_version, timeout_seconds=delay):
                        if event.get("type") in {"ADDED", "MODIFIED", "DELETED"}:
                            changed = True
                            break
                except ApiError:
                    self.watch_version = ""  # 410/transport loss always causes a fresh named GET.
                elapsed = monotonic() - start
                if not changed and elapsed < delay:
                    sleep(delay - elapsed)  # EOF/errors honor the bounded retry delay.
        return None
