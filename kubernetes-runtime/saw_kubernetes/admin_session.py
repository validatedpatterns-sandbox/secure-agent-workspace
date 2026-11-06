"""Kubernetes trust-bundle adapter for the VM's temporary admin identity.

Only public CA certificates enter the named Secret. resourceVersion provides
compare-and-swap; concurrent controller/relay sessions preserve each other's
trust. Dead-Pod and expired sessions are removed at the next trust update.
"""
import base64
from contextlib import contextmanager
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import ssl
import time
import uuid

from .adapters import GrpcGateway
from .compiler import ContractError
from .controller import ApiError
from .core import admin
from .reconcile import RpcError

SESSIONS = "saw.redhat.com/admin-sessions"
OWNER = "saw.redhat.com/runtime-owner"
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")


def encoded(raw):
    return base64.b64encode(raw).decode("ascii")


def bundle(base, certificates):
    return base.rstrip()+b"\n"+b"".join(certificates[key].rstrip()+b"\n" for key in sorted(certificates))


class TrustBundle:
    def __init__(self, request, namespace, trusted_namespace, gateway, owner_id, base_ca, pod, pod_uid, *, now=time.time):
        if not all(isinstance(v, str) and NAME.fullmatch(v) for v in (namespace, trusted_namespace, gateway, pod)):
            raise ContractError("invalid temporary administrator scope")
        try:
            for value in (owner_id, pod_uid):
                if str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
                    raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ContractError("invalid temporary administrator identity") from None
        self.request, self.now = request, now
        self.namespace, self.trusted_namespace = namespace, trusted_namespace
        self.name, self.owner_id = gateway+"-client-ca", owner_id
        self.base, self.pod, self.pod_uid = base_ca, pod, pod_uid
        self.path = f"/api/v1/namespaces/{namespace}/secrets/{self.name}"
        self.uid = None

    def _pod(self, holder):
        try:
            return self.request("GET", f"/api/v1/namespaces/{self.trusted_namespace}/pods/{holder['pod']}")
        except ApiError as exc:
            if exc.code == 404: return None
            raise

    def live(self, holder):
        pod = self._pod(holder)
        meta = (pod or {}).get("metadata", {})
        return (meta.get("uid") == holder["uid"] and not meta.get("deletionTimestamp")
                and (pod or {}).get("status", {}).get("phase") == "Running")

    def wait_for_holder(self, *, timeout=30, sleep=time.sleep, monotonic=time.monotonic):
        """A Job process can start before kubelet publishes its Running phase.

        Wait only for this exact, nondeleting Pod while it is Pending. Do not
        publish trust for it yet or relax live() for cleanup/publication checks.
        """
        deadline = monotonic() + timeout
        while True:
            pod = self._pod({"pod": self.pod}) or {}
            meta, phase = pod.get("metadata", {}), pod.get("status", {}).get("phase")
            if meta.get("uid") != self.pod_uid or meta.get("deletionTimestamp"):
                raise ContractError("administrator session holder missing, replaced or deleting")
            if phase == "Running":
                return
            if phase != "Pending":
                raise ContractError("administrator session holder is not starting or running")
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise ContractError("administrator session holder did not become Running before the deadline")
            sleep(min(0.5, remaining))

    def read(self):
        obj = self.request("GET", self.path)
        meta = obj.get("metadata", {})
        data = obj.get("data", {})
        if (meta.get("name") != self.name or meta.get("namespace") != self.namespace
                or meta.get("labels", {}).get(OWNER) != self.owner_id
                or meta.get("deletionTimestamp") or meta.get("ownerReferences")
                or not meta.get("uid") or not meta.get("resourceVersion")
                or self.uid is not None and self.uid != meta["uid"]
                or obj.get("immutable") is not False or obj.get("type") != "Opaque"
                or data.get("base.crt") != encoded(self.base)):
            raise ContractError("gateway client trust is foreign, replaced or immutable")
        self.uid = meta["uid"]
        try:
            sessions = json.loads(meta.get("annotations", {}).get(SESSIONS, "{}"))
            if not isinstance(sessions, dict) or len(sessions) > 16:
                raise ValueError()
            certs = {}
            for sid, holder in sessions.items():
                if str(uuid.UUID(sid)) != sid or set(holder) != {"pod", "uid", "expires"}:
                    raise ValueError()
                if (not NAME.fullmatch(holder["pod"]) or str(uuid.UUID(holder["uid"])) != holder["uid"]
                        # Allow modest node clock skew in metadata. TLS still
                        # enforces the certificate's actual one-day validity.
                        or type(holder["expires"]) is not int or holder["expires"] > self.now()+86400+300):
                    raise ValueError()
                certs[sid] = base64.b64decode(data["session-"+sid+".crt"], validate=True)
                if not re.fullmatch(rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*", certs[sid]):
                    raise ValueError()
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=certs[sid].decode("ascii"))
            if set(data) != {"base.crt", "ca.crt", *("session-"+sid+".crt" for sid in sessions)}:
                raise ValueError()
            if data["ca.crt"] != encoded(bundle(self.base, certs)):
                raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError, ssl.SSLError):
            raise ContractError("gateway temporary trust publication is malformed") from None
        return obj, sessions, certs

    def update(self, *, add=None, remove=None, clear_holder=False):
        for _ in range(8):
            obj, sessions, certs = self.read()
            before = copy.deepcopy(sessions)
            for sid, holder in list(sessions.items()):
                own = holder["uid"] == self.pod_uid and holder["pod"] == self.pod
                if (clear_holder and own) or holder["expires"] <= self.now() or not self.live(holder):
                    del sessions[sid], certs[sid]
            if remove and remove in sessions:
                if sessions[remove]["uid"] != self.pod_uid or sessions[remove]["pod"] != self.pod:
                    raise ContractError("cannot withdraw another administrator session")
                del sessions[remove], certs[remove]
            if add:
                holder = {"pod": self.pod, "uid": self.pod_uid, "expires": add["expires"]}
                if not self.live(holder) or (add["id"] not in sessions and len(sessions) >= 16):
                    raise ContractError("administrator session holder unavailable or limit exceeded")
                if add["id"] in sessions and sessions[add["id"]] != holder:
                    raise ContractError("administrator session identity collision")
                sessions[add["id"]], certs[add["id"]] = holder, add["ca"].encode()
            if sessions == before and not add:
                return
            obj["metadata"].setdefault("annotations", {})[SESSIONS] = json.dumps(sessions, sort_keys=True)
            obj["data"] = {"base.crt": encoded(self.base), "ca.crt": encoded(bundle(self.base, certs)),
                           **{"session-"+sid+".crt": encoded(cert) for sid, cert in certs.items()}}
            try:
                self.request("PUT", self.path, obj)
                return
            except ApiError as exc:
                if exc.code != 409: raise
        raise ContractError("gateway temporary trust update conflicted")


class GatewaySessions:
    def __init__(self, trust, endpoint, runtime="/run/saw-admin", *, gateway_factory=GrpcGateway):
        self.trust, self.endpoint, self.runtime = trust, endpoint, runtime
        self.gateway_factory = gateway_factory

    @contextmanager
    def _exclusive(self):
        admin.require_memory(self.runtime)
        fd = os.open(Path(self.runtime)/"session.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ContractError("another administrator operation owns this Pod's session") from None
            try:
                self.trust.update(clear_holder=True)
            finally:
                # Also remove private files if API recovery is unavailable.
                admin.remove_abandoned(self.runtime)
            self.trust.wait_for_holder()
            yield
        finally:
            os.close(fd)

    @contextmanager
    def open(self):
        with self._exclusive(), admin.identity(self.trust.base, self.runtime) as identity:
            gateway = None
            try:
                # Cleanup also runs after an ambiguous API response: a write
                # may have committed even when its response was lost.
                self.trust.update(add=identity)
                def accepted():
                    nonlocal gateway
                    if gateway is not None:
                        gateway.close()
                    tls = identity["tls"]
                    gateway = self.gateway_factory(self.endpoint, tls/"ca.crt", tls/"client/tls.crt", tls/"client/tls.key", timeout=3)
                    try:
                        gateway.call("GetGatewayInfo", {})
                        return True
                    except RpcError as exc:
                        if exc.code not in {"UNAVAILABLE", "UNAUTHENTICATED"}: raise
                        return False
                admin.wait_for_trust(accepted)
                gateway.timeout = 20
                yield gateway
            finally:
                if gateway is not None:
                    gateway.close()
                self.trust.update(remove=identity["id"])
