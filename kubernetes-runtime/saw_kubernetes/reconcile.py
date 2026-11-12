"""Serialized, restart-safe reconciliation over the stock OpenShell RPC surface.

The adapter implements ``call(method, request) -> response`` using protobuf-field
names. It must not retry unsafe writes itself or log request/response bodies.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

from .core import shared
from . import provider as governed

from .compiler import ContractError, MANAGED, OWNER, REVISION, SOURCE_REVISION, digest, request_id


class RpcError(Exception):
    def __init__(self, code):
        # Do not persist arbitrary gateway errors that could contain credentials.
        self.code = code if code in {
            "NOT_FOUND", "ALREADY_EXISTS", "UNAVAILABLE", "DEADLINE_EXCEEDED",
            "ABORTED", "RESOURCE_EXHAUSTED", "PERMISSION_DENIED", "UNAUTHENTICATED",
            "INVALID_ARGUMENT", "FAILED_PRECONDITION", "UNKNOWN"} else "UNKNOWN"
        super().__init__(self.code)


class MissingSandboxReceipt(ContractError):
    """Stopping an ambiguous create requires a verified receipt from a Running pass."""


class Busy(Exception):
    pass


class StateStore:
    """Single local/shared-filesystem writer; not a distributed Kubernetes lease."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise ContractError("state directory must not be a symlink")
        self.path = self.directory / "state.json"

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.directory / "reconcile.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy() from None
            yield
        finally:
            os.close(fd)

    def load(self):
        if not self.path.exists():
            return {}
        if self.path.is_symlink():
            raise ContractError("state must not be a symlink")
        try:
            value = json.loads(self.path.read_text())
        except (ValueError, OSError):
            raise ContractError("cannot read retained reconciler state") from None
        if not isinstance(value, dict):
            raise ContractError("retained reconciler state must be an object")
        return value

    def save(self, value):
        fd, tmp = tempfile.mkstemp(prefix="state-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, sort_keys=True)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp, self.path)
            dirfd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


class Reconciler:
    """One bounded observation/apply pass; callers schedule the next pass.

    `verify_resources(plan)` must independently read/validate current cluster
    resource identity and integration security prerequisites. It is mandatory,
    called before every pass, and must fail closed. Tests use fake resources;
    providing a no-op in a deployment is not qualification.
    """

    def __init__(self, rpc, state_directory, verify_resources, *, verify_shutdown=None):
        self.rpc = rpc
        self.store = StateStore(state_directory)
        if not callable(verify_resources):
            raise ContractError("resource verifier is required")
        self.verify_resources = verify_resources
        self.verify_shutdown = (verify_shutdown if verify_shutdown is not None else
                                getattr(verify_resources, "verify_shutdown", verify_resources))
        if not callable(self.verify_shutdown):
            raise ContractError("shutdown identity verifier must be callable")

    def _get(self, method, request, field):
        try:
            response = self.rpc.call(method, request)
        except RpcError as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise
        if not isinstance(response.get(field), dict):
            raise ContractError("gateway returned an invalid object")
        return response[field]

    def _mutate(self, method, request, plan, generation):
        body = copy.deepcopy(request)
        body["request_id"] = request_id(plan["ownerID"], method,
                                        {"request": request, "generation": generation})
        try:
            return self.rpc.call(method, body)
        except RpcError as exc:
            if exc.code != "ALREADY_EXISTS":
                raise
        # Observe on the next pass, including ALREADY_EXISTS and ambiguous
        # timeouts. Never assume the mutation response proves convergence.

    def _identity(self, kind, workspace, name, obj, plan, state, default=False):
        meta = obj.get("metadata", {})
        labels = meta.get("labels", {})
        if meta.get("deletion_time"):
            raise ContractError("managed object is being deleted")
        if meta.get("name") != name or not meta.get("id"):
            raise ContractError("gateway object identity is missing or changed")
        if kind != "workspace" and meta.get("workspace", "default") != workspace:
            raise ContractError("gateway object is in the wrong workspace")
        if not default and (labels.get(OWNER) != plan["ownerID"] or labels.get(MANAGED) != "kubernetes-runtime"):
            raise ContractError("refusing to adopt an object owned by another installation")
        key = f"{kind}/{workspace}/{name}"
        previous = state.setdefault("objectIDs", {}).get(key)
        if previous is not None and previous != meta["id"]:
            raise ContractError("same-name replacement detected; explicit recovery is required")
        state["objectIDs"][key] = meta["id"]
        self.store.save(state)

    @staticmethod
    def _sandbox_spec_matches(actual, desired):
        # The pinned gateway adds provider_attachment_epoch and normalizes an
        # unspecified restart policy to Never during create (grpc/sandbox.rs).
        # Policy is governed by the platform, not compiled by this adapter;
        # do not confuse that policy with permission to add other spec fields.
        allowed = {"template", "providers", "command", "tty", "policy",
                   "provider_attachment_epoch", "restart_policy", "environment",
                   "resource_requirements", "log_level"}
        if not isinstance(actual, dict) or set(actual) - allowed:
            return False
        if any(actual.get(field) for field in ["environment", "resource_requirements", "log_level"]):
            return False
        if actual.get("restart_policy", "SANDBOX_RESTART_POLICY_NEVER") != "SANDBOX_RESTART_POLICY_NEVER":
            return False
        for field in ["template", "providers", "command", "tty"]:
            default = False if field == "tty" else ([] if field == "providers" else None)
            if actual.get(field, default) != desired[field]:
                return False
        return True

    def reconcile(self, plan, *, generation, desired_state="Running"):
        if type(generation) is not int or generation < 1 or desired_state not in {"Running", "Stopped"}:
            raise ContractError("a positive intent generation and Running/Stopped state are required")
        body = {k: v for k, v in plan.items() if k != "revision"}
        if plan.get("sourceRevision") != SOURCE_REVISION or plan.get("schemaVersion") != 1 or digest(body) != plan.get("revision"):
            raise ContractError("invalid or modified compiled plan")
        if plan.get("mode") != "container" or plan.get("requestedPlacement") != {
                "supervisor": "container", "workload": plan["mode"]}:
            raise ContractError("stock adapter requires an ordinary-container supervisor")
        with self.store.locked():
            state = self.store.load()
            identity = {key: plan[key] for key in ["ownerID", "namespaceUID", "ownerSubject", "mode"]}
            if state and state.get("identity") != identity:
                raise ContractError("workspace identity, owner and deployment mode are immutable")
            previous = state.get("intent", {})
            intent = {"generation": generation, "revision": plan["revision"], "desiredState": desired_state}
            if previous.get("generation", 0) > generation or (previous.get("generation") == generation and previous != intent):
                raise ContractError("stale generation or conflicting intent at the same generation")
            (self.verify_shutdown if desired_state == "Stopped" else self.verify_resources)(plan)
            state.update(identity=identity, intent=intent)
            self.store.save(state)
            try:
                return self._pass(plan, state, generation, desired_state)
            except RpcError as exc:
                attempts = min(state.get("transientAttempts", 0) + 1, 8)
                state["transientAttempts"] = attempts
                self.store.save(state)
                if exc.code in {"UNAVAILABLE", "DEADLINE_EXCEEDED", "ABORTED", "RESOURCE_EXHAUSTED"}:
                    return self._status(plan, generation, "Retry", reason=exc.code,
                                        retry_after_seconds=min(2 ** attempts, 60))
                raise

    @staticmethod
    def _status(plan, generation, phase, **extra):
        return {"observedGeneration": generation, "desiredRevision": plan["revision"],
                "phase": phase, "requestedPlacement": plan["requestedPlacement"], **extra}

    def _pass(self, plan, state, generation, desired_state):
        info = self.rpc.call("GetGatewayInfo", {})
        if info.get("gateway_version") != plan["gatewayVersion"] or [d.get("name") for d in info.get("compute_drivers", [])] != ["kubernetes"]:
            raise ContractError("gateway version or active compute driver differs from approved inputs")
        if desired_state == "Stopped":
            return self._stop_pass(plan, state, generation)
        retired = plan.get("retiredSandboxes", {})
        if retired:
            refs = {"sandbox/" + name for name in retired}
            if any(state.get("objectIDs", {}).get("sandbox/" + k) != v for k, v in retired.items()):
                raise ContractError("refusing to stop a sandbox without its recorded identity")
            pending = self._stop_references(refs, plan, state, generation)
            if pending:
                return self._status(plan, generation, "Pending", pending=pending, retry_after_seconds=5)
        for provider_type in sorted({p["type"] for w in plan["workspaces"] for p in w["providers"]}):
            # Resolve platform scope explicitly (workspace_scope omitted). A
            # workspace administrator's same-name custom profile is not enough.
            profile = self.rpc.call("GetProviderProfile", {"id": provider_type}).get("profile", {})
            marker_provider = any(p.get("credentials") for w in plan["workspaces"] for p in w["providers"]
                                  if p["type"] == provider_type)
            if marker_provider:
                slots = profile.get("credentials", [])
                endpoints = profile.get("endpoints", [])
                slot, hosts = governed.requirements(provider_type, plan.get("customInferenceURL"))
                if (profile.get("id") != provider_type
                        or profile.get("source") != "interceptor/governance" or len(slots) != 1
                        or slots[0].get("env_vars") != slot["env_vars"] or slots[0].get("name") != slot["name"]
                        or sorted(e.get("host") for e in endpoints) != hosts
                        or any(e.get("port") != 443 or e.get("enforcement") != "NETWORK_ENFORCEMENT_MODE_ENFORCE" for e in endpoints)):
                    raise ContractError(f"{provider_type} profile differs from the approved inference boundary")
                continue
            if (profile.get("id") != provider_type or profile.get("credentials")
                    or not profile.get("source", "").startswith("interceptor/")):
                raise ContractError("provider profile is not a governed credential-free platform profile")
        pending = []
        adapter = SimpleNamespace(
            prepare_workspace=lambda ws: self._prepare_workspace(ws, plan, state, generation, pending),
            apply_provider=lambda ws, provider: self._apply_provider(ws, provider, plan, state, generation, pending),
            apply_sandbox=lambda ws, sandbox: self._apply_sandbox(
                ws, sandbox, plan, state, generation, desired_state, pending))
        for ws in plan["workspaces"]:
            shared.apply_workspace_sequence(ws, ws["providers"], ws["sandboxes"], adapter)
        state["transientAttempts"] = 0
        self.store.save(state)
        return self._status(plan, generation, "Pending" if pending else
                            ("GenericReady" if desired_state == "Running" else "Stopped"),
                            pending=pending, retry_after_seconds=5 if pending else 0)

    def _stop_pass(self, plan, state, generation):
        """Only stop previously observed IDs; never create or repair dependencies.

        Include retained sandboxes removed from current desired membership.
        Revoked PVC approval or a failed policy prerequisite must not require
        restarting a workload merely to regain the ability to stop it.
        """
        ids = state.get("objectIDs", {})
        references = {f"sandbox/{ws['name']}/{sb['name']}"
                      for ws in plan["workspaces"] for sb in ws["sandboxes"]}
        references.update(key for key in ids if key.startswith("sandbox/"))
        pending = self._stop_references(references, plan, state, generation)
        state["transientAttempts"] = 0
        self.store.save(state)
        return self._status(plan, generation, "Pending" if pending else "Stopped",
                            pending=pending, retry_after_seconds=5 if pending else 0)

    def _stop_references(self, references, plan, state, generation):
        ids = state.get("objectIDs", {})
        pending = []
        for ref in sorted(references):
            _, workspace, name = ref.split("/")
            scope = {"workspace_scope": {"workspace": workspace}}
            sandbox = self._get("GetSandbox", {**scope, "name": name}, "sandbox")
            if sandbox is None:
                continue  # No resource is created to satisfy Stopped intent.
            workspace_obj = self._get("GetWorkspace", {"name": workspace}, "workspace")
            workspace_ref = f"workspace//{workspace}"
            if ref not in ids and ref in state.get("pendingSandboxCreates", {}):
                raise MissingSandboxReceipt("start to recover the sandbox creation receipt before stopping")
            if (ref not in ids or workspace_ref not in ids or workspace_obj is None
                    or sandbox.get("metadata", {}).get("id") != ids[ref]
                    or workspace_obj.get("metadata", {}).get("id") != ids[workspace_ref]):
                raise ContractError("shutdown refuses unrecorded or replaced workspace/sandbox identity")
            self._identity("workspace", "", workspace, workspace_obj, plan, state, default=workspace == "default")
            self._identity("sandbox", workspace, name, sandbox, plan, state)
            phase = sandbox.get("status", {}).get("phase")
            if phase == "SANDBOX_PHASE_STOPPED":
                continue
            if phase not in {"SANDBOX_PHASE_READY", "SANDBOX_PHASE_ERROR"}:
                pending.append(ref)
                continue
            self._mutate("StopSandbox", {**scope, "name": name}, plan, generation)
            pending.append(ref)
        return pending

    def _prepare_workspace(self, ws, plan, state, generation, pending):
        scope = {"workspace_scope": {"workspace": ws["name"]}}
        obj = self._get("GetWorkspace", {"name": ws["name"]}, "workspace")
        if obj is None:
            if ws["name"] == "default":
                raise ContractError("gateway default workspace is missing")
            self._mutate("CreateWorkspace", {"name": ws["name"], "labels": {
                MANAGED: "kubernetes-runtime", OWNER: plan["ownerID"]}}, plan, generation)
            pending.append(f"workspace/{ws['name']}")
            return False
        self._identity("workspace", "", ws["name"], obj, plan, state, default=ws["name"] == "default")
        if obj.get("status", {}).get("phase") != "WORKSPACE_PHASE_ACTIVE":
            pending.append(f"workspace/{ws['name']}")
            return False
        members, token, tokens = [], "", set()
        while True:
            response = self.rpc.call("ListWorkspaceMembers", {**scope, "page_size": 100, "page_token": token})
            members.extend(response.get("members", []))
            token = response.get("next_page_token", "")
            if not token:
                break
            if token in tokens or len(tokens) >= 100:
                raise ContractError("invalid membership pagination")
            tokens.add(token)
        member = next((m for m in members if m.get("principal_subject") == plan["ownerSubject"]), None)
        if member is None:
            self._mutate("AddWorkspaceMember", {**scope, "principal_subject": plan["ownerSubject"],
                "role": "WORKSPACE_ROLE_ADMIN"}, plan, generation)
            pending.append(f"membership/{ws['name']}")
            return False
        if member.get("role") != "WORKSPACE_ROLE_ADMIN":
            raise ContractError("existing owner membership has unexpected role")
        return True

    def _apply_provider(self, ws, provider, plan, state, generation, pending):
        scope = {"workspace_scope": {"workspace": ws["name"]}}
        pname = provider["metadata"]["name"]
        reference = f"{ws['name']}/{pname}"
        existing = self._get("GetProvider", {**scope, "name": pname}, "provider")
        # Persist intent before the RPC: a committed create can outlive the
        # connection (or this process). The pinned gateway durably replays the
        # same caller/request ID/payload and checks the recorded object revision.
        # A subsequent GetProvider, even with our labels, is not a create receipt.
        creations = state.setdefault("pendingProxyProviders", {})
        intent = creations.get(reference)
        if intent is not None and (not isinstance(intent, dict)
                or intent.get("request") != digest(provider)
                or type(intent.get("generation")) is not int or intent["generation"] < 1):
            raise ContractError("pending provider creation changed; explicit recovery is required")
        if existing is None or intent is not None:
            if provider.get("credentials") and intent is None:
                intent = {"request": digest(provider), "generation": generation}
                creations[reference] = intent
                self.store.save(state)
            reply = self._mutate("CreateProvider", {**scope, "provider": provider}, plan,
                                 intent["generation"] if intent else generation)
            if provider.get("credentials") and reply:
                created = reply.get("provider", {})
                self._identity("provider", ws["name"], pname, created, plan, state)
                meta = created["metadata"]
                version = meta.get("resource_version")
                if not version:
                    raise ContractError("missing provider revision")
                state.setdefault("proxyProviderRevisions", {})[reference] = {
                    "version": version, "request": digest(provider)}
                creations.pop(reference, None)
                self.store.save(state)
            elif existing is not None:
                raise ContractError("provider creation receipt unavailable; explicit recovery is required")
            if existing is None:
                pending.append(f"provider/{reference}")
                return False
        self._identity("provider", ws["name"], pname, existing, plan, state)
        expected_credentials = {}
        if provider.get("credentials"):
            recorded = state.get("proxyProviderRevisions", {}).get(f"{ws['name']}/{pname}")
            if recorded != {"version": existing["metadata"].get("resource_version"), "request": digest(provider)}:
                raise ContractError("proxy provider ownership or credential revision requires explicit recovery")
            expected_credentials = dict.fromkeys(provider["credentials"], "REDACTED")
        if (existing.get("type") != provider["type"] or existing.get("config") or existing.get("profile_workspace")
                or existing.get("credentials", {}) != expected_credentials or existing.get("credential_handles")):
            raise ContractError("provider drift or unexpected credential state requires explicit recovery")
        return True

    def _apply_sandbox(self, ws, sandbox, plan, state, generation, desired_state, pending):
        scope = {"workspace_scope": {"workspace": ws["name"]}}
        sname = sandbox["name"]
        ref = f"sandbox/{ws['name']}/{sname}"
        existing = self._get("GetSandbox", {**scope, "name": sname}, "sandbox")
        creates = state.setdefault("pendingSandboxCreates", {})
        pending_create = creates.get(ref)
        if existing is None or pending_create is not None:
            if existing is None and ref in state.get("objectIDs", {}):
                raise ContractError("managed sandbox disappeared; refuse implicit recreation")
            if desired_state == "Stopped":
                pending.append(ref)
                return False
            body = {**scope, **sandbox}
            signature = digest(body)
            if pending_create is None:
                pending_create = {"generation": generation, "digest": signature}
                creates[ref] = pending_create
                self.store.save(state)
            if (not isinstance(pending_create, dict) or pending_create.get("digest") != signature
                    or type(pending_create.get("generation")) is not int or pending_create["generation"] < 1):
                raise ContractError("unacknowledged sandbox create changed; explicit recovery required")
            reply = self._mutate("CreateSandbox", body, plan, pending_create["generation"])
            created = (reply or {}).get("sandbox")
            if not isinstance(created, dict):
                raise ContractError("sandbox creation receipt unavailable; explicit recovery required")
            if existing and existing["metadata"]["id"] != created.get("metadata", {}).get("id"):
                raise ContractError("same-name replacement detected during create replay")
            self._verify_sandbox(created, sandbox)
            self._identity("sandbox", ws["name"], sname, created, plan, state)
            del creates[ref]
            self.store.save(state)
            pending.append(ref)
            return False
        self._verify_sandbox(existing, sandbox)
        self._identity("sandbox", ws["name"], sname, existing, plan, state)
        phase = existing.get("status", {}).get("phase")
        if phase == "SANDBOX_PHASE_ERROR":
            raise ContractError("sandbox reports an error; inspect through authorized diagnostics")
        target = "SANDBOX_PHASE_READY" if desired_state == "Running" else "SANDBOX_PHASE_STOPPED"
        if phase == target:
            return True
        if desired_state == "Running" and phase == "SANDBOX_PHASE_STOPPED":
            self._mutate("StartSandbox", {**scope, "name": sname}, plan, generation)
        elif desired_state == "Stopped" and phase == "SANDBOX_PHASE_READY":
            self._mutate("StopSandbox", {**scope, "name": sname}, plan, generation)
        pending.append(ref)
        return False

    def _verify_sandbox(self, observed, desired):
        if not self._sandbox_spec_matches(observed.get("spec", {}), desired["spec"]):
            raise ContractError("sandbox configuration drift; migration is not implemented")
        if observed.get("metadata", {}).get("annotations", {}).get(REVISION) != desired["annotations"][REVISION]:
            raise ContractError("sandbox desired revision mismatch")
