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

from . import provider as governed
from .core import shared

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
            raise ContractError("state directory must not be a symlink", safe_reason="ReconcilerStateRejected")
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
            raise ContractError("state must not be a symlink", safe_reason="ReconcilerStateRejected")
        try:
            value = json.loads(self.path.read_text())
        except (ValueError, OSError):
            raise ContractError("cannot read retained reconciler state",
                                safe_reason="ReconcilerStateRejected") from None
        if not isinstance(value, dict):
            raise ContractError("retained reconciler state must be an object",
                                safe_reason="ReconcilerStateRejected")
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

    def __init__(self, rpc, state_directory, verify_resources, *, verify_shutdown=None, read_credential=None):
        self.rpc = rpc
        # read_credential(secret, key) -> (value, revision) from the trusted
        # namespace; called only when a value is handed to OpenShell.
        self.read_credential = read_credential
        self.credential_env = {}
        self.store = StateStore(state_directory)
        if not callable(verify_resources):
            raise ContractError("resource verifier is required", safe_reason="InvalidPlan")
        self.verify_resources = verify_resources
        self.verify_shutdown = (verify_shutdown if verify_shutdown is not None else
                                getattr(verify_resources, "verify_shutdown", verify_resources))
        if not callable(self.verify_shutdown):
            raise ContractError("shutdown identity verifier must be callable", safe_reason="InvalidPlan")

    def _get(self, method, request, field):
        try:
            response = self.rpc.call(method, request)
        except RpcError as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise
        if not isinstance(response.get(field), dict):
            raise ContractError("gateway returned an invalid object", safe_reason="GatewayMismatch")
        return response[field]

    def _mutate(self, method, request, plan, generation, identity=None):
        body = copy.deepcopy(request)
        # `identity` replaces a request that carries a credential value, so the
        # idempotency key never depends on the secret itself.
        body["request_id"] = request_id(plan["ownerID"], method,
                                        {"request": request if identity is None else identity,
                                         "generation": generation})
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
            raise ContractError("managed object is being deleted", safe_reason="IdentityConflict")
        if meta.get("name") != name or not meta.get("id"):
            raise ContractError("gateway object identity is missing or changed", safe_reason="IdentityConflict")
        if kind != "workspace" and meta.get("workspace", "default") != workspace:
            raise ContractError("gateway object is in the wrong workspace", safe_reason="IdentityConflict")
        if not default and (labels.get(OWNER) != plan["ownerID"] or labels.get(MANAGED) != "kubernetes-runtime"):
            raise ContractError("refusing to adopt an object owned by another installation",
                                safe_reason="IdentityConflict")
        key = f"{kind}/{workspace}/{name}"
        previous = state.setdefault("objectIDs", {}).get(key)
        if previous is not None and previous != meta["id"]:
            raise ContractError("same-name replacement detected; explicit recovery is required",
                                safe_reason="IdentityConflict")
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
            raise ContractError("a positive intent generation and Running/Stopped state are required",
                                safe_reason="InvalidIntent")
        body = {k: v for k, v in plan.items() if k != "revision"}
        if plan.get("sourceRevision") != SOURCE_REVISION or plan.get("schemaVersion") != 1 or digest(body) != plan.get("revision"):
            raise ContractError("invalid or modified compiled plan", safe_reason="InvalidPlan")
        if plan.get("mode") not in ("container", "kata") or plan.get("requestedPlacement") != {
                "supervisor": "container", "workload": plan["mode"]}:
            raise ContractError("stock adapter requires an ordinary-container supervisor",
                                safe_reason="PlacementRejected")
        with self.store.locked():
            state = self.store.load()
            identity = {key: plan[key] for key in ["ownerID", "namespaceUID", "ownerSubject", "mode"]}
            if state and state.get("identity") != identity:
                raise ContractError("workspace identity, owner and deployment mode are immutable",
                                    safe_reason="IdentityConflict")
            if state.get("pendingProxyProviders") or state.get("proxyProviderRevisions"):
                # Providers created through the removed credential proxy cannot
                # be adopted: their revisions and credentials are not ours.
                raise ContractError("workspace was enrolled with the SAW credential proxy; "
                                    "start a new generation to re-enroll it", safe_reason="ReenrollRequired")
            previous = state.get("intent", {})
            intent = {"generation": generation, "revision": plan["revision"], "desiredState": desired_state}
            if previous.get("generation", 0) > generation or (previous.get("generation") == generation and previous != intent):
                raise ContractError("stale generation or conflicting intent at the same generation",
                                    safe_reason="StaleIntent")
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
            raise ContractError("gateway version or active compute driver differs from approved inputs",
                                safe_reason="GatewayMismatch")
        if desired_state == "Stopped":
            return self._stop_pass(plan, state, generation)
        retired = plan.get("retiredSandboxes", {})
        if retired:
            refs = {"sandbox/" + name for name in retired}
            if any(state.get("objectIDs", {}).get("sandbox/" + k) != v for k, v in retired.items()):
                raise ContractError("refusing to stop a sandbox without its recorded identity",
                                    safe_reason="SandboxStateMismatch")
            pending = self._stop_references(refs, plan, state, generation)
            if pending:
                return self._status(plan, generation, "Pending", pending=pending, retry_after_seconds=5)
        for provider_type in sorted({p["type"] for w in plan["workspaces"] for p in w["providers"]}):
            # Resolve platform scope explicitly (workspace_scope omitted). A
            # workspace administrator's same-name custom profile is not enough.
            profile = self.rpc.call("GetProviderProfile", {"id": provider_type}).get("profile", {})
            credentialed = any(p.get("credentialRef") for w in plan["workspaces"] for p in w["providers"]
                               if p["type"] == provider_type)
            if credentialed:
                # OpenShell attaches this credential only to the profile's
                # endpoints, so those must be exactly the approved ones.
                slots = profile.get("credentials", [])
                if (profile.get("id") != provider_type or len(slots) != 1
                        or not slots[0].get("env_vars")):
                    raise ContractError("provider profile must declare exactly one credential",
                                        safe_reason="ProviderProfileMismatch")
                self._verify_profile_endpoints(plan, provider_type, profile)
                self.credential_env[provider_type] = slots[0]["env_vars"][0]
                continue
            if (profile.get("id") != provider_type or profile.get("credentials")
                    or not profile.get("source", "").startswith("interceptor/")):
                raise ContractError("provider profile is not a governed credential-free platform profile",
                                    safe_reason="ProviderProfileMismatch")
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

    @staticmethod
    def _verify_profile_endpoints(plan, provider_type, profile):
        """A credentialed profile may list only the approved endpoints, all enforced."""
        try:
            approved = governed.approved_endpoints(provider_type, plan.get("customInferenceURL"))
        except (ValueError, TypeError):
            approved = None
        live = set()
        for endpoint in profile.get("endpoints", []):
            if (endpoint.get("enforcement") != "NETWORK_ENFORCEMENT_MODE_ENFORCE"
                    or endpoint.get("allowed_ips") or not endpoint.get("host")):
                approved = None
                break
            for port in endpoint.get("ports") or [endpoint.get("port", 443)]:
                live.add((endpoint["host"], int(port)))
        if not approved or live != approved:
            raise ContractError("provider profile endpoints differ from the approved ones",
                                safe_reason="ProviderProfileMismatch")
        # Host and port say where the key goes; path, protocol, access and
        # rules say what it may do there. A shipped profile must match exactly.
        try:
            specs = governed.approved_endpoint_specs(provider_type)
        except (ValueError, TypeError):
            specs = []
        if specs is not None and sorted(governed.endpoint_spec(e, shipped=False)
                                        for e in profile.get("endpoints", [])) != specs:
            raise ContractError("provider profile endpoints differ from the approved ones",
                                safe_reason="ProviderProfileMismatch")

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
                raise MissingSandboxReceipt("start to recover the sandbox creation receipt before stopping",
                                            safe_reason="SandboxStateMismatch")
            if (ref not in ids or workspace_ref not in ids or workspace_obj is None
                    or sandbox.get("metadata", {}).get("id") != ids[ref]
                    or workspace_obj.get("metadata", {}).get("id") != ids[workspace_ref]):
                raise ContractError("shutdown refuses unrecorded or replaced workspace/sandbox identity",
                                    safe_reason="IdentityConflict")
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
                raise ContractError("gateway default workspace is missing", safe_reason="WorkspaceRejected")
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
                raise ContractError("invalid membership pagination", safe_reason="WorkspaceRejected")
            tokens.add(token)
        member = next((m for m in members if m.get("principal_subject") == plan["ownerSubject"]), None)
        if member is None:
            self._mutate("AddWorkspaceMember", {**scope, "principal_subject": plan["ownerSubject"],
                "role": "WORKSPACE_ROLE_ADMIN"}, plan, generation)
            pending.append(f"membership/{ws['name']}")
            return False
        if member.get("role") != "WORKSPACE_ROLE_ADMIN":
            raise ContractError("existing owner membership has unexpected role",
                                safe_reason="WorkspaceRejected")
        return True

    def _apply_provider(self, ws, provider, plan, state, generation, pending):
        scope = {"workspace_scope": {"workspace": ws["name"]}}
        pname = provider["metadata"]["name"]
        reference = f"{ws['name']}/{pname}"
        ref = provider.get("credentialRef")
        refresh = provider.get("refresh")
        # Only OpenShell Provider fields go to the gateway; it rejects unknown ones.
        request = {k: v for k, v in provider.items() if k not in ("credentialRef", "refresh")}
        source = None
        if ref:
            if not callable(self.read_credential):
                raise ContractError("no credential source configured", safe_reason="ProviderRejected")
            if refresh:
                # The Secret holds only refresh material; OpenShell mints the
                # access token, so the provider starts without a value and the
                # material's Secret revision is the source.
                _, source = self.read_credential(ref["secret"], refresh["material"][0])
            else:
                value, source = self.read_credential(ref["secret"], ref["key"])
                request["credentials"] = {self.credential_env[provider["type"]]: value}
        # What we record and key requests on: the plan entry (a reference, never
        # the value) plus the Secret revision the value came from.
        identity = {"provider": provider, "source": source}
        existing = self._get("GetProvider", {**scope, "name": pname}, "provider")
        # Persist intent before the RPC: a committed create can outlive the
        # connection (or this process). The pinned gateway durably replays the
        # same caller/request ID/payload and checks the recorded object revision.
        # A subsequent GetProvider, even with our labels, is not a create receipt.
        creations = state.setdefault("pendingProviders", {})
        intent = creations.get(reference)
        if intent is not None and (not isinstance(intent, dict)
                or intent.get("request") != digest(identity)
                or type(intent.get("generation")) is not int or intent["generation"] < 1):
            raise ContractError("pending provider creation changed; explicit recovery is required",
                                safe_reason="ProviderRejected")
        revisions = state.setdefault("providerRevisions", {})
        if existing is None or intent is not None:
            if ref and intent is None:
                intent = {"request": digest(identity), "generation": generation}
                creations[reference] = intent
                self.store.save(state)
            reply = self._mutate("CreateProvider", {**scope, "provider": request}, plan,
                                 intent["generation"] if intent else generation,
                                 identity=identity if ref else None)
            if ref and reply:
                self._record_provider(ws, pname, reply, plan, state, identity)
                creations.pop(reference, None)
                self.store.save(state)
            elif existing is not None:
                raise ContractError("provider creation receipt unavailable; explicit recovery is required",
                                    safe_reason="ProviderRejected")
            if existing is None:
                pending.append(f"provider/{reference}")
                return False
        self._identity("provider", ws["name"], pname, existing, plan, state)
        expected_credentials = {}
        updates = state.setdefault("pendingProviderUpdates", {})
        update = updates.get(reference)
        if ref and update is not None:
            # A credential update was sent but its reply was lost. If the
            # provider moved on from the version we updated, that update (or
            # its replay) applied: record it, as long as the provider still has
            # exactly our credential slot. Otherwise it is resent below.
            current = existing["metadata"].get("resource_version")
            if current != update.get("from"):
                if (existing.get("type") != provider["type"] or existing.get("config")
                        or existing.get("credentials", {}) != dict.fromkeys(request.get("credentials", {}), "REDACTED")
                        or update.get("provider") != digest(provider)):
                    raise ContractError("provider changed during a credential update; explicit recovery is required",
                                        safe_reason="ProviderRejected")
                revisions[reference] = {"version": current, "provider": digest(provider),
                                        "source": update.get("source")}
                updates.pop(reference)
                self.store.save(state)
        if ref:
            recorded = revisions.get(reference, {})
            # OpenShell rewrites a refreshed provider (each minted token bumps
            # its version), so only a static credential pins the version.
            if (recorded.get("provider") != digest(provider)
                    or (not refresh and recorded.get("version") != existing["metadata"].get("resource_version"))):
                raise ContractError("provider ownership or credential revision requires explicit recovery",
                                    safe_reason="ProviderRejected")
            if recorded.get("source") != source and not refresh:
                # The Secret rotated: hand OpenShell the new value. Persist the
                # intent first, as for creates; a lost reply is resolved above.
                updates[reference] = {"provider": digest(provider), "source": source,
                                      "from": existing["metadata"].get("resource_version")}
                self.store.save(state)
                reply = self._mutate("UpdateProvider", {**scope, "provider": request}, plan, generation,
                                     identity=identity)
                if reply:
                    self._record_provider(ws, pname, reply, plan, state, identity)
                    updates.pop(reference, None)
                    self.store.save(state)
                pending.append(f"provider/{reference}")
                return False
            if refresh:
                if not self._apply_refresh(ws, provider, plan, state, generation, source, pending):
                    return False
                # Either nothing yet or the one token OpenShell minted.
                minted = {self.credential_env[provider["type"]]: "REDACTED"}
                expected_credentials = minted if existing.get("credentials") else {}
            else:
                expected_credentials = dict.fromkeys(request["credentials"], "REDACTED")
        if (existing.get("type") != provider["type"] or existing.get("config") or existing.get("profile_workspace")
                or existing.get("credentials", {}) != expected_credentials):
            raise ContractError("provider drift or unexpected credential state requires explicit recovery",
                                safe_reason="ProviderRejected")
        return True

    def _apply_refresh(self, ws, provider, plan, state, generation, source, pending):
        """Hand OpenShell the refresh material once per Secret revision.

        OpenShell then refreshes the access token itself and keeps any rotated
        refresh token; re-sending the Secret's original one would undo that.
        A revision counts as configured only once the gateway's refresh status
        shows the credential without an error. Until then a missing status
        entry is pending, and a configure whose reply was lost is sent again
        (same request ID, so the gateway replays rather than repeats it).
        """
        scope = {"workspace_scope": {"workspace": ws["name"]}}
        pname = provider["metadata"]["name"]
        reference = f"{ws['name']}/{pname}"
        key = self.credential_env[provider["type"]]
        configured = state.setdefault("refreshConfigured", {})
        sent = state.setdefault("refreshSent", {})
        if configured.get(reference) != source:
            attempt = sent.get(reference) or {}
            if attempt.get("source") != source or not attempt.get("acknowledged"):
                ref, refresh = provider["credentialRef"], provider["refresh"]
                material = {}
                for name in refresh["material"]:
                    value, revision = self.read_credential(ref["secret"], name)
                    if revision != source:
                        pending.append(f"provider/{reference}")
                        return False  # the Secret changed while reading; next pass
                    material[name] = value
                request = {**scope, "provider": pname, "credential_key": key,
                           "strategy": "PROVIDER_CREDENTIAL_REFRESH_STRATEGY_" + refresh["strategy"].upper(),
                           "material": material, "secret_material_keys": sorted(material)}
                identity = {"refresh": provider, "source": source}
                configure = self._mutate("ConfigureProviderRefresh", request, plan, generation, identity=identity)
                rotate = self._mutate("RotateProviderCredential",
                                      {**scope, "provider": pname, "credential_key": key},
                                      plan, generation, identity=identity)
                # Both returned: a reply, or ALREADY_EXISTS (_mutate returns None
                # for that only; every other failure raises before this line,
                # so a lost reply is resent with the same request ID). Observe
                # the refresh status from here on; never resend into ALREADY_EXISTS.
                sent[reference] = {"source": source, "acknowledged": True}
                self.store.save(state)
                pending.append(f"provider/{reference}")
                return False
        status = self.rpc.call("GetProviderRefreshStatus", {**scope, "provider": pname, "credential_key": key})
        entries = [c for c in status.get("credentials", []) if c.get("credential_key") == key]
        if any(c.get("last_error") or c.get("failure_code") for c in entries):
            raise ContractError("provider credential refresh is failing; see the gateway's refresh status",
                                safe_reason="ProviderRefreshFailed")
        if not entries:
            if configured.get(reference) == source:
                # It was working and the gateway no longer has it: refreshing stopped.
                raise ContractError("provider credential refresh is no longer configured at the gateway",
                                    safe_reason="ProviderRefreshFailed")
            pending.append(f"provider/{reference}")   # status not populated yet
            return False
        if configured.get(reference) != source:
            configured[reference] = source
            sent.pop(reference, None)
            self.store.save(state)
        return True

    def _record_provider(self, ws, pname, reply, plan, state, identity):
        created = reply.get("provider", {})
        self._identity("provider", ws["name"], pname, created, plan, state)
        version = created.get("metadata", {}).get("resource_version")
        if not version:
            raise ContractError("missing provider revision", safe_reason="ProviderRejected")
        state.setdefault("providerRevisions", {})[f"{ws['name']}/{pname}"] = {
            "version": version, "provider": digest(identity["provider"]), "source": identity["source"]}

    def _apply_sandbox(self, ws, sandbox, plan, state, generation, desired_state, pending):
        scope = {"workspace_scope": {"workspace": ws["name"]}}
        sname = sandbox["name"]
        ref = f"sandbox/{ws['name']}/{sname}"
        existing = self._get("GetSandbox", {**scope, "name": sname}, "sandbox")
        creates = state.setdefault("pendingSandboxCreates", {})
        pending_create = creates.get(ref)
        if existing is None or pending_create is not None:
            if existing is None and ref in state.get("objectIDs", {}):
                raise ContractError("managed sandbox disappeared; refuse implicit recreation",
                                    safe_reason="SandboxStateMismatch")
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
                raise ContractError("unacknowledged sandbox create changed; explicit recovery required",
                                    safe_reason="SandboxStateMismatch")
            reply = self._mutate("CreateSandbox", body, plan, pending_create["generation"])
            created = (reply or {}).get("sandbox")
            if not isinstance(created, dict):
                raise ContractError("sandbox creation receipt unavailable; explicit recovery required",
                                    safe_reason="SandboxStateMismatch")
            if existing and existing["metadata"]["id"] != created.get("metadata", {}).get("id"):
                raise ContractError("same-name replacement detected during create replay",
                                    safe_reason="IdentityConflict")
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
            raise ContractError("sandbox reports an error; inspect through authorized diagnostics",
                                safe_reason="SandboxRejected")
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
            raise ContractError("sandbox configuration drift; migration is not implemented",
                                safe_reason="SandboxDrift")
        if observed.get("metadata", {}).get("annotations", {}).get(REVISION) != desired["annotations"][REVISION]:
            raise ContractError("sandbox desired revision mismatch", safe_reason="SandboxDrift")
