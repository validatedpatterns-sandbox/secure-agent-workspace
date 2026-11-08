"""Translate a deliberately small SAW profile subset to pinned OpenShell RPCs.

Only the administrator binding file may select PVCs/resources/RuntimeClasses.
No API calls, secret reads or mutations happen during compilation.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path, PurePosixPath

from .core import shared
from . import harness
from . import provider as governed

SOURCE_REVISION = "305c8b3d7bbdb97a6f2f7264c3ad43b0087c307f"
OWNER = "saw.redhat.com/runtime-owner"
REVISION = "saw.redhat.com/desired-sha256"
MANAGED = "saw.redhat.com/managed-by"
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
QUANTITY = re.compile(r"[1-9][0-9]*(?:m|Ki|Mi|Gi|Ti)?\Z")


class ContractError(ValueError):
    """An input is invalid or requires an unimplemented capability."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def request_id(owner, operation, value):
    return str(uuid.uuid5(uuid.UUID(owner), operation + ":" + digest(value)))


def mapping(value, allowed, required, where):
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ContractError(f"{where} must be an object")
    if set(value) - set(allowed) or set(required) - set(value):
        raise ContractError(f"{where} has unknown or missing fields")
    return value


def name(value, where, max_length=19):
    if not isinstance(value, str) or len(value) > max_length or not NAME.fullmatch(value):
        raise ContractError(f"{where} must be a DNS label of at most {max_length} characters")
    return value


def _claim(binding, workspace, mount_path, volume_name):
    mapping(binding, {"claimName", "uid", "readOnly"}, {"claimName", "uid", "readOnly"}, "PVC binding")
    # Intentionally stricter than Kubernetes subdomains for this first adapter.
    name(binding["claimName"], "claimName", 63)
    if not isinstance(binding["uid"], str) or not binding["uid"]:
        raise ContractError("PVC binding requires its observed UID")
    if type(binding["readOnly"]) is not bool:
        raise ContractError("PVC readOnly must be explicit boolean")
    volume = {"name": volume_name, "persistent_volume_claim": {
        "claim_name": binding["claimName"], "read_only": binding["readOnly"]}}
    mount = {"name": volume_name, "mount_path": mount_path, "read_only": binding["readOnly"]}
    reference = {"workspace": workspace, "name": binding["claimName"], "uid": binding["uid"]}
    return volume, mount, reference


def _storage(binding, workspace):
    mapping(binding, {"workspace", "mounts", "resources", "browser", "toolGate"}, {"workspace"}, "sandbox binding")
    volume, mount, reference = _claim(binding["workspace"], workspace, "/sandbox/workspace", "saw-workspace")
    if reference["name"].startswith(("saw-gate-", "saw-audit-")):
        raise ContractError("reserved tool PVC cannot be used as a workspace")
    if binding["workspace"]["readOnly"]:
        raise ContractError("/sandbox/workspace must be writable")
    volumes, mounts, refs = [volume], [mount], [reference]
    if "toolGate" in binding:
        gate = binding["toolGate"]
        mapping(gate, {"trusted", "audit", "ownerLogin", "receiptKey", "modelSelector", "harness"}, {"trusted", "audit", "ownerLogin"}, "toolGate")
        name(gate["ownerLogin"], "toolGate ownerLogin", 63)
        for field, volume_name, path, readonly in [
            ("trusted", "saw-gate", "/sandbox/.saw/trusted", True),
            ("audit", "saw-audit", "/sandbox/.saw/audit", False),
        ]:
            volume, mount, reference = _claim(gate[field], workspace, path, volume_name)
            if not reference["name"].startswith(volume_name + "-") or mount["read_only"] != readonly:
                raise ContractError(f"{field} requires the reserved claim prefix and mount mode")
            mount["sub_path"] = "bundle" if readonly else "log"
            volumes.append(volume)
            mounts.append(mount)
            refs.append(reference)
    extra = binding.get("mounts", [])
    if not isinstance(extra, list) or len(extra) > 16:
        raise ContractError("mounts must be a list of at most 16 additional PVCs")
    for i, item in enumerate(extra):
        mapping(item, {"claimName", "uid", "readOnly", "mountPath"},
                {"claimName", "uid", "readOnly", "mountPath"}, "mount")
        path = item["mountPath"]
        # The driver reserves /sandbox itself. Mount the retained workspace below it. Additional data may
        # only mount under /data, never over trusted/runtime/configuration trees.
        if not isinstance(path, str) or not (path == "/data" or path.startswith("/data/")):
            raise ContractError("additional mounts must be at /data or below it")
        if str(PurePosixPath(path)) != path or ".." in PurePosixPath(path).parts or any(ord(c) < 32 for c in path):
            raise ContractError("mountPath must be normalized")
        for existing in mounts:
            other = existing["mount_path"]
            if path == other or path.startswith(other + "/") or other.startswith(path + "/"):
                raise ContractError("overlapping mounts are not supported")
        claim = {k: v for k, v in item.items() if k != "mountPath"}
        volume, mount, reference = _claim(claim, workspace, path, f"data-{i}")
        if reference["name"].startswith(("saw-gate-", "saw-audit-")):
            raise ContractError("reserved tool PVC cannot be used as a data mount")
        if any(r["name"] == reference["name"] for r in refs):
            raise ContractError("one PVC cannot be attached through multiple bindings")
        volumes.append(volume); mounts.append(mount); refs.append(reference)
    resources = binding.get("resources", {})
    mapping(resources, {"requests", "limits"}, set(), "resources")
    for group in resources.values():
        mapping(group, {"cpu", "memory", "ephemeral-storage"}, set(), "resource quantities")
        if any(not isinstance(v, str) or not QUANTITY.fullmatch(v) for v in group.values()):
            raise ContractError("resource quantities must be positive supported quantity strings")
    return {"volumes": volumes, "containers": {"agent": {
        "volume_mounts": mounts, "resources": resources}}}, refs


def compile_profile(profile_dir, config):
    """Directory frontend for the same flat ConfigMap compiler used by the controller."""
    root = Path(profile_dir)
    if not root.is_dir() or root.is_symlink():
        raise ContractError("profile path must be a real directory")
    files = {}
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or directory.is_symlink():
            raise ContractError("profile must contain workspace directories only")
        if "__" in directory.name:
            raise ContractError("workspace directory cannot contain a flat-key separator")
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ContractError("profile documents must be regular files, not symlinks")
            try:
                files[f"profiles__input__{directory.name}__{path.name}"] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                raise ContractError("cannot read profile document") from None
    return compile_profile_files(files, config)


def _openclaw_startup(kind, info):
    slot, _ = governed.requirements(kind, info.get("baseUrl"))
    endpoint = info.get("baseUrl") or shared.NATIVE_BASE_URLS[kind]
    provider_id = shared.openclaw_managed_provider_id(kind)
    timeout = info.get("timeoutSeconds", 0)
    return (Path(__file__).with_name("openclaw.sh").read_text()
            .replace("@SAW_PROVIDER_KEY@", json.dumps(provider_id))
            .replace("@SAW_BASE_URL@", json.dumps(endpoint))
            .replace("@SAW_TIMEOUT@", f"timeoutSeconds: {timeout}, " if timeout else "")
            .replace("@SAW_API@", "anthropic-messages" if info["protocol"] == "anthropic" else "openai-completions")
            .replace("@SAW_KEY_ENV@", slot["env_vars"][0])
            .replace("@SAW_PROVIDER_ID@", provider_id))


def _compatible_inference(workspace, sandbox, config):
    """Resolve the shared BOM against explicit credential and public-input bindings."""
    provider = shared.select_inference_provider(
        workspace.providers, sandbox.providers,
        inference_ref=(sandbox.inference or {}).get("providerRef"))
    if provider is None or provider.type not in {"openai", "anthropic", "nvidia", "custom-inference"}:
        raise ContractError("agent requires a supported bound inference provider")
    custom = provider.type == "custom-inference"
    protocol = "openai" if custom else shared.PROVIDER_PROTOCOLS[provider.type]
    endpoint = (config.get("customInferenceURL") if custom else
                shared.NATIVE_BASE_URLS.get(provider.type) or shared.PROTOCOL_NATIVE_BASE_URLS[protocol])
    if custom:
        try:
            governed.custom_host(endpoint)
        except (ValueError, TypeError) as exc:
            raise ContractError("custom inference endpoint is not approved") from exc
    inputs = config.get("modelInputs", {})
    credentials = {(b["secret"], b["key"]) for b in config.get("proxyBindings", [])}
    def read_model(secret, key):
        if secret != provider.credential_secret or (secret, key) in credentials:
            raise ContractError("model input is outside the public inference binding")
        if custom and key == "url":
            return endpoint
        if custom and key != "model":
            raise ContractError("unapproved custom inference input")
        return inputs.get(secret + "." + key, "")
    try:
        if sandbox.inference:
            info = shared.resolve_inference(workspace, sandbox, read_model, lambda *_: None,
                                            forbidden=credentials)
        else:
            info = {"providerRef": provider.name,
                    "protocol": shared.sandbox_protocol(sandbox, provider),
                    "baseUrl": shared.sandbox_endpoint(sandbox, provider),
                    "model": shared.sandbox_model(sandbox, provider), "timeoutSeconds": 0}
    except shared.InstallerError as exc:
        raise ContractError("invalid sandbox inference inputs") from exc
    if (provider.name not in sandbox.providers or info["baseUrl"] not in ("", endpoint)
            or info["protocol"] != protocol or info.get("models")
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,180}", info["model"])):
        raise ContractError("inference inputs differ from the approved endpoint or supported protocol")
    info["baseUrl"] = endpoint
    return provider, info


def compile_profile_files(files, config):
    """Compile stock SAW ConfigMap data with administrator-approved bindings.

    The shared VM/Kubernetes core owns document parsing, models and semantic
    validation. This adapter adds only backend capabilities, attachment approval
    inputs and the pinned Kubernetes driver envelope. No credentials are read.
    """
    if not isinstance(files, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                          for k, v in files.items()):
        raise ContractError("profile data must be a mapping of flat file names to YAML text")
    try:
        documents, raw_harness, index = shared.split_bom_files(files)
        bundles = harness.read_bundles(raw_harness, index)
        profiles = shared.parse_profiles(documents, strict=True, document_check=_check_document_capabilities)
        shared.validate_profiles(profiles, governed=True)
    except shared.InstallerError:
        # Parser errors may contain input snippets. The controller publishes
        # status; do not accidentally turn that into a profile/secret echo.
        raise ContractError("profile documents fail shared SAW schema or semantic validation") from None
    mapping(config, {"ownerID", "namespace", "namespaceUID", "ownerSubject", "mode",
                     "workloadRuntimeClass", "workloadRuntimeClassUID", "bindings",
                     "approvedCredentialFreeProviders", "gatewayVersion", "retiredSandboxes", "modelInputs", "proxyBindings", "customInferenceURL"},
            {"ownerID", "namespace", "namespaceUID", "ownerSubject", "mode", "bindings",
             "approvedCredentialFreeProviders", "gatewayVersion"}, "administrator configuration")
    try:
        owner = str(uuid.UUID(config["ownerID"]))
        if uuid.UUID(owner).int == 0:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ContractError("ownerID must be a nonzero UUID") from None
    name(config["namespace"], "namespace", 63)
    for key in ["namespaceUID", "ownerSubject", "gatewayVersion"]:
        if not isinstance(config[key], str) or not config[key].strip():
            raise ContractError(f"{key} must be a nonempty string")
    mode = config["mode"]
    runtime = config.get("workloadRuntimeClass", "")
    if mode != "container":
        raise ContractError("this adapter only accepts container")
    if runtime or config.get("workloadRuntimeClassUID"):
        raise ContractError("container mode must not select a RuntimeClass")
    approved = config["approvedCredentialFreeProviders"]
    if not isinstance(approved, list) or any(not isinstance(p, str) for p in approved):
        raise ContractError("approvedCredentialFreeProviders must be a list")
    bindings = config["bindings"]
    if not isinstance(bindings, dict):
        raise ContractError("bindings must be an object")
    workspaces, all_refs, used_bindings = [], [], set()
    for _, workspace in shared.enabled_workspaces(profiles):
        ws_name = name(workspace.name, "workspace")
        providers = []
        for provider in workspace.providers:
            if not provider.enabled:
                continue
            name(provider.name, "provider")
            name(provider.type, "provider type")
            # All semantic checks (references, credentialFree, governed names)
            # live in the common core. The trusted proxy owns private credentials and refresh.
            entry = {"metadata": {"name": provider.name, "labels": {
                MANAGED: "kubernetes-runtime", OWNER: owner}}, "type": provider.type}
            if not config.get("proxyBindings") and (provider.refresh_strategy or provider.credentials_spec or provider.credential_secret_key != "api_key"):
                raise ContractError("provider requires an unported credential/refresh capability or approval")
            if provider.credential_free:
                if provider.type == "custom-inference":
                    raise ContractError("custom inference requires a bound credential")
                if provider.type not in approved:
                    raise ContractError("credential-free provider requires administrator approval")
            elif config.get("proxyBindings"):
                try:
                    entry["credentials"] = governed.checked_marker(provider, config["proxyBindings"], config.get("customInferenceURL"))
                except ValueError as exc:
                    raise ContractError(str(exc)) from exc
            else:
                raise ContractError("provider requires an unported credential/refresh capability or approval")
            providers.append(entry)
        sandboxes = []
        for sandbox in workspace.sandboxes:
            if not sandbox.enabled:
                continue
            name(sandbox.name, "sandbox")
            command = ["sh", "-c", "sleep infinity"]
            if sandbox.env or sandbox.model or sandbox.agent != "openclaw":
                raise ContractError("harness/UI/inference/env capability is not yet ported to Kubernetes")
            if sandbox.ui and (sandbox.type not in ("openclaw","nemoclaw") or sandbox.ui != {"route": True}
                               or not bindings.get(f"{ws_name}/{sandbox.name}", {}).get("browser")):
                raise ContractError("UI route capability requires the matching approved OpenClaw browser binding")
            if sandbox.type in ("openclaw", "nemoclaw"):
                inference_provider, info = _compatible_inference(workspace, sandbox, config)
                if not any(p["metadata"]["name"] == inference_provider.name and p.get("credentials")
                           for p in providers):
                    raise ContractError("agent requires an explicitly bound inference credential")
                kind = inference_provider.type
                script = _openclaw_startup(kind, info)
                browser = bindings.get(f"{ws_name}/{sandbox.name}", {}).get("browser")
                extra = ""
                if browser is not None:
                    if "toolGate" not in bindings[f"{ws_name}/{sandbox.name}"]:
                        raise ContractError("browser requires the read-only tool gate for its relay proof")
                    mapping(browser, {"origin", "ownerLogin"}, {"origin", "ownerLogin"}, "browser")
                    origin, login = browser["origin"], browser["ownerLogin"]
                    if (not isinstance(origin, str) or not re.fullmatch(r"https://[a-z0-9.-]+", origin)
                            or not isinstance(login, str) or not NAME.fullmatch(login)):
                        raise ContractError("browser requires an explicit HTTPS origin and owner login")
                    extra = ("const proof = fs.readFileSync('/sandbox/.saw/trusted/relay-proof','ascii');\n"
                             "if (!/^[a-f0-9]{64}$/.test(proof)) throw new Error('invalid browser relay proof');\n"
                             "config.gateway.trustedProxies = ['127.0.0.1/32','::1/128'];\n"
                             "config.gateway.controlUi = {allowedOrigins:[" + json.dumps(origin) + "]};\n"
                             "config.gateway.auth = {mode:'trusted-proxy',password:config.gateway.auth.token,"
                             "trustedProxy:{userHeader:'x-saw-relay-identity',allowUsers:[" + json.dumps(config["ownerSubject"]) + " + '.' + proof],"
                             "allowLoopback:true,deviceAutoApprove:{enabled:true,scopes:['operator.read','operator.write']}}};\n")
                script = script.replace("@SAW_BROWSER_CONFIG@\n", extra)
                command = ["sh", "-ec", script, "saw-openclaw", info["model"]]
            elif sandbox.type != "generic" or sandbox.inference:
                raise ContractError("agent or inference capability is not yet ported to Kubernetes")
            if not IMAGE.fullmatch(sandbox.image):
                raise ContractError("sandbox image must be pinned by sha256 digest")
            references = sandbox.providers
            if len(set(references)) != len(references):
                raise ContractError("sandbox provider references must be unique")
            key = f"{ws_name}/{sandbox.name}"
            if key not in bindings:
                raise ContractError(f"{key} requires an administrator-approved retained workspace PVC")
            used_bindings.add(key)
            if sandbox.type not in ("openclaw", "nemoclaw") and "browser" in bindings[key]:
                raise ContractError("browser settings require an OpenClaw sandbox")
            driver, refs = _storage(bindings[key], ws_name)
            all_refs.extend(refs)
            if "toolGate" in bindings[key]:
                if sandbox.type not in ("openclaw", "nemoclaw"):
                    raise ContractError("toolGate requires an OpenClaw sandbox")
                login = bindings[key]["toolGate"]["ownerLogin"]
                if browser and login != browser["ownerLogin"]:
                    raise ContractError("browser and tool gate owners must match")
                identity = shared.tool_gate_identity(login, config["ownerSubject"], ws_name, sandbox.name)
                assets = Path(shared.__file__).parent
                receipt_key = bindings[key]["toolGate"].get("receiptKey")
                try:
                    _, _, gate_digest, _ = shared.tool_gate_bundle(assets, identity, receipt_key)
                except shared.InstallerError as exc:
                    raise ContractError(str(exc)) from exc
                script = Path(__file__).with_name("tool_gate_preflight.js").read_text()
                if bindings[key]["toolGate"].get("modelSelector") is True:
                    if not receipt_key:
                        raise ContractError("mutable model requires a trusted gate")
                    # The shared model resolver validates the original choice.
                    # The command is stable across an owner's later selections.
                    command[-1] = "model-from-gate"
                    command[2] = command[2].replace("const model = process.argv[2];", """
const selection = JSON.parse(fs.readFileSync('/sandbox/.saw/trusted/model.json','utf8'));
if (!Number.isSafeInteger(selection.generation) || selection.generation < 1 ||
    typeof selection.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(selection.model))
  throw new Error('invalid published model');
const model = selection.model;
""")
                    if kind in {"custom-inference", "nvidia"}:
                        command[2] = command[2].replace("[A-Za-z0-9._-]{0,99}", r"[A-Za-z0-9._\/-]{0,99}")
                    script = script.replace("for (const path of treeFiles(root).sort()) {",
                        "for (const path of treeFiles(root).sort()) {\n  if (path === root + '/model.json') continue;")
                if browser:
                    script = script.replace("for (const path of treeFiles(root).sort()) {",
                        "for (const path of treeFiles(root).sort()) {\n  if (path === root + '/relay-proof') continue;")
                if receipt_key:
                    # Keep the VM-style file preflight for previously published plans.
                    script = script[:script.index("if (!fs.lstatSync(audit)")] + """
config.plugins = {allow:['saw-tool-gate'],load:{paths:[root+'/plugin']},
                  entries:{'saw-tool-gate':{enabled:true}}};
config.tools = {allow:['read','write','exec']};
"""
                    command[2] = command[2].replace("exec openclaw gateway", """openclaw plugins list --json > "$TMPDIR/saw-plugins.json"
node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1])).plugins.find(x=>x.id==="saw-tool-gate");if(!p?.enabled||p.status!=="loaded"||p.rootDir!=="/sandbox/.saw/trusted/plugin")process.exit(1)' "$TMPDIR/saw-plugins.json"
exec openclaw gateway""")
                    if browser:
                        command[2] = command[2].replace("scopes:['operator.read','operator.write']",
                            "scopes:['operator.read','operator.write','operator.approvals']")
                command[2] = command[2].replace("const target = process.env.OPENCLAW_CONFIG_PATH;",
                    script.replace("@SAW_GATE_DIGEST@", gate_digest) + "\nconst target = process.env.OPENCLAW_CONFIG_PATH;")
            gate = bindings[key].get("toolGate", {})
            try:
                expected_harness = harness.binding_for(sandbox, bundles)
                if expected_harness != gate.get("harness"):
                    raise ContractError("sandbox harness differs from its enrolled binding")
                if expected_harness:
                    if not gate.get("receiptKey") or sandbox.type not in ("openclaw", "nemoclaw"):
                        raise ContractError("harness requires an enrolled agent and signed tool gate")
                    provider_types = {p.type for p in workspace.providers if p.enabled and p.name in sandbox.providers}
                    catalog = {t: governed.requirements(t)[1] for t in provider_types if t in governed.SUPPORTED}
                    harness.configure(command, driver, bundles[expected_harness["name"]], workspace, sandbox, catalog)
            except shared.InstallerError as exc:
                raise ContractError(str(exc)) from exc
            spec = {"template": {"image": sandbox.image, "driver_config": {"kubernetes": driver}},
                    "providers": sorted(references), "command": command, "tty": False}
            if sandbox.type in ("openclaw", "nemoclaw"):
                # The boundary binary runs before the main command and inherits
                # image TMPDIR. OpenShift assigns a distinct UID per namespace.
                spec["template"]["environment"] = {"TMPDIR": "/tmp"}
            sandboxes.append({"name": sandbox.name, "spec": spec, "annotations": {REVISION: digest(spec)},
                              "labels": {MANAGED: "kubernetes-runtime", OWNER: owner}})
        workspaces.append({"name": ws_name, "providers": sorted(providers, key=lambda p: p["metadata"]["name"]),
                           "sandboxes": sorted(sandboxes, key=lambda s: s["name"])})
    if not workspaces or not any(w["sandboxes"] for w in workspaces):
        raise ContractError("profile must contain at least one enabled generic sandbox")
    if set(bindings) != used_bindings:
        raise ContractError("unused administrator bindings must be removed")
    claims = [r["name"] for r in all_refs]
    if len(claims) != len(set(claims)):
        raise ContractError("sharing retained claims between sandboxes is not supported")
    plan = {"schemaVersion": 1, "sourceRevision": SOURCE_REVISION, "ownerID": owner,
            "namespace": config["namespace"], "namespaceUID": config["namespaceUID"],
            "ownerSubject": config["ownerSubject"], "mode": mode, "gatewayVersion": config["gatewayVersion"],
            "requestedPlacement": {"supervisor": "container", "workload": mode},
            "runtimeClass": {"name": runtime, "uid": config.get("workloadRuntimeClassUID", "")},
            "claims": sorted(all_refs, key=lambda r: (r["workspace"], r["name"])),
            "workspaces": sorted(workspaces, key=lambda w: w["name"])}
    if any(p["type"] == "custom-inference" for w in workspaces for p in w["providers"]):
        plan["customInferenceURL"] = config["customInferenceURL"]
    retired = config.get("retiredSandboxes", {})
    if not isinstance(retired, dict):
        raise ContractError("retiredSandboxes must map workspace/sandbox names to retained IDs")
    for target, identifier in retired.items():
        if (not isinstance(target, str) or target.count("/") != 1 or target in used_bindings
                or not all(NAME.fullmatch(part) for part in target.split("/"))):
            raise ContractError("retired sandbox must be a distinct, named former workload")
        try:
            if str(uuid.UUID(identifier)) != identifier:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ContractError("retired sandbox requires its recorded UUID") from None
    if retired:
        plan["retiredSandboxes"] = dict(retired)
    return {**plan, "revision": digest(plan)}


def _check_document_capabilities(document, kind):
    # These fields belong to SAW's common language but are consumed by the VM
    # chart, not its normalized installer models. Reject before normalization
    # so the Kubernetes path cannot silently drop UI/harness requirements.
    if kind == "Sandboxes":
        for entry in document.get("spec", {}).get("sandboxes", []):
            if entry.get("enabled", True) and entry.get("harnessRequired") and not entry.get("harnessRef"):
                raise ContractError("required harness capability has no harnessRef")
