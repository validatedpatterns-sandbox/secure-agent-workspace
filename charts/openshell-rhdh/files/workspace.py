"""Common workspace projection used by installation and portal adapters.

Inputs are operator configuration, a BOM catalog and an immutable public
installation binding. Callers own authentication, credential storage, reads and
resource application. This module never discovers or changes cluster state.
"""
import hashlib
import json
import re
import urllib.parse
import urllib.error


class WorkspaceError(ValueError):
    """Invalid workspace configuration or immutable publication."""


def enabled_catalog_sandboxes(profile):
    for workspace in profile.get("workspaces", []):
        if workspace.get("enabled"):
            for sandbox in workspace.get("sandboxes", []):
                if sandbox.get("enabled"):
                    yield workspace["name"], sandbox


def sandbox_targets(user, registration, profile, *, model_lifecycle=False):
    """Expand the shared BOM catalog into isolated Kubernetes attachments."""
    enabled = list(enabled_catalog_sandboxes(profile))
    targets = {}
    for workspace, sb in enabled:
        key = workspace + "/" + sb["name"]
        suffix = hashlib.sha256((registration+"/"+key).encode()).hexdigest()[:16]
        single = len(enabled)==1
        targets[key] = dict(workspace=workspace, sandbox=sb["name"], ui=bool(sb.get("uiRoute")),
                            image=sb.get("image", ""), base=user if single else user+"-"+suffix[:8],
                            relayID=registration if single else suffix,
                            subjectMap="saw-portal-relay-subject" if single else "saw-portal-relay-"+suffix)
        if model_lifecycle and sb.get("modelInput"):
            targets[key]["modelInput"] = sb["modelInput"]
    return targets


def public_model_inputs(profile, secrets):
    """Only catalog-declared, noncredential model selectors can enter public intent."""
    values = {}
    confidential = {secrets.get(name, {}).get(field["key"])
                    for name, entry in profile.get("secrets", {}).items()
                    for field in entry["fields"] if field["kind"] == "secret"}
    custom_models = {sb.get("modelInput") for _, sb in enabled_catalog_sandboxes(profile) if sb.get("endpointInput")}
    for key in {sb["modelInput"] for _, sb in enabled_catalog_sandboxes(profile) if sb.get("modelInput")}:
        secret, field = key.split(".",1)
        allowed = any(f["key"] == field and f["kind"] == "text" for f in profile["secrets"][secret]["fields"])
        value = secrets.get(secret,{}).get(field)
        spelling = r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}" if key in custom_models else r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
        if not allowed or value and (value in confidential or not re.fullmatch(spelling, value)):
            raise WorkspaceError("invalid public model selector")
        if value:
            values[key]=value
    return values


def approved_endpoint(profile, secrets, boundary):
    refs = {sb["endpointInput"] for _, sb in enabled_catalog_sandboxes(profile) if sb.get("endpointInput")}
    if not refs:
        return None
    endpoint = boundary.get("inferenceBaseURL", "")
    if not isinstance(endpoint, str) or not re.fullmatch(
            r"https://[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::443)?(?:/[A-Za-z0-9_-]+)*/v1", endpoint):
        raise WorkspaceError("site has no approved custom inference endpoint")
    if boundary.get("allowHosts") != [urllib.parse.urlsplit(endpoint).hostname]:
        raise WorkspaceError("custom inference requires a dedicated broker host")
    for ref in refs:
        secret, key = ref.split(".", 1)
        fields = profile["secrets"][secret]["fields"]
        if not any(f["key"] == key and f["kind"] == "url" for f in fields):
            raise WorkspaceError("endpoint input must be public URL metadata")
        if secrets.get(secret, {}).get(key, "").rstrip("/") != endpoint:
            raise WorkspaceError("endpoint differs from the site-approved custom inference URL")
    return endpoint


def enrolled_site(site, ws, read):
    """Only the trusted bootstrap publishes bindings; images, code and endpoints always come from Git."""
    a = site.get("automaticEnrollment")
    if not a or not read:
        return site
    reg, install = ws["registration"], ws["installationID"]
    ns = "saw-ctl-" + reg
    def publication(name):
        obj = read(f"/api/v1/namespaces/{ns}/configmaps/{name}")
        if not obj or not obj.get("data"):
            return {}
        meta=obj["metadata"]
        if obj.get("immutable") is not True or meta.get("deletionTimestamp") or meta.get("labels",{}).get("saw.redhat.com/runtime-owner")!=install:
            raise WorkspaceError("invalid registration publication")
        return obj["data"]
    fresh = {k:v for k,v in site.items() if k!="enrollment"}
    data=publication("saw-portal-enrollment")
    if a.get("enabled") is False:
        if data:
            raise WorkspaceError("cannot disable enrollment of a bound workspace; use desiredState")
        return fresh
    for key, kind in (("reference", dict), ("relay", dict), ("revision", str),
                      ("image", str), ("buildNamespace", str)):
        if not isinstance(a.get(key), kind) or not a[key]:
            raise WorkspaceError(f"container site for {ws['name']} requires automaticEnrollment.{key}")
    if not data:
        return fresh
    bound=json.loads(data["binding.json"])
    if set(bound)!={"registration","intent","approved","gatewayCA"} or bound["registration"]!=reg or set(bound["approved"])!=set(a["reference"]):
        raise WorkspaceError("invalid published enrollment")
    intent=bound["intent"]
    if intent["bindings"]["ownerID"]!=install or intent["bindings"]["namespace"]!="saw-"+ws["name"] or intent["bindings"]["ownerSubject"]!=ws["ownerSubject"] or intent["profileRef"]["sha256"]!=site.get("selectedDigest",a.get("profileSHA256")):
        raise WorkspaceError("published intent does not belong to this workspace")
    subjects = {target["subjectMap"]:publication(target["subjectMap"]).get("subject", "")
                for target in site.get("targets",{}).values() if target["ui"]}
    fresh["subjects"] = subjects
    sub=subjects.get("saw-portal-relay-subject","") if site.get("targets") else publication("saw-portal-relay-subject").get("subject","")
    if sub and (not re.fullmatch(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}",sub) or sub==ws["ownerSubject"]):
        raise WorkspaceError("invalid relay subject")
    relay={**a["relay"],"gatewayCA":bound["gatewayCA"],"subject":sub,"workspaceID":""}
    fresh["enrollment"]={**{k:a[k] for k in ("revision","image","buildNamespace")},"registration":reg,"intent":intent,"approved":bound["approved"],"relay":relay}
    return fresh


def previous_child(application, appset, owner):
    """Read only the public values of the child controlled by this ApplicationSet."""
    if not application:
        return None
    meta = application["metadata"]
    if (meta.get("deletionTimestamp") or meta.get("labels", {}).get("openshell.pattern/owner") != owner["name"]
            or not any(ref.get("apiVersion") == "argoproj.io/v1alpha1" and ref.get("kind") == "ApplicationSet"
                       and ref.get("name") == appset and ref.get("controller") is True for ref in meta.get("ownerReferences", []))):
        raise WorkspaceError("cannot verify existing workspace Application ownership")
    source = application["spec"]["source"]
    if source.get("path") != "charts/saw-users":
        raise WorkspaceError("unexpected workspace Application source")
    values = json.loads(source["helm"]["values"])
    users = values["users"]
    if len(users) != 1 or any(users[0].get(k) != owner.get(k) for k in ("name", "installationID", "registration", "ownerSubject")):
        raise WorkspaceError("existing Application belongs to a different registration")
    if not isinstance(values, dict) or values["global"]["targetRevision"] != source["targetRevision"]:
        raise WorkspaceError("existing Application revision does not match its values")
    return values


def project_workspace(workspace, defaults, site, catalog, read=None, previous=None):
    try:
        values = _project_workspace(workspace, defaults, site, catalog, read)
        name = workspace["name"]
        projected = values.get("containerSites", {}).get(name, {})
        if previous and projected and site.get("automaticEnrollment"):
            subjects = projected.get("subjects", {})
            incomplete = not projected.get("enrollment") or any(
                target.get("ui") and not subjects.get(target["subjectMap"]) for target in projected["targets"].values())
            if incomplete:
                retained = previous(workspace)
                if retained:
                    old = retained["containerSites"][name]
                    if (old.get("enrollment") and not projected.get("enrollment") or
                            any(sub and not subjects.get(key) for key, sub in old.get("subjects", {}).items())):
                        # Returning the exact existing parameters holds only this child;
                        # omitting it could tell the static ApplicationSet to prune it.
                        return retained
        return values
    except WorkspaceError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        # Inputs include operator configuration and immutable API publications.
        # Do not include arbitrary values (especially JSON bodies) in diagnostics.
        detail = f"missing {exc.args[0]}" if isinstance(exc, KeyError) and exc.args[0] in {
            "subject", "registration", "installationID", "reference", "allowHosts", "bindings",
            "binding.json", "profileRef", "sha256", "initialModelInputs"} else "invalid site or publication"
        raise WorkspaceError(f"workspace {workspace.get('name', '?')}: {detail}") from None


def _project_workspace(workspace, defaults, site, catalog, read=None):
    """Project an authenticated registration into common saw-users chart values.

    Entry points resolve the owner, choose a registration and load any public
    enrollment objects. They must not manufacture a successful enrollment.
    Neither RHDH nor a particular Kubernetes client is required here.
    """
    ws = {**workspace, "values": {**workspace.get("values", {})}}
    mode = ws["values"].get("deployment", {}).get("mode", "vm")
    if mode not in {"vm", "container"}:
        raise WorkspaceError("unsupported workspace deployment mode")
    ws["values"]["deployment"] = {"mode": mode}
    # This map belongs to the operator's installation configuration, never the
    # registration or an owner request. Pin only code in the configured repository.
    revisions = defaults.get("workspaceRevisions", {})
    if not isinstance(revisions, dict) or any(
            not isinstance(name, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,17}[a-z0-9])?", name)
            or not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}", revision)
            for name, revision in revisions.items()):
        raise WorkspaceError("workspaceRevisions requires owner names and full Git commit SHAs")
    values = {**{k:v for k,v in defaults.items() if k != "workspaceRevisions"}, "users": [ws]}
    if ws.get("name") in revisions:
        values["global"] = {**defaults.get("global", {}), "targetRevision": revisions[ws["name"]]}
    if mode != "container":
        return values
    if not isinstance(site, dict) or not site:
        raise WorkspaceError(f"container site is missing for {ws['name']}")
    if ws.get("ownerSubject") != site.get("subject"):
        raise WorkspaceError("container site must bind the resolved owner subject")
    automatic = site.get("automaticEnrollment", {})
    selected, *extra = ws.get("profiles", []) or [None]
    foundation = automatic.get("enabled") is False
    if extra or selected not in catalog or not foundation and selected not in automatic.get("approvedProfiles", {}):
        raise WorkspaceError("container requires one approved BOM profile")
    if not ws.get("registration") or not ws.get("installationID"):
        raise WorkspaceError("container requires a registration and installation identity")
    overrides = site.get("profileImageOverrides", {}).get(selected, {})
    if overrides:
        ws["imageOverrides"] = overrides
    managed = ws.get("lifecycleVersion") == 1
    site = {**site,
            "targets": sandbox_targets(ws["name"], ws["registration"], catalog[selected],
                                       model_lifecycle=managed),
            "selectedDigest": automatic.get("approvedProfiles", {}).get(selected, ""),
            "modelInputs": ws.get("modelInputs", {})}
    for target in site["targets"].values():
        target["image"] = overrides.get(target["sandbox"], target["image"])
    boundary = site.get("profileBoundaries", {}).get(selected)
    if boundary:
        site = {**site, "providerAllowHosts": boundary["allowHosts"],
                "automaticEnrollment": {**automatic, "reference": boundary["reference"]}}
    if ws.get("customInferenceURL"):
        if not boundary or boundary.get("inferenceBaseURL") != ws["customInferenceURL"]:
            raise WorkspaceError("endpoint differs from the site-approved custom inference URL")
        site["customInferenceURL"] = ws["customInferenceURL"]
    if managed:
        site.update(lifecycleVersion=1, modelInputs=ws["initialModelInputs"],
                    requestedModels=ws.get("modelInputs", {}), desiredState=ws["desiredState"],
                    restartGeneration=ws["restartGeneration"])
    values["containerSites"] = {ws["name"]: enrolled_site(site, ws, read)}
    return values


# Preserve the existing lifecycle API stage IDs across entry points.
STAGE_IDS = ("registered", "apps", "vm", "running", "ready")


def sandbox_ui_links(user, profiles, catalog, domain):
    out = []
    for profile in profiles:
        for workspace, sb in enabled_catalog_sandboxes(catalog.get(profile, {})):
            if sb.get("uiRoute"):
                out.append((f"{sb['name']} UI ({workspace})",
                            f"https://{user}-{workspace}-{sb['name']}-ui.apps.{domain}"))
    return out



def container_status(read_resource, entry, site, argo_ns, domain, ping, catalog=None):
    # Reuse the VM pipeline's wire stage IDs so old RHDH tasks can finish.
    # Only observations and their user-facing names differ.
    user = entry["name"]
    ns = f"saw-{user}"
    reg = entry["registration"]
    rev = entry.get("intentGeneration")
    gen = isinstance(rev, int) and not isinstance(rev, bool) and rev > 0
    app = read_resource(f"/apis/argoproj.io/v1alpha1/namespaces/{argo_ns}/applications/saw-{user}") or {}
    meta = app.get("metadata", {})
    app_ok = meta.get("labels", {}).get("openshell.pattern/owner") == user and not meta.get("deletionTimestamp")
    app_status = app.get("status", {})
    def read(name, field):
        cm = read_resource(f"/api/v1/namespaces/{ns}/configmaps/{name}") or {}
        meta = cm.get("metadata", {})
        labels = meta.get("labels", {})
        if (meta.get("deletionTimestamp") or not reg
                or labels.get("saw.redhat.com/runtime-owner") != entry["installationID"]
                or field == "status.json" and labels.get("saw.redhat.com/managed-by") != "kubernetes-runtime-controller"):
            return {}
        try:
            value = json.loads(cm.get("data", {}).get(field, "{}"))
            return value if isinstance(value, dict) else {}
        except (ValueError, TypeError):
            return {}
    intent = read("saw-runtime-intent", "intent.json") if app_ok else {}
    bound = bool(reg and site and gen and intent.get("generation") == rev
                 and intent.get("bindings", {}).get("ownerSubject") == site["subject"]
                 and intent.get("bindings", {}).get("namespace") == ns
                 and intent.get("bindings", {}).get("mode") == "container"
                 and intent.get("bindings", {}).get("ownerID") == entry["installationID"])
    desired = entry.get("desiredState", "Running")
    bound = bound and intent.get("desiredState") == desired
    st = read("saw-runtime-status", "status.json") if bound else {}
    profile = (read_resource(f"/api/v1/namespaces/{ns}/configmaps/saw-bom-profiles") or {}) if bound else {}
    files = profile.get("data", {})
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    ref = intent.get("profileRef", {})
    current = (bound and not profile.get("metadata", {}).get("deletionTimestamp")
               and ref.get("name") == "saw-bom-profiles" and bool(ref.get("uid"))
               and ref["uid"] == profile.get("metadata", {}).get("uid") and ref.get("sha256") == digest(files)
               and type(st.get("observedGeneration")) is int and st["observedGeneration"] == rev
               and st.get("inputRevision") == digest({"intent": intent, "files": files}))
    running = current and st.get("phase") == "GenericReady" and intent.get("desiredState") == "Running"
    links = sandbox_ui_links(user, entry.get("profiles", []), catalog, domain) if catalog and entry.get("desiredState") != "Stopped" else []
    profiles = entry.get("profiles", [])
    declared = [sb for p in profiles for _, sb in enabled_catalog_sandboxes(catalog[p])] if (
        catalog and all(p in catalog for p in profiles)) else []
    headless = bool(declared) and all(sb.get("uiRoute") is False for sb in declared)
    ready = bool(running and (headless or (links and domain)) and app_status.get("sync", {}).get("status") == "Synced"
                 and app_status.get("health", {}).get("status") == "Healthy" and all(ping(url) for _,url in links))
    observations = [(True, "Registration recorded"), (app_ok, "Argo application for this owner"),
                    (bound, "Intent for this registration and update"),
                    (running, "Profile sandboxes running"), (ready, "Workspace ready" if headless else "Owner chat routes available")]
    stopped = bool(current and desired == "Stopped" and st.get("phase") == "Stopped")
    if desired == "Stopped":
        observations[-2:] = [(stopped, "OpenShell sandboxes stopped"), (stopped, "Storage retained")]
    phase = "none"
    steps = []
    waiting = False
    for stage, (done, title) in zip(STAGE_IDS, observations):
        state = "waiting" if waiting else "done" if done else "active"
        if state == "done":
            phase = stage
        else:
            waiting = True
        steps.append(dict(id=stage, title=title, detail=title, state=state))
    failed = bool(current and st.get("phase") == "Blocked" or app_ok and app_status.get("operationState", {}).get("phase") in ("Error", "Failed"))
    message = "Container reconciliation failed" if failed else next((s["title"] for s in steps if s["state"] == "active"), "Workspace ready")
    if stopped and not failed:
        message = "Workspace stopped"
        phase = "stopped"
    return dict(user=user, deploymentMode="container", phase="failed" if failed else phase, title=message,
                registration=reg, generation=rev, observedGeneration=st.get("observedGeneration"),
                desiredState=desired, modelInputs=entry.get("modelInputs", {}),
                message=message, text=message, ready=ready and not failed, failed=failed, steps=steps,
                links=[dict(title=title,url=url) for title,url in links] if ready and not failed else [])



def owner_route_available(url, issuer, client, timeout=3):
    """Require an anonymous challenge AND a registered callback at the trusted issuer."""
    origin = url.rstrip("/")
    auth = issuer.rstrip("/") + "/protocol/openid-connect/auth"
    if not issuer.startswith("https://") or not origin.startswith("https://"):
        return False
    location = origin
    for hop in range(3):
        try:
            with client.open(location, timeout=timeout) as res:
                return (location.split("?")[0] == auth and res.status == 200
                        and b'id="kc-form-login"' in res.read(256 * 1024))
        except urllib.error.HTTPError as exc:
            with exc:
                target = urllib.parse.urljoin(location, exc.headers.get("Location", ""))
                if exc.code not in (302, 303, 307):
                    return False
            parts = urllib.parse.urlsplit(target)
            if hop == 0 and target.split("?")[0] == origin + "/oauth2/start":
                location = target
                continue
            params = urllib.parse.parse_qs(parts.query)
            if (target.split("?")[0] != auth or params.get("client_id") != ["openshell-dashboard"]
                    or params.get("redirect_uri") != [origin + "/oauth2/callback"]):
                return False
            location = target
        except (OSError, ValueError):
            return False
    return False
