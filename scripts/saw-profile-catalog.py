#!/usr/bin/env python3
"""Generate the SAW-BOM profile catalog from charts/saw-bom/profiles.

The catalog says, for each profile, which workspaces and sandboxes it
creates (and which sandboxes ask for a UI route), and which Secrets its
providers read, with the fields each one needs. Two charts read it, since a
Helm chart can only read its own files:

  charts/saw-users/files/profile-catalog.json      UI routes and the Secrets
                                                   to sync, per user
  charts/openshell-rhdh/files/profile-catalog.json the portal pipelines
  charts/openshell-rhdh/files/create-workspace.yaml the RHDH template: the
                                                   profiles to pick from, and
                                                   the fields each one needs
  charts/openshell-rhdh/files/delete-workspace.yaml the delete template (the
                                                   same pipeline steps)

    scripts/saw-profile-catalog.py            write both files
    scripts/saw-profile-catalog.py --check    fail when they are stale (CI)
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "charts" / "saw-bom" / "profiles"
CATALOG_OUTPUTS = [ROOT / "charts" / "saw-users" / "files" / "profile-catalog.json",
                   ROOT / "charts" / "openshell-rhdh" / "files" / "profile-catalog.json"]
TEMPLATE_OUTPUT = ROOT / "charts" / "openshell-rhdh" / "files" / "create-workspace.yaml"
DELETE_TEMPLATE = ROOT / "charts" / "openshell-rhdh" / "files" / "delete-workspace.yaml"
ADMIN_TEMPLATE_OUTPUT = ROOT / "charts" / "openshell-rhdh" / "files" / "create-workspace-for-user.yaml"
ADMIN_DELETE_TEMPLATE = ROOT / "charts" / "openshell-rhdh" / "files" / "delete-workspace-for-user.yaml"


def load(path):
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def secret_fields(provider):
    """The fields a provider reads from its Secret, as the installer does
    (resolve_credentials): the key, and optionally a base URL and a model."""
    fields = [{"key": provider.get("credentialSecretKey", "api_key"), "kind": "secret",
               "required": True, "title": "API key"}]
    if provider.get("baseUrlSecretKey"):
        fields.append({"key": provider["baseUrlSecretKey"], "kind": "url", "required": True,
                       "title": "Endpoint base URL (OpenAI-compatible, ending in /v1)"})
    if provider.get("modelSecretKey"):
        field = {"key": provider["modelSecretKey"], "kind": "text", "required": True,
                 "title": "Model"}
        if provider.get("model"):
            field["default"] = provider["model"]
        fields.append(field)
    return fields


def catalog():
    out = {}
    for pdir in sorted(p for p in PROFILES.iterdir() if p.is_dir()):
        workspaces, secrets, descriptions = [], {}, []
        # The default workspace first: its description is the profile's.
        for wdir in sorted((w for w in pdir.iterdir() if w.is_dir()),
                           key=lambda w: (w.name != "default", w.name)):
            ws = load(wdir / "workspace.yaml")
            meta, spec = ws.get("metadata") or {}, ws.get("spec") or {}
            name = meta.get("name", wdir.name)
            description = meta.get("description", "")
            if description:
                descriptions.append(description)
            enabled = spec.get("enabled", True)
            sandboxes = []
            for sb in (load(wdir / "sandbox.yaml").get("spec") or {}).get("sandboxes") or []:
                ui = sb.get("ui") or {}
                sandboxes.append({"name": sb["name"], "type": sb.get("type", "generic"),
                                  "enabled": sb.get("enabled", True),
                                  "uiRoute": bool(ui.get("route", False))})
            workspaces.append({"name": name, "description": description, "enabled": enabled,
                               "sandboxes": sandboxes})
            if not enabled:
                continue
            for prov in (load(wdir / "providers.yaml").get("spec") or {}).get("providers") or []:
                if not prov.get("enabled", True) or not prov.get("credentialSecret"):
                    continue
                entry = secrets.setdefault(prov["credentialSecret"],
                                           {"providers": [], "fields": []})
                entry["providers"] = sorted(set(entry["providers"]) | {prov.get("type", "")})
                for f in secret_fields(prov):
                    if f["key"] not in {x["key"] for x in entry["fields"]}:
                        entry["fields"].append(f)
        for entry in secrets.values():
            # The Secret's optional `provider` key lets the installer refuse
            # a key for another service; only set when it is unambiguous.
            entry["provider"] = entry["providers"][0] if len(entry["providers"]) == 1 else ""
        out[pdir.name] = {"description": "; ".join(dict.fromkeys(descriptions)),
                          "workspaces": workspaces, "secrets": secrets}
    return {"profiles": out}


def render():
    return json.dumps(catalog(), indent=2, sort_keys=True) + "\n"


# The signed-in user's name: user.entity is empty for users who are not in
# the catalog (they sign in without one), user.ref is always set.
USER_NAME = "${{ user.ref | parseEntityRef | pick('name') }}"


def form_name(secret, key):
    """Form property for a Secret field: letters, digits and _ only, so it
    can be read as ${{ secrets.<name> }} / ${{ parameters.<name> }}."""
    return f"{secret}__{key}".replace("-", "_").replace(".", "_")


# The user's Backstage token, for the generator's /status (through the RHDH
# proxy endpoint /saw-status): it answers only about that user.
STATUS_HEADERS = {"X-Saw-Token": "${{ secrets.backstageToken }}"}
RUN_NAME = "${{ steps.run.output.body.metadata.name }}"
# Seconds one status call may wait. The scaffolder reaches RHDH's proxy
# through RHDH's route, and the OpenShift router drops a request that is
# quiet for 30 s (its default timeout): stay well below.
WAIT = 20


def status_get(step_id, name, query, each=None, wait=False, check=False):
    """A GET on /proxy/saw-status/<query>. A waiting step is repeated
    (`each`): each call returns as soon as its stage is reached or failed,
    else after at most WAIT seconds. A check step fails (422) when the stage
    failed or was not reached."""
    step = {"id": step_id, "name": name, "action": "http:backstage:request",
            "input": {"method": "GET", "path": "/proxy/saw-status/" + query,
                      "headers": dict(STATUS_HEADERS), "timeout": 90000}}
    if wait:
        step["input"]["continueOnBadResponse"] = True
    if each:
        step["each"] = list(range(1, each + 1))
    return step


def log_step(step_id, name, source):
    return {"id": step_id, "name": name, "action": "debug:log",
            "input": {"message": "${{ steps['" + source + "'].output.body.text }}"}}


# The pipelines' tasks, as the run page's steps: (task, step name, minutes
# the page follows it; the pipeline task's own timeout is a little longer).
# Each task is one stage (charts/openshell-rhdh portal-pipelines).
CREATE_TASKS = [
    ("register", "Verify the request, store the keys, register the workspace", 5),
    ("argo-cd-apps", "Argo CD creates the workspace's applications", 12),
    ("vm", "Argo CD creates the VM", 12),
    ("vm-running", "Start the VM", 17),
    ("sandboxes", "Install OpenShell and the sandboxes (about 10 minutes)", 32),
]
DELETE_TASKS = [
    ("unregister", "Verify the request, delete the Argo CD application", 5),
    ("argo-cd-removes", "Argo CD removes the namespace and the VM", 22),
    ("finish", "Remove the registry entry and the keys", 5),
]


def pipeline_steps(tasks):
    """One step per pipeline task (it waits for that task to end), then the
    run's log, then a check that fails the run if the pipeline failed."""
    steps = [status_get(f"task-{task}", name, f"run/{RUN_NAME}?task={task}&wait={WAIT}",
                        each=minutes * 60 // WAIT, wait=True)
             for task, name, minutes in tasks]
    return steps + [
        status_get("pipeline", "Pipeline result", f"run/{RUN_NAME}"),
        log_step("pipeline-log", "Pipeline log", "pipeline"),
        status_get("pipeline-check", "Check the pipeline", f"run/{RUN_NAME}?assert=1", check=True),
    ]


def pipeline_run(action, workspace="saw-" + USER_NAME):
    """The PipelineRun the template starts. The label puts it on the
    workspace's Tekton tab (the register task refuses another user's)."""
    return {"apiVersion": "tekton.dev/v1", "kind": "PipelineRun",
            "metadata": {"generateName": f"saw-{action}-",
                         "labels": {"saw.redhat.com/request": "true",
                                    "backstage.io/kubernetes-id": workspace}},
            "spec": {"pipelineRef": {"name": f"saw-workspace-{action}"},
                     "timeouts": {"pipeline": "1h30m"},
                     "taskRunTemplate": {"serviceAccountName": "__PROVISIONER_SA__"},
                     "params": [{"name": "request", "value":
                                 "${{ steps.request.output.body.metadata.name }}"}]}}


# The admin templates: a workspace for another user, one at a time. The
# pipeline refuses them for anyone not in portal.admins.
FOR_USER = "${{ parameters.forUser }}"
FOR_USER_FIELD = {"title": "User", "type": "string", "pattern": "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                  "maxLength": 19, "ui:autofocus": True,
                  "description": "The Keycloak user name the workspace is for (namespace saw-<user>). "
                                 "Administrators only; your own name for your workspace. The user signs in with "
                                 "their own password."}


def render_template(cat, for_user=False):
    """The RHDH scaffolder template for a new workspace.

    Step 1 picks a profile; step 2 asks only for the fields that profile's
    Secrets need (JSON Schema dependencies). API keys use the Secret field,
    so they reach the request as ${{ secrets.* }} and are not stored with
    the task. The steps create the request Secret (with the user's Backstage
    token, which the pipeline verifies) and start saw-workspace-create, then
    follow it on the run page, one step per pipeline task (each a stage of
    the workspace, until its sandbox UIs answer), then the pipeline's log."""
    profiles = cat["profiles"]
    one_of, string_data = [], {"action": "create", "token": "${{ secrets.backstageToken }}",
                               "profile": "${{ parameters.profile }}"}
    if for_user:
        string_data["forUser"] = FOR_USER
    who = FOR_USER if for_user else USER_NAME
    for pname, prof in sorted(profiles.items()):
        props, required = {"profile": {"const": pname}}, []
        routes = [f"{sb['name']} ({ws['name']})" for ws in prof["workspaces"] if ws["enabled"]
                  for sb in ws["sandboxes"] if sb["enabled"] and sb["uiRoute"]]
        if routes:
            props["uiRoutes"] = {"title": "Sandbox web UIs", "type": "null",
                                 "description": "Published on their own route, signed in with "
                                                "Keycloak, for you only: " + ", ".join(routes)}
        for sname, spec in sorted(prof["secrets"].items()):
            for field in spec["fields"]:
                name = form_name(sname, field["key"])
                prop = {"title": f"{sname}: {field['title']}", "type": "string"}
                if field["kind"] == "secret":
                    prop["ui:field"] = "Secret"
                    prop["description"] = (f"Stored in Vault for your workspace only "
                                           f"(provider {spec['provider'] or '/'.join(spec['providers'])})")
                    string_data[f"{sname}.{field['key']}"] = "${{ secrets." + name + " }}"
                else:
                    if field.get("default"):
                        prop["default"] = field["default"]
                    if field["kind"] == "url":
                        prop["pattern"] = "^https?://"
                    string_data[f"{sname}.{field['key']}"] = "${{ parameters." + name + " }}"
                props[name] = prop
                if field.get("required"):
                    required.append(name)
        one_of.append({"properties": props, "required": required})
    names = sorted(profiles)
    template = {
        "apiVersion": "scaffolder.backstage.io/v1beta3",
        "kind": "Template",
        "metadata": {
            "name": "create-saw-workspace-for-user" if for_user else "create-saw-workspace",
            "title": ("Create or update an agent workspace for a user" if for_user
                      else "Create or update my agent workspace"),
            "description": ("Administrators: a Secure Agent Workspace for a user, yourself included, with "
                            "the keys you enter for them; for a user who has one, it changes its profile "
                            "or keys. Keys go to Vault, not to Git." if for_user else
                            "Your own Secure Agent Workspace: a VM with OpenShell and the OpenClaw / "
                            "NemoClaw sandboxes of a SAW-BOM profile. If you have one, this changes its "
                            "profile or keys. Keys go to Vault, not to Git."),
            "tags": ["openshell", "openclaw", "nemoclaw", "secure-agent-workspace"]
                    + (["admin"] if for_user else []),
            # RBAC shows this template to administrators only; the user's to
            # every user (create or update), but not to administrators.
            **({"labels": {"saw.redhat.com/admin": "true"}} if for_user else {}),
        },
        "spec": {
            "owner": "user:default/admin",
            "type": "agent-workspace",
            "parameters": ([{"title": "User", "required": ["forUser"],
                             "properties": {"forUser": FOR_USER_FIELD}}] if for_user else []) + [{
                "title": "Workspace profile",
                "description": ("The workspace is named after the user (namespace saw-<user>)." if for_user
                                else "The workspace is named after you (namespace saw-<your user name>)."),
                "required": ["profile"],
                "properties": {"profile": {
                    "title": "Profile", "type": "string", "enum": names,
                    "enumNames": [f"{n}: {profiles[n]['description']}" if profiles[n]["description"]
                                  else n for n in names],
                    "default": "data-science" if "data-science" in names else names[0]}},
                "dependencies": {"profile": {"oneOf": one_of}},
            }],
            "steps": [
                {"id": "request", "name": "Submit the request", "action": "http:backstage:request",
                 "input": {"method": "POST", "path": "/proxy/saw-requests",
                           "headers": {"Content-Type": "application/json"},
                           "body": {"apiVersion": "v1", "kind": "Secret",
                                    "metadata": {"generateName": "saw-req-",
                                                 "labels": {"saw.redhat.com/request": "true"}},
                                    "type": "Opaque", "stringData": string_data}}},
                {"id": "run", "name": "Start the pipeline", "action": "http:backstage:request",
                 "input": {"method": "POST", "path": "/proxy/saw-pipelineruns",
                           "headers": {"Content-Type": "application/json"},
                           "body": pipeline_run("create", "saw-" + who)}},
                *pipeline_steps(CREATE_TASKS),
                status_get("status", "Workspace status", "workspace?user=" + who if for_user else "workspace"),
                log_step("status-log", "Workspace status report", "status"),
            ],
            "output": {
                "links": [{"title": "The workspace in the catalog" if for_user else "Your workspace in the catalog",
                           "entityRef": "component:default/saw-" + who}],
                "text": [{"title": "Workspace status",
                          "content": "${{ steps.status.output.body.text }}"}]},
        },
    }
    return ("# Generated by scripts/saw-profile-catalog.py from charts/saw-bom/profiles; do not edit.\n"
            + yaml.safe_dump(template, sort_keys=False, width=100, default_flow_style=None))


def render_delete_template(for_user=False):
    """The RHDH scaffolder template that deletes the user's workspace (an
    administrator's: any user's)."""
    picked = "${{ parameters.workspace | parseEntityRef | pick('name') }}"
    template = {
        "apiVersion": "scaffolder.backstage.io/v1beta3",
        "kind": "Template",
        "metadata": {
            "name": "delete-saw-workspace-for-user" if for_user else "delete-saw-workspace",
            "title": "Delete a user's agent workspace" if for_user else "Delete my agent workspace",
            "description": ("Administrators: removes a user's Secure Agent Workspace, its VM, its sandboxes "
                            "and everything in them, and the user's keys in Vault. This cannot be undone."
                            if for_user else
                            "Removes your Secure Agent Workspace: its VM, its sandboxes and everything in "
                            "them, and your keys in Vault. This cannot be undone."),
            "tags": ["openshell", "secure-agent-workspace"] + (["admin"] if for_user else []),
            # Administrators only; the user's: users with a workspace.
            "labels": {"saw.redhat.com/admin" if for_user else "saw.redhat.com/owners": "true"},
        },
        "spec": {
            "owner": "user:default/admin",
            "type": "agent-workspace",
            # The form's last button says "Create" unless told otherwise.
            "presentation": {"buttonLabels": {"reviewButtonText": "Review",
                                              "createButtonText": "Delete workspace"}},
            "parameters": [{
                "title": "Confirm",
                "required": ["workspace", "confirm"],
                "properties": {
                    # The user's form lists only their own workspace; the
                    # admin's lists all. The pipeline checks either way.
                    "workspace": {"title": "Workspace to delete", "type": "string",
                                  "ui:field": "EntityPicker" if for_user else "OwnedEntityPicker",
                                  "ui:options": {"catalogFilter": {"kind": "Component",
                                                                   "spec.type": "agent-workspace"},
                                                 "defaultKind": "Component",
                                                 "allowArbitraryValues": False}},
                    "confirm": {"title": "I understand that this workspace, its VM and its data are deleted",
                                "type": "boolean", "const": True}},
            }],
            "steps": [
                {"id": "request", "name": "Submit the request", "action": "http:backstage:request",
                 "input": {"method": "POST", "path": "/proxy/saw-requests",
                           "headers": {"Content-Type": "application/json"},
                           "body": {"apiVersion": "v1", "kind": "Secret",
                                    "metadata": {"generateName": "saw-req-",
                                                 "labels": {"saw.redhat.com/request": "true"}},
                                    "type": "Opaque",
                                    "stringData": {"action": "delete",
                                                   "token": "${{ secrets.backstageToken }}",
                                                   "workspace": "${{ parameters.workspace }}"}}}},
                {"id": "run", "name": "Start the pipeline", "action": "http:backstage:request",
                 "input": {"method": "POST", "path": "/proxy/saw-pipelineruns",
                           "headers": {"Content-Type": "application/json"},
                           "body": pipeline_run("delete", picked)}},
                *pipeline_steps(DELETE_TASKS),
            ],
            "output": {"text": [{"title": "Workspace deleted", "content":
                                 "Pipeline run **" + RUN_NAME + "** deleted workspace " + picked
                                 + ": its VM, namespace and keys are gone."}]},
        },
    }
    return ("# Generated by scripts/saw-profile-catalog.py; do not edit.\n"
            + yaml.safe_dump(template, sort_keys=False, width=100, default_flow_style=None))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when an output is stale")
    args = parser.parse_args(argv)
    text = render()
    outputs = [(path, text) for path in CATALOG_OUTPUTS]
    outputs.append((TEMPLATE_OUTPUT, render_template(json.loads(text))))
    outputs.append((DELETE_TEMPLATE, render_delete_template()))
    outputs.append((ADMIN_TEMPLATE_OUTPUT, render_template(json.loads(text), for_user=True)))
    outputs.append((ADMIN_DELETE_TEMPLATE, render_delete_template(for_user=True)))
    stale = []
    for path, text in outputs:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current == text:
            continue
        if args.check:
            stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print("stale profile catalog (run scripts/saw-profile-catalog.py): " + ", ".join(stale),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
