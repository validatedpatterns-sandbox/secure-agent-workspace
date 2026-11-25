"""Render the same owner request through both Helm levels and the stock component charts."""
import copy
import importlib.util
from pathlib import Path
import json
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
U = "alice"
REG = "a8cb6cbd0eb62f31"
SITE = yaml.safe_load((ROOT / "tests/fixtures/container-site.yaml").read_text())["portal"]["containerSites"][U]
GLOBAL = {"repoURL":"https://github.com/example/secure-agent-workspace","targetRevision":"test",
          "vpArgoNamespace":"vp-gitops","clusterDomain":"cluster.example.com"}


def render(chart, release, ns, values):
    result = subprocess.run(["helm","template",release,str(ROOT/"charts"/chart),"--namespace",ns,
                  "--api-versions","agents.x-k8s.io/v1beta1","--api-versions","policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy",
                  "--api-versions","admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy","-f","-"],
                 input=json.dumps(values),text=True,capture_output=True)
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def child(app):
    src = app["spec"]["source"]
    helm = src["helm"]
    return render(src["path"].split("/")[-1],helm["releaseName"],app["spec"]["destination"]["namespace"],
                  helm.get("valuesObject") or yaml.safe_load(helm["values"]))


def user():
    return {"name":U, "ownerSubject":SITE["subject"],"installationID":"802fe583-9329-54b6-b5b4-7be58ec171f3",
            "registration":REG,"intentGeneration":1,"vaultPrefix":f"secret/data/hub/saw-{U}",
            "values":{"deployment":{"mode":"container"}},"profiles":["data-science"],"pruneOnRemove":True}


def test_container_has_own_gateway_credential_audit_and_policy():
    top = render("saw-users","portal-ws-"+U,"saw-portal",{"global":GLOBAL,"users":[user()],"containerSites":{U:SITE}})
    apps = [a for a in top if a["kind"]=="Application"]
    assert {a["spec"]["source"]["path"] for a in apps} == {"charts/saw-bom","charts/saw-portal-container"}
    resources = [r for a in apps for r in child(a)]
    assert all(isinstance(r["spec"]["source"]["targetRevision"], str)
               for r in resources if r["kind"] == "Application")
    es, = [r for r in resources if r["kind"]=="ExternalSecret" and r["metadata"]["name"]=="inference"]
    assert es["metadata"]["namespace"] == "saw-ctl-"+REG
    assert es["spec"]["data"] == [{"secretKey":"api_key","remoteRef":{"key":user()["vaultPrefix"]+"/inference","property":"api_key"}}]
    archived_ns, = [r for r in resources if r["kind"]=="Namespace" and r["metadata"]["name"]=="saw-history-"+REG]
    archive_annotations=archived_ns["metadata"]["annotations"]
    assert archive_annotations["argocd.argoproj.io/compare-options"]=="IgnoreExtraneous"
    assert set(archive_annotations["argocd.argoproj.io/sync-options"].split(","))=={"Delete=false","Prune=false"}
    workloads = [r for a in resources if a["kind"]=="Application" for r in child(a)]
    assert not any(r["kind"]=="VirtualMachine" for r in workloads)
    net, = [r for r in workloads if r["kind"]=="AdminNetworkPolicy"]
    assert net["spec"]["subject"]["pods"]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == "saw-"+U
    assert any(r["kind"]=="StatefulSet" and r["metadata"]["name"] == U+"-gateway" for r in workloads)
    history, = [r for r in workloads if r["kind"]=="PersistentVolumeClaim" and r["metadata"]["name"].endswith("-history")]
    assert history["metadata"]["namespace"] == "saw-history-"+REG
    assert "Delete=false" in history["metadata"]["annotations"]["argocd.argoproj.io/sync-options"]
    assert "saw-unrelated-vm" not in json.dumps(workloads)


@pytest.mark.parametrize("prefix", ["secret/data/hub/saw-" + U, "secret/data/hub/saw-" + U + "/" + REG])
def test_container_reads_keys_where_they_were_written(prefix):
    """Static entries keep one per-user path; the portal writes each
    registration's keys under .../saw-<user>/<registration> (vault.write uses
    the registry entry's vaultPrefix). Both must reach the ExternalSecret as is."""
    entry = {**user(), "vaultPrefix": prefix}
    top = render("saw-users", "portal-ws-" + U, "saw-portal", {"global": GLOBAL, "users": [entry], "containerSites": {U: SITE}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    es, = [r for r in resources if r["kind"] == "ExternalSecret" and r["metadata"]["name"] == "inference"]
    assert es["spec"]["data"][0]["remoteRef"]["key"] == prefix + "/inference"


@pytest.mark.parametrize("prefix", ["secret/data/hub/saw-other/" + REG, "secret/data/hub/saw-" + U + "/" + "f" * 16])
def test_container_refuses_another_owners_or_registrations_path(prefix):
    v = dict(owner=U, ownerSubject=SITE["subject"], registration=REG, vaultPrefix=prefix)
    with pytest.raises(AssertionError, match="vaultPrefix must match"):
        render("saw-portal-container", U, "saw-" + U, v)


def test_container_rejects_another_registrations_keys():
    v = dict(owner=U,ownerSubject=SITE["subject"],registration=REG,vaultPrefix="secret/data/hub/saw-other")
    with pytest.raises(AssertionError,match="vaultPrefix must match"):
        render("saw-portal-container",U,"saw-"+U,v)


def test_automatic_enrollment_cannot_read_secrets_or_mount_history():
    site=SITE
    v=dict(owner=U,ownerSubject=site["subject"],registration=REG,installationID=user()["installationID"],vaultPrefix=user()["vaultPrefix"],site=site,**{"global":GLOBAL})
    resources=render("saw-portal-container",U,"saw-"+U,v)
    j,=[r for r in resources if r["kind"]=="Job"]
    spec=j["spec"]["template"]["spec"]
    assert not any("persistentVolumeClaim" in v for v in spec["volumes"])
    assert not any("secret" in v for v in spec["volumes"])
    assert "gateway-ca" not in {v["name"] for v in spec["volumes"]}
    assert all(mount["name"] != "gateway-ca"
               for container in spec["containers"] for mount in container.get("volumeMounts", []))
    control_role, = [r for r in resources if r["kind"] == "Role"
                     and r["metadata"]["namespace"] == "saw-ctl-"+REG
                     and r["metadata"]["name"] == "enroll-"+REG]
    ca_rule, = [rule for rule in control_role["rules"]
                if "configmaps" in rule["resources"] and U+"-gateway-ca" in rule.get("resourceNames", [])]
    assert ca_rule["verbs"] == ["get"]
    assert U+"-gateway-ca" in ca_rule["resourceNames"]
    workspace_role, = [r for r in resources if r["kind"] == "Role"
                       and r["metadata"]["namespace"] == "saw-"+U
                       and r["metadata"]["name"] == "enroll-"+REG]
    assert all(U+"-gateway-ca" not in rule.get("resourceNames", [])
               for rule in workspace_role["rules"])
    script_volume, = [volume for volume in spec["volumes"] if volume["name"] == "scripts"]
    script_config, = [resource for resource in resources
                       if resource["kind"] == "ConfigMap"
                       and resource["metadata"]["name"] == script_volume["configMap"]["name"]]
    assert {"http_errors.py", "kube_api.py"} <= set(script_config["data"])
    grants=[rule for r in resources if r["kind"] in ("Role","ClusterRole") and "enroll" in r["metadata"]["name"] for rule in r["rules"]]
    assert all("secrets" not in x["resources"] and "*" not in x["verbs"] for x in grants)
    assert [x["resourceNames"] for x in grants if "patch" in x["verbs"]]==[["saw-portal-enrollment"]]
    files=ROOT/"charts/saw-portal-container/files"
    assert (files/"receipt.py").read_bytes()==(ROOT/"kubernetes-runtime/saw_kubernetes/receipt.py").read_bytes()
    assert (files/"gateway_ca.py").read_bytes()==(ROOT/"kubernetes-runtime/saw_kubernetes/gateway_ca.py").read_bytes()
    assert (files/"portal_contract.py").read_text()==(ROOT/"kubernetes-runtime/saw_kubernetes/portal_contract.py").read_text().replace("from .boundary import","from saw_kubernetes.boundary import")


def test_runtime_controller_reads_only_the_named_public_gateway_ca():
    values = yaml.safe_load((ROOT / "tests/fixtures/saw-kubernetes-controller-values.yaml").read_text())
    docs = render("saw-kubernetes-controller", "alice", "saw-ci-trusted", values)
    role, = [r for r in docs if r["kind"] == "Role" and r["metadata"]["namespace"] == "saw-ci-trusted"]
    ca_rule, = [r for r in role["rules"] if "configmaps" in r["resources"] and "alice-gateway-ca" in r["resourceNames"]]
    assert ca_rule["verbs"] == ["get"]
    workspace_role, = [r for r in docs if r["kind"] == "Role" and r["metadata"]["namespace"] == "saw-alice"]
    assert all("alice-gateway-ca" not in r.get("resourceNames", []) for r in workspace_role["rules"])
    deployment, = [r for r in docs if r["kind"] == "Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    assert "identity" not in {v["name"] for v in pod["volumes"]}
    assert all(m["name"] != "identity" for c in pod["containers"] for m in c["volumeMounts"])


def test_status_reader_keeps_rhdh_and_provisioner_access_with_static_observer():
    site = {**SITE, "observer": {"namespace": "saw-workspaces", "serviceAccount": "saw-projector-owner"}}
    docs = render("saw-portal-container", U, "saw-"+U, dict(
        site=site, owner=U, registration=REG, installationID=user()["installationID"],
        ownerSubject=SITE["subject"], vaultPrefix=user()["vaultPrefix"], **{"global": GLOBAL}))
    binding, = [o for o in docs if o["kind"] == "RoleBinding"
                and o["metadata"]["name"] == "saw-portal-runtime-observer"]
    assert {(s["namespace"], s["name"]) for s in binding["subjects"]} == {
        ("saw-workspaces", "saw-projector-owner"),
        ("saw-portal", "saw-workspaces-generator"),
        ("saw-portal", "saw-portal-provisioner"),
    }
    role, = [o for o in docs if o["kind"] == "Role"
             and o["metadata"]["name"] == "saw-portal-runtime-observer"]
    assert role["rules"] == [{"apiGroups": [""], "resources": ["configmaps"],
                              "resourceNames": ["saw-bom-profiles", "saw-runtime-intent", "saw-runtime-status"],
                              "verbs": ["get"]}]


def test_multiple_catalog_sandboxes_receive_distinct_storage_and_ui_namespaces():
    import importlib.util
    spec = importlib.util.spec_from_file_location("portal_topology",ROOT/"charts/openshell-rhdh/files/portal.py")
    portal=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portal)
    catalog=json.loads((ROOT/"charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    targets=portal.sandbox_targets(U,REG,catalog["data-science"])
    assert set(targets)=={"default/notebook","cuda-dev/cuda-sandbox"}
    site={**SITE,"targets":targets,"selectedDigest":"a"*64}
    docs=render("saw-portal-container",U,"saw-"+U,dict(site=site,owner=U,registration=REG,installationID=user()["installationID"],ownerSubject=SITE["subject"],vaultPrefix=user()["vaultPrefix"],**{"global":GLOBAL}))
    writers=[o for o in docs if o["kind"]=="Application" and o["spec"]["source"]["path"]=="charts/saw-audit-writer"]
    assert len(writers)==2
    assert {o["spec"]["source"]["helm"]["releaseName"] for o in writers}=={x["base"] for x in targets.values()}
    assert {o["metadata"]["name"] for o in docs if o["kind"]=="Namespace" and o["metadata"]["name"].startswith("saw-ui-")}=={"saw-ui-"+x["relayID"] for x in targets.values()}
    for writer in writers:
        identity=writer["spec"]["source"]["helm"]["valuesObject"]["identity"]
        assert identity["workspace"]+"/"+identity["sandbox"] in targets


@pytest.mark.parametrize("older_component", [None, "identity", "gateway"])
def test_gateway_api_versions_require_the_same_reviewed_identity_revision(older_component):
    site = json.loads(json.dumps(SITE))
    revision = "a" * 40
    site["stack"]["identity"]["revision"] = revision
    site["stack"]["gateway"]["revision"] = revision
    if older_component:
        site["stack"][older_component]["revision"] = "b" * 40
    values = dict(site=site, owner=U, registration=REG, installationID=user()["installationID"],
                  ownerSubject=SITE["subject"], vaultPrefix=user()["vaultPrefix"],
                  **{"global": {**GLOBAL, "targetRevision": revision}})
    apps = [r for r in render("saw-portal-container", U, "saw-" + U, values)
            if r["kind"] == "Application"]
    gateway, = [app for app in apps if app["spec"]["source"]["path"] == "charts/openshell-saw-kubernetes"]
    expected = ["agents.x-k8s.io/v1beta1/Sandbox", "policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy"]
    for app in apps:
        helm = app["spec"]["source"]["helm"]
        if app is gateway and older_component is None:
            assert helm["apiVersions"] == expected
        else:
            assert "apiVersions" not in helm


@pytest.mark.parametrize("auto_approve,revision,renders", [
    (False, "a" * 40, True), (False, "main", False), (True, "main", True), (True, "a" * 40, True)])
def test_only_auto_approve_sites_may_follow_a_branch(auto_approve, revision, renders):
    # The same rule as preflight.configuration_facts (the portal and installer).
    site = json.loads(json.dumps(SITE))
    for item in site["stack"].values():
        item["revision"] = revision
    site["automaticEnrollment"]["revision"] = revision
    site["automaticEnrollment"]["relay"]["revision"] = revision
    site["automaticEnrollment"]["autoApprove"] = auto_approve
    values = dict(site=site, owner=U, registration=REG, installationID=user()["installationID"],
                  ownerSubject=SITE["subject"], vaultPrefix=user()["vaultPrefix"], **{"global": GLOBAL})
    result = subprocess.run(["helm", "template", U, str(ROOT / "charts/saw-portal-container"), "--namespace", "saw-" + U,
                             "--api-versions", "agents.x-k8s.io/v1beta1", "-f", "-"],
                            input=json.dumps(values), text=True, capture_output=True)
    assert (result.returncode == 0) == renders, result.stderr
    if not renders:
        assert "full Git commit SHA" in result.stderr


def test_model_gate_claim_is_shared_only_for_the_publisher_and_agent():
    audit = SITE["stack"]["audit"]["values"]
    # Use the same per-registration Helm values projection as the nested Applications.
    target = dict(workspace="default", sandbox="notebook", ui=True, base=U,
                  relayID=REG, subjectMap="saw-portal-relay-subject", modelInput="inference.model")
    site = {**SITE, "lifecycleVersion": 1, "targets": {"default/notebook": target}}
    manifests = render("saw-portal-container", U, "saw-"+U, {
        "site": site, "owner": U, "registration": REG, "installationID": user()["installationID"],
        "ownerSubject": SITE["subject"], "vaultPrefix": user()["vaultPrefix"], "global": GLOBAL})
    writer, = [r for r in manifests if r["kind"]=="Application" and r["spec"]["source"]["path"]=="charts/saw-audit-writer"]
    claims = {r["metadata"]["name"]:r["spec"] for r in child(writer) if r["kind"]=="PersistentVolumeClaim"}
    assert claims["saw-gate-"+U]["accessModes"] == ["ReadWriteMany"]
    assert claims["saw-gate-"+U]["storageClassName"] == audit["exchangeStorageClass"]
    assert claims["workspace-"+U]["accessModes"] == claims[U+"-history"]["accessModes"] == ["ReadWriteOnce"]


def app_values(application):
    source = application["spec"]["source"]["helm"]
    return source.get("valuesObject") or yaml.safe_load(source["values"])


def test_personal_assistant_credentials_are_projected_for_openshell():
    owner = {**user(), "profiles":["personal-assistant"]}
    site = {**SITE}
    site["automaticEnrollment"]={**SITE["automaticEnrollment"],"approvedProfiles":{"personal-assistant":"a"*64}}
    parent = render("saw-users","portal-ws-"+U,"saw-portal",{"global":GLOBAL,"users":[owner],"containerSites":{U:site}})
    app, = [a for a in parent if a.get("spec",{}).get("source",{}).get("path")=="charts/saw-portal-container"]
    bindings = {b["secret"]: b for b in app_values(app)["site"]["credentialBindings"]}
    assert set(bindings)=={"gmail","slack","inference"}
    assert bindings["gmail"]=={"secret":"gmail","key":"access_token","type":"gmail","refresh":"oauth2_refresh_token"}
    assert bindings["slack"]=={"secret":"slack","key":"bot_token","type":"slack"}
    resources=child(app)
    secrets={r["metadata"]["name"]:r for r in resources if r["kind"]=="ExternalSecret"}
    # Gmail's Secret holds only the refresh material; OpenShell mints the access token.
    for name,keys in {"gmail":{"refresh_token","client_id","client_secret"},"slack":{"bot_token"},"inference":{"api_key"}}.items():
        assert secrets[name]["metadata"]["namespace"]=="saw-ctl-"+REG
        assert {e["secretKey"] for e in secrets[name]["spec"]["data"]}==keys
    # Every Vault property synced is one the profile collects (what the portal writes).
    catalog = json.loads((ROOT/"charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    for name, spec in catalog["personal-assistant"]["secrets"].items():
        collected = {f["key"] for f in spec.get("fields", [])}
        assert {e["remoteRef"]["property"] for e in secrets[name]["spec"]["data"]} <= collected, name
    # No SAW credential proxy: OpenShell's supervisor injects the credentials.
    assert not [r for r in resources if "proxy" in r["metadata"]["name"]]
    assert not [r for r in resources if r["kind"]=="Application"
                and r["spec"]["source"]["path"].endswith("saw-kubernetes-proxy")]


def test_custom_inference_secret_carries_the_site_url():
    url="https://models.fixture.test/v1"
    owner={**user(),"profiles":["custom-inference"],"webSearch":{"enabled":False}}
    site={**SITE,"customInferenceURL":url,
          "automaticEnrollment":{**SITE["automaticEnrollment"],"approvedProfiles":{"custom-inference":"a"*64}}}
    root=render("saw-users","portal-ws-"+U,"saw-portal",{"global":GLOBAL,"users":[owner],"containerSites":{U:site}})
    app,=[a for a in root if a.get("spec",{}).get("source",{}).get("path")=="charts/saw-portal-container"]
    assert app_values(app)["site"]["credentialBindings"]==[{"secret":"inference","key":"api_key","type":"custom-inference"}]
    es,=[r for r in child(app) if r["kind"]=="ExternalSecret"]
    assert es["metadata"]["namespace"]=="saw-ctl-"+REG
    assert es["spec"]["target"]["template"]=={"engineVersion":"v2","mergePolicy":"Merge","data":{"url":url}}
    assert [e["secretKey"] for e in es["spec"]["data"]]==["api_key"]


def test_enrollment_job_uses_immutable_revisioned_inputs():
    from copy import deepcopy
    values = dict(owner=U, ownerSubject=SITE["subject"], registration=REG,
                  installationID=user()["installationID"], vaultPrefix=user()["vaultPrefix"],
                  site=deepcopy(SITE), **{"global": GLOBAL})
    def publication(v):
        resources = render("saw-portal-container", U, "saw-"+U, v)
        job, = [o for o in resources if o["kind"] == "Job"]
        configs = {o["metadata"]["name"]: o for o in resources if o["kind"] == "ConfigMap"}
        volume, = [v for v in job["spec"]["template"]["spec"]["volumes"] if v["name"] == "scripts"]
        source = configs[volume["configMap"]["name"]]
        assert source["immutable"] is True
        return job["metadata"]["name"], source["metadata"]["name"]
    initial = publication(values)
    assert publication(values) == initial
    values["site"]["automaticEnrollment"]["image"] = "registry.example.test/controller@sha256:" + "b"*64
    changed = publication(values)
    assert all(a != b for a, b in zip(initial, changed))
    values["site"]["automaticEnrollment"]["resources"]["limits"]["memory"] = "8Gi"
    assert all(a != b for a, b in zip(changed, publication(values)))


@pytest.mark.parametrize("override, expected", [
    (None, "0.1.10-rhaiv.0"),
    ("0.1.7-rhaiv.1", "0.1.7-rhaiv.1"),
])
def test_enrollment_compiles_the_selected_gateway_version(override, expected):
    from copy import deepcopy
    site = deepcopy(SITE)
    if override:
        site["stack"]["gateway"]["values"]["kubernetes"]["gateway"] = {"version": override}
    values = dict(owner=U, ownerSubject=SITE["subject"], registration=REG,
                  installationID=user()["installationID"], vaultPrefix=user()["vaultPrefix"],
                  site=site, **{"global": GLOBAL})
    resources = render("saw-portal-container", U, "saw-" + U, values)
    job, = [o for o in resources if o["kind"] == "Job"]
    script_volume, = [v for v in job["spec"]["template"]["spec"]["volumes"]
                      if v["name"] == "scripts"]
    config, = [o for o in resources if o["kind"] == "ConfigMap"
               and o["metadata"]["name"] == script_volume["configMap"]["name"]]
    bootstrap = json.loads(config["data"]["config.json"])
    assert bootstrap["gatewayVersion"] == expected


def test_enrollment_default_gateway_version_matches_gateway_chart():
    portal_values = yaml.safe_load((ROOT / "charts/saw-portal-container/values.yaml").read_text())
    gateway_values = yaml.safe_load((ROOT / "charts/openshell-saw-kubernetes/values.yaml").read_text())
    gateway_chart = yaml.safe_load((ROOT / "charts/openshell-saw-kubernetes/Chart.yaml").read_text())
    default = portal_values["driverDefaults"]["gatewayVersion"]
    assert default == gateway_values["kubernetes"]["gateway"]["version"]
    assert default == gateway_chart["appVersion"]


def test_static_projection_owns_no_workload_and_generates_same_composition():
    site = dict(SITE)
    values = {"global": GLOBAL, "users": [user()], "containerSites": {U: site},
              "projection": {"enabled": True, "applicationSetControllerLabels": {"app.kubernetes.io/name": "vp-gitops-applicationset-controller"}, "egress": [{"ports": [{"protocol": "TCP", "port": 443}]}]}}
    docs = render("saw-users", "workspaces", "saw-installation", values)
    assert not any(o["kind"] in ("Namespace", "Application", "VirtualMachine") for o in docs)
    appset, = [o for o in docs if o["kind"] == "ApplicationSet"]
    deployment, = [o for o in docs if o["kind"] == "Deployment"]
    assert appset["spec"]["template"]["spec"]["source"]["path"] == "charts/saw-users"
    assert appset["spec"]["template"]["spec"]["source"]["targetRevision"] == "{{ .revision }}"
    assert appset["spec"]["template"]["spec"]["source"]["helm"]["values"] == "{{ .workspaceValues }}"
    configuration, = [o for o in docs if "workspaces.json" in o.get("data", {})]
    pod = deployment["spec"]["template"]["spec"]
    config_volume, = [v for v in pod["volumes"] if v["name"] == "configuration"]
    assert configuration["kind"] == "ConfigMap"
    assert configuration["metadata"]["name"] == config_volume["configMap"]["name"]
    account, = [o for o in docs if o["kind"] == "ServiceAccount"
                and o["metadata"]["name"] == pod["serviceAccountName"]]
    assert "data" not in account
    cfg = json.loads(configuration["data"]["workspaces.json"])
    observer = cfg["containerSites"][U]["observer"]
    assert observer == {"namespace": "saw-installation", "serviceAccount": deployment["metadata"]["name"]}
    assert cfg["users"] == [user()]
    assert not any(o["kind"] == "Secret" for o in docs), "plugin identity is generated, never committed in values"
    # Only the bootstrap can create its two identity Secrets; the server reads public data.
    server = deployment["spec"]["template"]["spec"]["serviceAccountName"]
    rules = [o for o in docs if o["kind"] in ("Role", "ClusterRole") and o["metadata"]["name"] == server]
    assert all("secrets" not in r["resources"] and r["verbs"] == ["get"] for o in rules for r in o["rules"])
    preflight_role, = [o for o in docs if o["kind"] == "ClusterRole"
                       and o["metadata"]["name"] == server + "-preflight"]
    assert all("secrets" not in rule.get("resources", []) for rule in preflight_role["rules"])
    assert any(rule.get("resourceNames") == ["saw-saw-alice-runtime", "saw-saw-alice-runtime-kata"]
               for rule in preflight_role["rules"])
    source, = [o for o in docs if o["kind"] == "ConfigMap" and "projector.py" in o.get("data", {})]
    assert source["data"]["preflight.py"] == (ROOT / "charts/saw-portal-container/files/preflight.py").read_text()
    container_values = dict(owner=U, ownerSubject=SITE["subject"], registration=REG,
                            installationID=user()["installationID"], vaultPrefix=user()["vaultPrefix"],
                            site={**SITE, "observer": observer}, **{"global": GLOBAL})
    resources = render("saw-portal-container", U, "saw-"+U, container_values)
    readers = [o for o in resources if o["kind"] == "RoleBinding" and o["metadata"]["name"] == "portal-binding-reader"]
    assert readers[0]["subjects"] == [{"kind": "ServiceAccount", "name": server, "namespace": "saw-installation"}]


def test_static_kata_projector_can_read_only_approved_platform_metadata():
    entry = user()
    entry["values"] = {"deployment": {"mode": "kata"}}
    site = {**SITE, "kataRuntimeClass": {"name": "kata", "uid": "11111111-1111-4111-8111-111111111111",
                                          "sha256": "a" * 64}}
    docs = render("saw-users", "workspaces", "saw-installation", {
        "global": GLOBAL, "users": [entry], "containerSites": {U: site},
        "projection": {"enabled": True, "applicationSetControllerLabels": {"app": "controller"},
                       "egress": [{"ports": [{"protocol": "TCP", "port": 443}]}]}})
    role, = [obj for obj in docs if obj["kind"] == "ClusterRole"
             and obj["metadata"]["name"].endswith("-preflight")]
    assert any(rule.get("resources") == ["runtimeclasses"] and rule.get("resourceNames") == ["kata"]
               for rule in role["rules"])
    assert any(rule.get("resources") == ["nodes"] and rule.get("verbs") == ["list"]
               for rule in role["rules"])
    assert all("secrets" not in rule.get("resources", []) for rule in role["rules"])


def test_static_mixed_backends_keep_vm_resolution_in_the_root():
    values = {"global": GLOBAL, "users": [user(), {"name": "bob"}], "containerSites": {U: SITE},
              "ownerResolution": {"enabled": True},
              "projection": {"enabled": True, "applicationSetControllerLabels": {"app.kubernetes.io/name": "vp-gitops-applicationset-controller"}, "egress": [{"ports": [{"protocol": "TCP", "port": 443}]}]}}
    docs = render("saw-users", "workspaces", "saw-installation", values)
    apps = [o for o in docs if o["kind"] == "Application"]
    assert {o["metadata"]["name"] for o in apps} == {"saw-bob", "saw-bob-bom", "saw-bob-secrets"}
    resolver = [o for o in docs if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "saw-owner-subject"]
    assert [o["metadata"]["namespace"] for o in resolver] == ["saw-bob"]
    configuration, = [o for o in docs if "workspaces.json" in o.get("data", {})]
    assert json.loads(configuration["data"]["workspaces.json"])["users"] == [user()]


def test_foundation_can_be_reviewed_without_placeholder_approval_or_workload():
    from copy import deepcopy
    site = deepcopy(SITE)
    site["automaticEnrollment"]["enabled"] = False
    del site["automaticEnrollment"]["reference"]
    site["automaticEnrollment"].pop("approvedProfiles", None)
    render("saw-users", "workspaces", "saw-installation", {
        "global": GLOBAL, "users": [user()], "containerSites": {U: site}})
    docs = render("saw-portal-container", U, "saw-"+U, dict(
        site=site, owner=U, ownerSubject=site["subject"], registration=REG,
        installationID=user()["installationID"], vaultPrefix=user()["vaultPrefix"], **{"global": GLOBAL}))
    assert not any(o["kind"] == "Job" for o in docs), "no enrollment before review"
    assert not any(o["metadata"]["name"] == "saw-runtime-intent" for o in docs)
    assert any(o["metadata"]["name"] == "saw-portal-enrollment" for o in docs)
    assert any(o["kind"] == "RoleBinding" and o["metadata"]["name"] == "portal-binding-reader" for o in docs)
    assert any(o.get("spec", {}).get("source", {}).get("path") == "charts/openshell-saw-kubernetes" for o in docs)


def pull_grant_render(image):
    site = copy.deepcopy(SITE)
    site["automaticEnrollment"]["image"] = image
    site["enrollment"] = dict(
        registration=REG, image=image, buildNamespace="builds", revision="1" * 40,
        approved={}, intent={"profileRef": {"name": "saw-bom-profiles"}, "bindings": {
            "ownerID": user()["installationID"], "ownerSubject": SITE["subject"],
            "namespace": "saw-" + U, "namespaceUID": "fixture-uid", "mode": "container",
            "bindings": {"default/notebook": {
                "workspace": {"claimName": "workspace-" + U},
                "toolGate": {"trusted": {"claimName": "saw-gate-" + U},
                             "audit": {"claimName": "saw-audit-" + U},
                             "ownerLogin": U, "receiptKey": "fixture-public-key"},
                "browser": {"ownerLogin": U, "origin": "https://alice-default-notebook-ui.apps.cluster.example.com"}}}}})
    return render("saw-portal-container", U, "saw-" + U, dict(
        site=site, owner=U, ownerSubject=SITE["subject"], registration=REG,
        installationID=user()["installationID"], intentGeneration=1,
        vaultPrefix=user()["vaultPrefix"], **{"global": GLOBAL}))


def test_gate_preparation_waits_for_the_relay_browser_proof():
    """Argo never recreates a failed Job, so preparation must outlast the
    relay identity Job that projects the proof it mounts."""
    resources = pull_grant_render("ghcr.io/example/saw-kubernetes-runtime@sha256:" + "b" * 64)
    jobs = [r for r in resources if r["kind"] == "Job" and r["metadata"]["name"].startswith("saw-gate-preparation")]
    assert jobs and all(j["spec"]["activeDeadlineSeconds"] == 1800 for j in jobs)


def test_a_published_runtime_image_needs_no_build_namespace():
    """A registry image needs no ImageStream pull grant, so nothing is created
    in buildNamespace (which need not exist) and the charts are told none."""
    resources = pull_grant_render("ghcr.io/example/saw-kubernetes-runtime@sha256:" + "b" * 64)
    assert not [r for r in resources if r["metadata"].get("namespace") == "builds"]
    for app in (r for r in resources if r["kind"] == "Application"):
        values = app_values(app)
        assert values.get("imageBuildNamespace", "") == "", app["metadata"]["name"]


@pytest.mark.parametrize("stream", ["saw-kubernetes-runtime", "custom-runtime"])
def test_runtime_pull_grants_follow_the_configured_image(stream):
    from copy import deepcopy
    site = deepcopy(SITE)
    image = "image-registry.openshift-image-registry.svc:5000/builds/" + stream + "@sha256:" + "b" * 64
    site["automaticEnrollment"]["image"] = image
    site["enrollment"] = dict(
        registration=REG, image=image, buildNamespace="builds", revision="1" * 40,
        approved={}, intent={"profileRef": {"name": "saw-bom-profiles"}, "bindings": {
            "ownerID": user()["installationID"], "ownerSubject": SITE["subject"],
            "namespace": "saw-" + U, "namespaceUID": "fixture-uid", "mode": "container",
            "bindings": {"default/notebook": {
                "workspace": {"claimName": "workspace-" + U},
                "toolGate": {"trusted": {"claimName": "saw-gate-" + U},
                             "audit": {"claimName": "saw-audit-" + U},
                             "ownerLogin": U, "receiptKey": "fixture-public-key"},
                "browser": {"ownerLogin": U, "origin": "https://alice-default-notebook-ui.apps.cluster.example.com"}}}}})
    resources = render("saw-portal-container", U, "saw-" + U, dict(
        site=site, owner=U, ownerSubject=SITE["subject"], registration=REG,
        installationID=user()["installationID"], intentGeneration=1,
        vaultPrefix=user()["vaultPrefix"], **{"global": GLOBAL}))
    grants = [rule for obj in resources if obj["kind"] == "Role"
              for rule in obj["rules"] if "imagestreams/layers" in rule["resources"]
              and obj["metadata"]["name"] in {"enroll-" + REG + "-pull", "portal-gate-" + REG}]
    assert len(grants) == 2
    assert all(rule["resourceNames"] == [stream] and rule["verbs"] == ["get"] for rule in grants)

def test_removing_last_static_owner_keeps_only_empty_registration_config():
    docs = render("saw-users", "static", "saw-workspaces", {
        "global": GLOBAL, "users": [], "projection": {"enabled": True}})
    assert len(docs) == 1
    assert docs[0]["kind"] == "ConfigMap"
    assert docs[0]["metadata"]["name"].endswith("-configuration")
    assert json.loads(docs[0]["data"]["workspaces.json"]) == {"users": []}


def test_a_site_without_workload_settings_uses_the_driver_defaults():
    """Regression: the shipped defaults set no gateway workload block (its image
    comes from the first sandbox target), so the policy's runtime image must
    fall back to driverDefaults instead of failing on a nil lookup."""
    site = copy.deepcopy(SITE)
    del site["stack"]["gateway"]["values"]["kubernetes"]["workload"]
    image = "registry.example.test/agent@sha256:" + "c"*64
    site["targets"]["default/notebook"]["image"] = image   # the projector sets it from the BOM
    top = render("saw-users","portal-ws-"+U,"saw-portal",{"global":GLOBAL,"users":[user()],"containerSites":{U:site}})
    portal, = [a for a in top if a["kind"]=="Application" and a["spec"]["source"]["path"]=="charts/saw-portal-container"]
    apps = [r for r in child(portal) if r["kind"]=="Application"]
    defaults = yaml.safe_load((ROOT/"charts/saw-portal-container/values.yaml").read_text())["driverDefaults"]
    policy, = [a for a in apps if a["metadata"]["name"].endswith("-policy")]
    assert app_values(policy)["runtimeImage"] == defaults["runtimeImage"]
    gateway, = [a for a in apps if a["metadata"]["name"].endswith("-gateway")]
    assert app_values(gateway)["kubernetes"]["workload"]["image"] == image


def ip_free_site():
    """The site as a fresh cluster has it: no egress lists, issuer, IPs or class names."""
    site = copy.deepcopy(SITE)
    site.pop("auditReceipts")
    site["stack"]["gateway"]["values"]["kubernetes"]["storage"].pop("className", None)
    for key in ("storageClass", "exchangeStorageClass"):
        site["stack"]["audit"]["values"].pop(key, None)
    site["stack"]["identity"]["values"].pop("network", None)
    gateway = site["stack"]["gateway"]["values"]
    gateway["kubernetes"]["network"].pop("gatewayEgress", None)
    gateway.get("oidc", {}).pop("issuerUrl", None)
    relay = site["automaticEnrollment"]["relay"]
    relay.pop("egress", None)
    relay.pop("issuer", None)
    return site


def test_workspace_reaches_the_api_through_control_plane_nodes_without_cluster_ips():
    top = render("saw-users", "portal-ws-" + U, "saw-portal",
                 {"global": GLOBAL, "users": [user()], "containerSites": {U: ip_free_site()}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    api, = [r for r in resources if r["kind"] == "AdminNetworkPolicy"]
    assert api["metadata"]["name"] == f"saw-{REG}-kubernetes-api"
    assert api["spec"]["priority"] > 51  # after the runtime's own supervisor policy
    subject = api["spec"]["subject"]["pods"]
    names = subject["namespaceSelector"]["matchExpressions"][0]["values"]
    assert {"saw-" + U, "saw-ctl-" + REG} <= set(names)
    assert subject["podSelector"]["matchLabels"] == {"saw.redhat.com/kubernetes-api": "allow"}
    assert {"key": "openshell.ai/boundary-role", "operator": "DoesNotExist"} in subject["podSelector"]["matchExpressions"]
    rule, = api["spec"]["egress"]
    assert rule["action"] == "Allow" and rule["ports"] == [{"portNumber": {"protocol": "TCP", "port": 6443}}]
    assert rule["to"] == [{"nodes": {"matchExpressions": [
        {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists"}]}}]
    workloads = [r for a in resources if a["kind"] == "Application" for r in child(a)]
    every = resources + workloads
    # No policy anywhere in the workspace names a cluster address other than "any" for HTTPS.
    for policy in (r for r in every if r["kind"] == "NetworkPolicy"):
        for egress in policy["spec"].get("egress") or []:
            for peer in egress.get("to", []):
                if "ipBlock" in peer:
                    assert peer["ipBlock"]["cidr"] == "0.0.0.0/0", policy["metadata"]["name"]
                    assert egress["ports"] == [{"protocol": "TCP", "port": 443}]
    gateway, = [r for r in workloads if r["kind"] == "StatefulSet" and r["metadata"]["name"] == U + "-gateway"]
    assert gateway["spec"]["template"]["metadata"]["labels"]["saw.redhat.com/kubernetes-api"] == "allow"
    config = next(r for r in workloads if r["kind"] == "ConfigMap" and r["metadata"]["name"] == U + "-gateway-config")
    assert "https://openshell-keycloak-ingress-saw-keycloak.apps.cluster.example.com/realms/openshell" in json.dumps(config)
    claims = {r["metadata"]["name"]: r["spec"].get("storageClassName") for r in every
              if r["kind"] == "PersistentVolumeClaim"}
    # Without receipts every volume is ReadWriteOnce on the cluster default class.
    assert claims and all(c is None for c in claims.values())
    sandboxes = [r for r in every if r["kind"] in ("Pod", "Sandbox")]
    assert not any("saw.redhat.com/kubernetes-api" in json.dumps(s) for s in sandboxes)


def test_without_receipts_the_gate_keeps_a_local_log_and_no_history():
    site = ip_free_site()
    top = render("saw-users", "portal-ws-" + U, "saw-portal",
                 {"global": GLOBAL, "users": [user()], "containerSites": {U: site}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    assert not [r for r in resources if r["kind"] == "Namespace" and r["metadata"]["name"].startswith("saw-history-")]
    writer, = [r for r in resources if r["kind"] == "Application"
               and r["spec"]["source"]["path"] == "charts/saw-audit-writer"]
    assert writer["spec"]["destination"]["namespace"] == "saw-" + U
    audit = child(writer)
    assert sorted(r["kind"] for r in audit) == ["PersistentVolumeClaim"] * 3
    assert {r["metadata"]["name"]: r["spec"]["accessModes"] for r in audit} == {
        "saw-audit-" + U: ["ReadWriteOnce"], "saw-gate-" + U: ["ReadWriteOnce"], "workspace-" + U: ["ReadWriteOnce"]}
    enroll, = [r for r in resources if r["kind"] == "ConfigMap" and r["metadata"]["name"].startswith("bootstrap-")]
    assert json.loads(enroll["data"]["config.json"])["auditReceipts"] is False
    assert not [r for r in resources if r["kind"] == "NetworkPolicy" and r["metadata"]["name"] == "bootstrap-writer"]


def test_receipts_keep_the_history_writer_and_exchange():
    top = render("saw-users", "portal-ws-" + U, "saw-portal",
                 {"global": GLOBAL, "users": [user()], "containerSites": {U: SITE}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    assert [r for r in resources if r["kind"] == "Namespace" and r["metadata"]["name"] == "saw-history-" + REG]
    writer, = [r for r in resources if r["kind"] == "Application"
               and r["spec"]["source"]["path"] == "charts/saw-audit-writer"]
    audit = child(writer)
    assert {r["metadata"]["name"] for r in audit if r["kind"] == "Deployment"} == {U + "-writer", U + "-forward"}
    exchange, = [r for r in audit if r["kind"] == "PersistentVolumeClaim" and r["metadata"]["name"] == "saw-audit-" + U]
    assert exchange["spec"]["accessModes"] == ["ReadWriteMany"]


def test_gateway_and_supervisors_reach_the_ocsf_collector():
    top = render("saw-users", "portal-ws-" + U, "saw-portal",
                 {"global": GLOBAL, "users": [user()], "containerSites": {U: ip_free_site()}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    workloads = [r for a in resources if a["kind"] == "Application" for r in child(a)]
    collector = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshell-agents"}},
                 "podSelector": {"matchLabels": {"app.kubernetes.io/name": "saw-ocsf-collector",
                                                 "app.kubernetes.io/component": "opentelemetry-collector"}}}
    config = next(r for r in workloads if r["kind"] == "ConfigMap" and r["metadata"]["name"] == U + "-gateway-config")
    assert "endpoint = \"http://saw-ocsf-collector.openshell-agents.svc:4317\"" in config["data"]["gateway.toml"]
    gateway = next(r for r in workloads if r["kind"] == "NetworkPolicy" and r["metadata"]["name"] == U + "-gateway")
    assert {"to": [collector], "ports": [{"protocol": "TCP", "port": 4317}]} in gateway["spec"]["egress"]
    supervisors, = [r for r in workloads if r["kind"] == "AdminNetworkPolicy"]
    rule, = [e for e in supervisors["spec"]["egress"] if e["name"] == "ocsf-collector"]
    assert rule["action"] == "Pass" and rule["to"] == [{"pods": collector}]
    assert rule["ports"] == [{"portNumber": {"protocol": "TCP", "port": 4317}}]
    # Before the private-network deny, so the in-cluster collector stays reachable.
    names = [e["name"] for e in supervisors["spec"]["egress"]]
    assert names.index("ocsf-collector") < names.index("deny-private-networks")
    # The supervisor admission check accepts the collector the gateway passes it.
    admission = [r for r in workloads if r["kind"] == "ValidatingAdmissionPolicy"]
    checks = " ".join(v["expression"] for a in admission for v in a["spec"]["validations"])
    assert "e.value == \"http://saw-ocsf-collector.openshell-agents.svc:4317\"" in checks
    # The agent trace relay is on by default and goes to the same collector.
    assert "[openshell.gateway.otlp.agent]" in config["data"]["gateway.toml"]
    assert ("e.name != 'OPENSHELL_OTLP_AGENT_ENDPOINT' || "
            "e.value == \"http://saw-ocsf-collector.openshell-agents.svc:4317\"") in " ".join(checks.split())


def test_ocsf_export_can_be_turned_off():
    site = ip_free_site()
    site["telemetry"] = {"ocsfEndpoint": ""}
    top = render("saw-users", "portal-ws-" + U, "saw-portal",
                 {"global": GLOBAL, "users": [user()], "containerSites": {U: site}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    workloads = [r for a in resources if a["kind"] == "Application" for r in child(a)]
    assert "otlp" not in json.dumps([r for r in workloads if r["kind"] == "ConfigMap"])
    supervisors, = [r for r in workloads if r["kind"] == "AdminNetworkPolicy"]
    assert "ocsf-collector" not in [e["name"] for e in supervisors["spec"]["egress"]]
    admission = [r for r in workloads if r["kind"] == "ValidatingAdmissionPolicy"]
    assert "OPENSHELL_OTLP" not in json.dumps(admission)


def test_gateway_and_admission_pin_the_same_runtime_and_supervisor_images():
    """The policy admits only the images the gateway is configured with; the two
    must come from one value, not from two charts' separate defaults."""
    top = render("saw-users", "portal-ws-" + U, "saw-portal",
                 {"global": GLOBAL, "users": [user()], "containerSites": {U: ip_free_site()}})
    resources = [r for a in top if a["kind"] == "Application" for r in child(a)]
    workloads = [r for a in resources if a["kind"] == "Application" for r in child(a)]
    config = next(r for r in workloads if r["kind"] == "ConfigMap" and r["metadata"]["name"] == U + "-gateway-config")
    toml = config["data"]["gateway.toml"]
    defaults = yaml.safe_load((ROOT / "charts/saw-portal-container/values.yaml").read_text())["driverDefaults"]
    assert f'sandbox_runtime_image = "{defaults["runtimeImage"]}"' in toml
    assert f'supervisor_image = "{defaults["supervisorImage"]}"' in toml
    checks = " ".join(v["expression"] for a in workloads if a["kind"] == "ValidatingAdmissionPolicy"
                      for v in a["spec"]["validations"])
    assert json.dumps(defaults["runtimeImage"]) in checks
    assert json.dumps(defaults["supervisorImage"]) in checks
    # The gateway chart's own defaults name the same images.
    gateway = yaml.safe_load((ROOT / "charts/openshell-saw-kubernetes/values.yaml").read_text())["kubernetes"]
    assert gateway["workload"]["runtimeImage"] == defaults["runtimeImage"]
    assert gateway["supervisor"]["image"] == defaults["supervisorImage"]


def test_the_pattern_installs_the_collector():
    values = yaml.safe_load((ROOT / "values-prod.yaml").read_text())["clusterGroup"]
    assert values["subscriptions"]["opentelemetry"]["name"] == "opentelemetry-product"
    assert values["applications"]["saw-telemetry"]["path"] == "charts/saw-telemetry"
    collector, = render("saw-telemetry", "saw-telemetry", "openshell-agents", {})
    assert collector["metadata"]["name"] == "saw-ocsf"  # Service saw-ocsf-collector
    pipelines = collector["spec"]["config"]["service"]["pipelines"]
    for signal in ("logs", "traces"):   # OCSF events and relayed agent traces
        assert pipelines[signal]["receivers"] == ["otlp"] and pipelines[signal]["exporters"] == ["debug"]
    assert collector["spec"]["config"]["receivers"]["otlp"]["protocols"] == {"grpc": {"endpoint": "0.0.0.0:4317"}}
