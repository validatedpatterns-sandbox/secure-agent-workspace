"""Render the same owner request through both Helm levels and the stock component charts."""
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
            "registration":REG,"intentGeneration":1,"vaultPrefix":f"secret/data/hub/saw-{U}/{REG}",
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


def test_container_rejects_another_registrations_keys():
    v = dict(owner=U,ownerSubject=SITE["subject"],registration=REG,vaultPrefix="secret/data/hub/saw-other/"+REG)
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
    public_ca = next(v for v in spec["volumes"] if v["name"] == "gateway-ca")
    assert public_ca["configMap"]["name"] == U+"-gateway-ca"
    grants=[rule for r in resources if r["kind"] in ("Role","ClusterRole") and "enroll" in r["metadata"]["name"] for rule in r["rules"]]
    assert all("secrets" not in x["resources"] and "*" not in x["verbs"] for x in grants)
    assert [x["resourceNames"] for x in grants if "patch" in x["verbs"]]==[["saw-portal-enrollment"]]
    files=ROOT/"charts/saw-portal-container/files"
    assert (files/"receipt.py").read_bytes()==(ROOT/"kubernetes-runtime/saw_kubernetes/receipt.py").read_bytes()
    assert (files/"portal_contract.py").read_text()==(ROOT/"kubernetes-runtime/saw_kubernetes/portal_contract.py").read_text().replace("from .boundary import","from saw_kubernetes.boundary import")


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


def test_personal_assistant_uses_the_vm_proxy_policy_and_trusted_secret_projection():
    owner = {**user(), "profiles":["personal-assistant"]}
    site = {**SITE, "providerAllowHosts":["integrate.api.nvidia.com","slack.com","gmail.googleapis.com","oauth2.googleapis.com"]}
    site["automaticEnrollment"]={**SITE["automaticEnrollment"],"approvedProfiles":{"personal-assistant":"a"*64}}
    parent = render("saw-users","portal-ws-"+U,"saw-portal",{"global":GLOBAL,"users":[owner],"containerSites":{U:site}})
    app, = [a for a in parent if a.get("spec",{}).get("source",{}).get("path")=="charts/saw-portal-container"]
    resources=child(app)
    broker,=[r for r in resources if r["kind"]=="ConfigMap" and r["metadata"]["name"].endswith("-proxy-policy")]
    policy=json.loads(broker["data"]["config.json"])
    bindings={b["secret"]:b for b in policy["bindings"]}
    assert set(bindings)=={"gmail","slack","inference"}
    assert bindings["gmail"]["refresh"]["tokenURL"]=="https://oauth2.googleapis.com/token"
    assert bindings["slack"]=={"secret":"slack","key":"bot_token","providers":["slack"]}
    secrets={r["metadata"]["name"]:r for r in resources if r["kind"]=="ExternalSecret"}
    for name,keys in {"gmail":{"refresh_token","client_id","client_secret"},"slack":{"bot_token"},"inference":{"api_key"}}.items():
        assert secrets[name]["metadata"]["namespace"]=="saw-ctl-"+REG
        assert {e["secretKey"] for e in secrets[name]["spec"]["data"]}==keys
    proxy,=[r for r in resources if r["kind"]=="Application" and r["spec"]["source"]["path"]=="charts/saw-kubernetes-proxy"]
    assert proxy["spec"]["source"]["helm"]["valuesObject"]["credentialSecretNames"]==sorted(secrets)


def test_custom_inference_projection_pins_broker_url_and_keeps_key_private():
    url="https://models.fixture.test/v1"
    owner={**user(),"profiles":["custom-inference"],"webSearch":{"enabled":False}}
    site={**SITE,"providerAllowHosts":["models.fixture.test"],"customInferenceURL":url,
          "automaticEnrollment":{**SITE["automaticEnrollment"],"approvedProfiles":{"custom-inference":"a"*64}}}
    root=render("saw-users","portal-ws-"+U,"saw-portal",{"global":GLOBAL,"users":[owner],"containerSites":{U:site}})
    app,=[a for a in root if a.get("spec",{}).get("source",{}).get("path")=="charts/saw-portal-container"]
    resources=child(app)
    broker,=[r for r in resources if r["kind"]=="ConfigMap" and r["metadata"]["name"].endswith("-proxy-policy")]
    policy=json.loads(broker["data"]["config.json"])
    assert policy["allowHosts"]==["models.fixture.test"] and not policy["profiles"].get("custom-inference")
    assert policy["bindings"]==[{"providers":["custom-inference"],"key":"api_key","secret":"inference"}]
    es,=[r for r in resources if r["kind"]=="ExternalSecret"]
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
    container_values = dict(owner=U, ownerSubject=SITE["subject"], registration=REG,
                            installationID=user()["installationID"], vaultPrefix=user()["vaultPrefix"],
                            site={**SITE, "observer": observer}, **{"global": GLOBAL})
    resources = render("saw-portal-container", U, "saw-"+U, container_values)
    readers = [o for o in resources if o["kind"] == "RoleBinding" and o["metadata"]["name"] == "portal-binding-reader"]
    assert readers[0]["subjects"] == [{"kind": "ServiceAccount", "name": server, "namespace": "saw-installation"}]


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


@pytest.mark.parametrize("stream", ["saw-kubernetes-runtime", "custom-runtime"])
def test_runtime_pull_grants_follow_the_configured_image(stream):
    from copy import deepcopy
    site = deepcopy(SITE)
    image = "image-registry.example.test/builds/" + stream + "@sha256:" + "b" * 64
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
