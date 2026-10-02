"""Render the openshell-saw and saw-bom charts and check what the VM receives.

Needs `helm` on PATH (CI installs it). The tests also cross-check the two
charts: the rendered installer ConfigMap and profile ConfigMap are laid out
as the VM would mount them, and the shipped installer validates them.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshell-saw"
BOM_CHART = ROOT / "charts" / "saw-bom"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def helm_template(chart=CHART, *args, release="saw-test", namespace="saw-alice"):
    return subprocess.run([HELM, "template", release, str(chart), "--namespace", namespace, *args],
                          capture_output=True, text=True)


def _pattern_saw_settings():
    """The openshell-saw values the saw-users chart gives every user
    (defaults.openshellSaw) plus alice as owner, as --set flags, so these
    tests follow the chart instead of a copy of it."""
    defaults = yaml.safe_load((ROOT / "charts/saw-users/values.yaml").read_text())["defaults"]["openshellSaw"]

    def flatten(prefix, value):
        if isinstance(value, dict):
            for k, v in value.items():
                yield from flatten(f"{prefix}.{k}" if prefix else k, v)
        else:
            yield "--set", f"{prefix}={str(value).lower() if isinstance(value, bool) else value}"

    flags = [f for pair in flatten("", defaults) for f in pair]
    return (*flags, "--set", "accessControl.owner=alice")


PATTERN_SAW_SETTINGS = _pattern_saw_settings()


def render(*args, **kwargs):
    result = helm_template(CHART, "--set", "sandboxName=saw-test", *args, **kwargs)
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    return {(d["kind"], d["metadata"]["name"]): d for d in docs}


def render_error(*args):
    result = helm_template(CHART, "--set", "sandboxName=saw-test", *args)
    assert result.returncode != 0, "render was expected to fail"
    return result.stderr


def cloud_config(docs, name="saw-test"):
    user_data = docs[("Secret", f"{name}-cloudinit")]["stringData"]["userData"]
    assert user_data.startswith("#cloud-config\n")
    return yaml.safe_load(user_data)


def written(cfg, path):
    return next(f["content"] for f in cfg["write_files"] if f["path"] == path)


def installer_data(docs, name="saw-test"):
    return docs[("ConfigMap", f"{name}-installer")]["data"]


@pytest.fixture(scope="module")
def ab():
    spec = importlib.util.spec_from_file_location(
        "apply_bom_chart", CHART / "files" / "installer" / "apply_bom.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def default_docs():
    return render()


# -- no SSH provisioning --------------------------------------------------------

def test_no_setup_job_and_no_ssh_provisioning(default_docs):
    kinds = {k for k, _ in default_docs}
    assert ("Job", "saw-test-setup") not in default_docs
    assert ("Job", "saw-test-prepare") in default_docs
    assert "VirtualMachine" in kinds
    text = yaml.safe_dump(list(default_docs.values()))
    for forbidden in ("virtctl", "guest_ssh", "guest_scp", "portforward", "openshell-aap-ssh"):
        assert forbidden not in text, forbidden


def test_prepare_role_has_no_vm_access(default_docs):
    rules = default_docs[("Role", "saw-test-prepare")]["rules"]
    groups = {g for r in rules for g in r["apiGroups"]}
    assert "kubevirt.io" not in groups and "subresources.kubevirt.io" not in groups


def test_prepare_scripts_render_and_are_valid_bash(default_docs, tmp_path):
    data = default_docs[("ConfigMap", "saw-test-prepare-scripts")]["data"]
    assert set(data) == {"prepare.sh", "install-deps.sh", "bootstrap-golden-image.sh",
                         "register-keycloak-redirect.sh"}
    for name, text in data.items():
        path = tmp_path / name
        path.write_text(text)
        assert subprocess.run(["bash", "-n", str(path)]).returncode == 0, name
    assert 'VM_NAME="saw-test"' in data["prepare.sh"]


# -- VM wiring -------------------------------------------------------------

def test_vm_attaches_inputs_as_serial_disks(default_docs):
    spec = default_docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]
    disks = {d["name"]: d.get("serial") for d in spec["domain"]["devices"]["disks"]}
    volumes = {v["name"]: v for v in spec["volumes"]}
    assert disks["saw-installer"] == "saw-installer"
    assert volumes["saw-installer"]["configMap"] == {"name": "saw-test-installer"}
    assert volumes["saw-profiles"]["configMap"] == {"name": "saw-bom-profiles", "optional": True}
    secret_volumes = {v["secret"]["secretName"]: n for n, v in volumes.items() if "secret" in v}
    assert secret_volumes == {"inference": "saw-sec-0", "web-search": "saw-sec-1"}
    for name in secret_volumes.values():
        assert disks[name] == name
        assert volumes[name]["secret"]["optional"] is True
    assert set(disks) == set(volumes)
    assert volumes["cloudinitdisk"]["cloudInitNoCloud"]["secretRef"]["name"] == "saw-test-cloudinit"


def test_duplicate_secret_names_attach_once():
    docs = render("--set", "inference.secretName=web-search")
    volumes = docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]["volumes"]
    assert [v["secret"]["secretName"] for v in volumes if "secret" in v] == ["web-search"]


def test_cloud_init_ships_the_guest_files_unchanged(default_docs):
    cfg = cloud_config(default_docs)
    guest = CHART / "files" / "guest"
    assert written(cfg, "/usr/local/sbin/saw-mount-inputs") == (guest / "saw-mount-inputs.sh").read_text()
    assert written(cfg, "/etc/systemd/system/saw-install.service") == (guest / "saw-install.service").read_text()
    assert written(cfg, "/etc/systemd/system/saw-apply.service") == (guest / "saw-apply.service").read_text()


def test_cloud_init_does_not_depend_on_the_secret_list(default_docs):
    """cloud-init runs once per VM; the Secret list must come from the
    installer disk (re-read every boot), not from cloud-init."""
    other = render("--set", "inference.secretName=", "--set", "additionalProviderSecrets[0]=other")
    assert cloud_config(default_docs) == cloud_config(other)


def test_secret_disk_order_matches_config_json(default_docs):
    spec = default_docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]
    by_disk = {v["name"]: v["secret"]["secretName"] for v in spec["volumes"] if "secret" in v}
    config = json.loads(installer_data(default_docs)["config.json"])
    assert by_disk == {f"saw-sec-{i}": name for i, name in enumerate(config["secrets"])}


def test_gateway_files_identical_on_cloud_init_and_installer_disk(default_docs):
    cfg, data = cloud_config(default_docs), installer_data(default_docs)
    assert written(cfg, "/etc/openshell/gateway.env").strip() == data["gateway.env"].strip()
    assert written(cfg, "/etc/openshell/gateway.toml").strip() == data["gateway.toml"].strip()


def test_runcmd_is_valid_bash_and_enables_units_first(default_docs, tmp_path):
    run = cloud_config(default_docs)["runcmd"][0]
    path = tmp_path / "runcmd.sh"
    path.write_text(run)
    assert subprocess.run(["bash", "-n", str(path)]).returncode == 0
    assert run.index("systemctl enable saw-install.service saw-apply.service") < \
        run.index("systemctl start openshell-gateway-setup.service")
    assert "|| echo" in run.split("openshell-gateway-setup.service", 1)[1].splitlines()[0] + \
        run.split("openshell-gateway-setup.service", 1)[1].splitlines()[1]
    assert "set -e" not in run.replace("set -uo", "")


def test_installer_units_run_install_then_apply(default_docs, tmp_path):
    cfg = cloud_config(default_docs)
    install = written(cfg, "/etc/systemd/system/saw-install.service")
    apply = written(cfg, "/etc/systemd/system/saw-apply.service")
    assert "Wants=saw-install.service" in apply
    assert ("ExecStart=/usr/local/sbin/saw-with-lock /usr/bin/python3 "
            "/var/lib/saw/verified/installer/apply_bom.py install "
            "--installer-dir /var/lib/saw/verified/installer" in install)
    assert ("ExecStart=/usr/local/sbin/saw-with-lock /usr/bin/python3 "
            "/var/lib/saw/verified/installer/apply_bom.py apply "
            "--installer-dir /var/lib/saw/verified/installer" in apply)
    assert "saw-install.service" in unit_deps(apply)["After"]
    for unit in (install, apply):
        assert "ExecStartPre=/usr/local/sbin/saw-mount-inputs" in unit
        # apply_bom.py always runs from the staged, verified copy, never the
        # live mount (PR #54 review, 2).
        assert "ExecStartPre=/usr/local/sbin/saw-stage-installer" in unit
        assert unit.index("saw-stage-installer") < unit.index("ExecStart=/usr/local/sbin/saw-with-lock")
        assert "StandardOutput=journal+console" in unit      # visible in guest-console-log
        assert "StartLimitBurst=" in unit                     # retries are bounded
        assert "ConditionPathExists=/var/lib/openshell-gateway-setup.done" in unit
    run = cfg["runcmd"][0]
    assert "systemctl start --no-block saw-install.service saw-apply.service" in run
    if shutil.which("systemd-analyze"):
        for name, text in (("saw-install.service", install), ("saw-apply.service", apply)):
            (tmp_path / name).write_text(text)
        result = subprocess.run(["systemd-analyze", "verify", *(str(tmp_path / n) for n in
                                 ("saw-install.service", "saw-apply.service"))],
                                capture_output=True, text=True)
        assert "Unknown" not in result.stderr and "Invalid" not in result.stderr, result.stderr


def unit_deps(text):
    deps = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in ("After", "Before", "WantedBy", "DefaultDependencies"):
            deps.setdefault(key, []).extend(value.split())
    return deps


def golden_image_setup_unit():
    """openshell-gateway-setup.service as the golden image build writes it."""
    build = (ROOT / "image-builder-charts" / "helm" / "openshell-gateway-image" /
             "templates" / "buildconfig.yaml").read_text()
    body = build.split("cat > /build/openshell-gateway-setup.service <<'UNIT'\n", 1)[1].split("UNIT\n", 1)[0]
    return "\n".join(line.strip() for line in body.splitlines())


def ordering_cycle(units):
    """Find a boot ordering cycle the way systemd sees it. A target gets an
    implicit After= on every unit it wants (WantedBy=), unless that unit is
    already ordered after the target or has DefaultDependencies=no; that
    implicit edge is what turns 'After=<unit ordered after the target>' into
    a cycle that makes systemd delete the job at boot."""
    before = {}                                   # a -> {b}: a starts before b

    def edge(a, b):
        before.setdefault(a, set()).add(b)
    for name, deps in units.items():
        for other in deps.get("After", []):
            edge(other, name)
        for other in deps.get("Before", []):
            edge(name, other)
    for name, deps in units.items():
        if deps.get("DefaultDependencies", ["yes"])[-1] == "no":
            continue
        for target in deps.get("WantedBy", []):
            if target not in deps.get("After", []):
                edge(name, target)

    def visit(node, path):
        if node in path:
            return path[path.index(node):] + [node]
        for nxt in sorted(before.get(node, ())):
            found = visit(nxt, path + [node])
            if found:
                return found
        return None
    for start in sorted(before):
        found = visit(start, [])
        if found:
            return found
    return None


def test_ordering_cycle_detector_catches_the_live_boot_failure():
    """The units as first shipped: systemd deleted saw-install at boot."""
    units = {
        "openshell-gateway-setup.service": unit_deps(golden_image_setup_unit()),
        "saw-install.service": unit_deps("After=network-online.target openshell-gateway-setup.service\n"
                                         "WantedBy=multi-user.target"),
    }
    assert ordering_cycle(units)


def test_installer_units_have_no_boot_ordering_cycle(default_docs):
    """Live bug: saw-install was After= the golden image's setup unit, which
    is After=multi-user.target, while WantedBy=multi-user.target made the
    target wait for saw-install. systemd broke the cycle by deleting the
    saw-install and saw-apply jobs, so nothing ran after a reboot."""
    cfg = cloud_config(default_docs)
    units = {
        "openshell-gateway-setup.service": unit_deps(golden_image_setup_unit()),
        "saw-install.service": unit_deps(written(cfg, "/etc/systemd/system/saw-install.service")),
        "saw-apply.service": unit_deps(written(cfg, "/etc/systemd/system/saw-apply.service")),
    }
    assert units["openshell-gateway-setup.service"]["After"] == ["multi-user.target"]
    assert ordering_cycle(units) is None
    # Still runs after the golden image's first-boot setup, install before apply.
    assert "openshell-gateway-setup.service" in units["saw-install.service"]["After"]
    assert "saw-install.service" in units["saw-apply.service"]["After"]


def test_readiness_probe_is_opt_in(default_docs):
    assert "readinessProbe" not in default_docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]
    docs = render("--set", "vm.readinessProbe=true")
    probe = docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]["readinessProbe"]
    assert probe["exec"]["command"] == ["test", "-f", "/var/lib/saw/ready"]


def test_bom_change_changes_vm_template(default_docs):
    before = default_docs[("VirtualMachine", "saw-test")]["spec"]["template"]["metadata"]["annotations"]
    docs = render("--set", "bom.metadata.name=openshell-next")
    after = docs[("VirtualMachine", "saw-test")]["spec"]["template"]["metadata"]["annotations"]
    assert before["openshell.pattern/installer-checksum"] != after["openshell.pattern/installer-checksum"]


# -- gateway configuration -------------------------------------------------------

def gateway_files(docs):
    cfg = cloud_config(docs)
    env = written(cfg, "/etc/openshell/gateway.env")
    toml = tomllib.loads(written(cfg, "/etc/openshell/gateway.toml"))
    return env, toml


def test_gateway_uses_mtls_and_bom_supervisor(default_docs):
    env, toml = gateway_files(default_docs)
    assert "OPENSHELL_ENABLE_MTLS_AUTH=true" in env
    assert "OPENSHELL_GATEWAY_CONFIG=/home/cloud-user/.config/openshell/gateway.toml" in env
    assert "OPENSHELL_CONFIG_FILE" not in env      # not read by OpenShell 0.1.x
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert toml["openshell"]["drivers"]["podman"]["supervisor_image"] == \
        values["bom"]["spec"]["openshell"]["supervisor"]["image"]
    assert "oidc" not in toml["openshell"].get("gateway", {})   # no issuer configured


def test_gateway_config_is_schema_v2_for_openshell_01(default_docs):
    """OpenShell 0.1.x rejects a gateway.toml without version 2 and wants the
    compute driver and the sandbox runtime image named."""
    env, toml = gateway_files(default_docs)
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert toml["openshell"]["version"] == 2
    assert toml["openshell"]["gateway"]["compute_driver"] == "podman"
    assert toml["openshell"]["drivers"]["podman"]["sandbox_runtime_image"] == \
        values["bom"]["spec"]["openshell"]["sandbox"]["image"]
    assert "OPENSHELL_COMPUTE_DRIVER=podman" in env
    assert "OPENSHELL_DRIVERS" not in env


def test_gateway_oidc_for_users_with_roles():
    docs = render("--set", "oidc.issuerUrl=https://kc.example.com/realms/openshell")
    env, toml = gateway_files(docs)
    oidc = toml["openshell"]["gateway"]["oidc"]
    assert oidc == {"issuer": "https://kc.example.com/realms/openshell", "audience": "openshell-cli",
                    "roles_claim": "realm_access.roles", "admin_role": "openshell-admin",
                    "user_role": "openshell-user"}
    assert toml["openshell"]["gateway"]["auth"]["allow_unauthenticated_users"] is False
    assert "OPENSHELL_ENABLE_MTLS_AUTH=true" in env      # installer still uses mTLS


def test_governance_can_be_disabled():
    _, toml = gateway_files(render("--set", "governance.enabled=false"))
    assert "interceptors" not in toml["openshell"].get("gateway", {})


def test_governance_endpoint_is_the_shared_namespace(default_docs):
    # The SAW runs in saw-alice; the interceptor stays in openshell-agents.
    _, toml = gateway_files(default_docs)
    [interceptor] = toml["openshell"]["gateway"]["interceptors"]
    assert interceptor["grpc_endpoint"] == \
        "http://governance-interceptor.openshell-agents.svc.cluster.local:18081"
    _, toml = gateway_files(render("--set", "governance.namespace=gov"))
    assert toml["openshell"]["gateway"]["interceptors"][0]["grpc_endpoint"] == \
        "http://governance-interceptor.gov.svc.cluster.local:18081"


def test_cluster_domain_fills_routes_issuer_and_dashboard():
    docs = render("--set", "global.clusterDomain=example.com")
    config = json.loads(installer_data(docs)["config.json"])
    # Keycloak lives in its own namespace (default "saw-keycloak").
    assert config["oidcIssuer"] == \
        "https://openshell-keycloak-ingress-saw-keycloak.apps.example.com/realms/openshell"
    assert config["dashboard"]["redirectUrl"] == \
        "https://saw-test-webui-saw-alice.apps.example.com/oauth2/callback"
    assert config["sandboxDashboardRoute"] == "saw-test-dashboard-saw-alice.apps.example.com"
    # The installer turns routeHost into the gateway certificate SAN drop-in.
    assert config["routeHost"] == "saw-test-gateway-saw-alice.apps.example.com"
    assert "OPENSHELL_ROUTE_FQDN=saw-test-gateway-saw-alice.apps.example.com" in \
        installer_data(docs)["gateway.env"]


# -- installer ConfigMap -----------------------------------------------------

def test_installer_configmap_ships_the_real_files(default_docs, ab):
    data = installer_data(default_docs)
    assert data["apply_bom.py"] == (CHART / "files" / "installer" / "apply_bom.py").read_text()
    assert data["setup-dashboard.sh"] == (CHART / "files" / "installer" / "setup-dashboard.sh").read_text()
    bom = yaml.safe_load(data["installer-bom.yaml"])
    assert ab.validate_bom(bom)
    config = json.loads(data["config.json"])
    assert config["vmName"] == "saw-test" and config["mtlsGateway"] == "saw-installer"
    assert config["runtimeUser"] == "cloud-user" and config["secrets"] == ["inference", "web-search"]


def test_owner_subject_is_passed_to_installer():
    docs = render("--set", "accessControl.ownerSubject=3f2c-subject")
    assert json.loads(installer_data(docs)["config.json"])["ownerSubject"] == "3f2c-subject"


def test_pattern_override_renders_with_nemoclaw(ab):
    docs = render(*PATTERN_SAW_SETTINGS)
    bom = yaml.safe_load(installer_data(docs)["installer-bom.yaml"])
    assert bom["spec"]["nemoclaw"]["cliImage"].startswith("quay.io/rh-ai-quickstart/nemoclaw-cli")
    assert ab.validate_bom(bom)["spec"]["openshell"]["gateway"]


# -- render-time guards ---------------------------------------------------------

def test_tag_pinned_bom_fails_at_render():
    err = render_error("--set", "bom.spec.openshell.gateway.image=quay.io/x/gateway:v1")
    assert "must be pinned by digest" in err


def test_docker_runtime_is_rejected():
    assert "podman only" in render_error("--set", "containerRuntime=docker")


def test_long_sandbox_name_is_rejected():
    assert "19-character" in render_error("--set", "sandboxName=a-very-long-sandbox-name")


def test_invalid_secret_name_is_rejected():
    assert "invalid secret name" in render_error("--set", "inference.secretName=Bad_Name")


# -- saw-bom chart and cross-chart contract -------------------------------------

def render_bom_chart():
    result = helm_template(BOM_CHART)
    assert result.returncode == 0, result.stderr
    [cm] = [d for d in yaml.safe_load_all(result.stdout) if d]
    return cm


def test_saw_bom_chart_ships_profiles_only():
    cm = render_bom_chart()
    assert cm["metadata"]["name"] == "saw-bom-profiles"
    assert "apply_bom.py" not in cm["data"]
    assert all(re.fullmatch(r"profiles__[^_]+(?:-[^_]+)*__[a-z0-9-]+__(workspace|providers|sandbox)\.yaml", k)
               for k in cm["data"]), list(cm["data"])


def test_rendered_inputs_validate_in_the_shipped_installer(tmp_path, default_docs):
    """Lay out /run/saw exactly as saw-mount-inputs would from the two charts,
    then run the installer that the chart ships: `validate` must pass."""
    docs = render(*PATTERN_SAW_SETTINGS)
    run_saw = tmp_path / "run-saw"
    for key, value in installer_data(docs).items():
        (run_saw / "installer").mkdir(parents=True, exist_ok=True)
        (run_saw / "installer" / key).write_text(value)
    for key, value in render_bom_chart()["data"].items():
        (run_saw / "profiles").mkdir(exist_ok=True)
        (run_saw / "profiles" / key).write_text(value)
    for secret, data in {"inference": {"api_key": "k1", "provider": "build"},
                         "web-search": {"api_key": "k2"}}.items():
        (run_saw / "secrets" / secret).mkdir(parents=True)
        for key, value in data.items():
            (run_saw / "secrets" / secret / key).write_text(value)
    result = subprocess.run([sys.executable, str(run_saw / "installer" / "apply_bom.py"),
                             "validate", "--inputs", str(run_saw)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "inputs are valid" in result.stdout
    assert "2 workspace(s) ['cuda-dev', 'default']" in result.stdout
    assert "3 credential(s)" in result.stdout


# -- per-SAW namespaces ----------------------------------------------------------

def all_docs(*args, namespace="saw-alice"):
    result = helm_template(CHART, "--set", "sandboxName=saw-test", *args, namespace=namespace)
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def test_saw_namespace_can_bootstrap_the_shared_golden_image():
    docs = all_docs()
    role = next(d for d in docs if d["kind"] == "Role" and d["metadata"]["name"].endswith("golden-image"))
    binding = next(d for d in docs if d["kind"] == "RoleBinding" and d["metadata"]["name"].endswith("golden-image"))
    assert role["metadata"]["namespace"] == "openshell-agents"
    assert binding["metadata"]["namespace"] == "openshell-agents"
    # KubeVirt clones the root disk as the namespace's default SA; CDI needs
    # create on datavolumes/source in the source namespace for it.
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "default", "namespace": "saw-alice"},
        {"kind": "ServiceAccount", "name": "saw-test-prepare", "namespace": "saw-alice"}]
    assert {"apiGroups": ["cdi.kubevirt.io"], "resources": ["datavolumes/source"],
            "verbs": ["create"]} in role["rules"]
    vm = next(d for d in docs if d["kind"] == "VirtualMachine")
    assert vm["spec"]["dataVolumeTemplates"][0]["spec"]["sourceRef"]["namespace"] == "openshell-agents"


def test_no_cross_namespace_role_when_sharing_the_golden_namespace():
    docs = all_docs(namespace="openshell-agents")
    assert not [d for d in docs if d["metadata"]["name"].endswith("golden-image")]
    docs = all_docs("--set", "source.registryURL=docker://quay.io/x/disk:1")
    assert not [d for d in docs if d["metadata"]["name"].endswith("golden-image")]


def test_keycloak_admin_access_is_granted_in_the_keycloak_namespace():
    docs = all_docs()
    kc = [d for d in docs if "keycloak-admin-read" in d["metadata"]["name"]]
    assert {d["metadata"]["namespace"] for d in kc} == {"saw-keycloak"}
    assert all(d["metadata"]["name"] == "saw-test-saw-alice-keycloak-admin-read" for d in kc)
    docs = all_docs("--set", "oidc.keycloakNamespace=sso")
    assert {d["metadata"]["namespace"] for d in docs if "keycloak-admin-read" in d["metadata"]["name"]} == {"sso"}
    prepare = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "saw-test-prepare-scripts")
    assert 'KEYCLOAK_NS="sso"' in prepare["data"]["prepare.sh"]


def test_cluster_scoped_names_include_the_namespace():
    """Two SAWs with the same name in different namespaces must not collide."""
    names_a = {(d["kind"], d["metadata"]["name"]) for d in all_docs(namespace="saw-a")
               if d["kind"].startswith("Cluster")}
    names_b = {(d["kind"], d["metadata"]["name"]) for d in all_docs(namespace="saw-b")
               if d["kind"].startswith("Cluster")}
    assert names_a and not names_a & names_b


GOV_CHART = ROOT / "charts" / "governance-interceptor"


def test_governance_interceptor_admits_labelled_saw_namespaces():
    result = subprocess.run([HELM, "template", "gov", str(GOV_CHART), "--namespace", "openshell-agents"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    policy = next(d for d in yaml.safe_load_all(result.stdout) if d and d["kind"] == "NetworkPolicy")
    sources = policy["spec"]["ingress"][0]["from"]
    assert {"podSelector": {"matchLabels": {"kubevirt.io": "virt-launcher"}}} in sources
    assert {"namespaceSelector": {"matchLabels": {"openshell.pattern/saw": "true"}},
            "podSelector": {"matchLabels": {"kubevirt.io": "virt-launcher"}}} in sources


def test_pattern_puts_keycloak_and_each_saw_in_their_own_namespaces():
    values = yaml.safe_load((ROOT / "values-prod.yaml").read_text())["clusterGroup"]
    namespaces, apps, subs = values["namespaces"], values["applications"], values["subscriptions"]
    assert "keycloak" not in namespaces   # left to a platform Keycloak, if any
    assert namespaces["saw-keycloak"]["targetNamespaces"] == ["saw-keycloak"]
    assert subs["rhbk"]["namespace"] == "saw-keycloak"
    assert apps["openshell-keycloak"]["namespace"] == "saw-keycloak"
    saw = yaml.safe_load((ROOT / "charts/openshell-saw/values.yaml").read_text())
    assert saw["oidc"]["keycloakNamespace"] == "saw-keycloak"
    # Per-user namespaces and apps come from the saw-users chart, not this file.
    assert "saw-alice" not in namespaces
    for gone in ("openshell-saw", "saw-bom", "pattern-secrets"):
        assert gone not in apps, gone
    users_app = apps["saw-users"]
    assert users_app["namespace"] == "openshell-agents"
    assert users_app["path"] == "charts/saw-users"
    assert users_app["extraValueFiles"] == ["/overrides/saw-users.yaml"]
    assert users_app["syncPolicy"]["automated"]["prune"] is True
    listed = yaml.safe_load((ROOT / "overrides/saw-users.yaml").read_text())["users"]
    assert [user["name"] for user in listed] == ["alice"]
    for app in ("governance-interceptor", "governance-policy"):
        assert apps[app]["namespace"] == "openshell-agents", app


def test_vm_logs_its_serial_console(default_docs):
    """The installer logs to the console; make it visible in the pod even when
    the cluster default leaves serial console logging off."""
    devices = default_docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]["domain"]["devices"]
    assert devices["logSerialConsole"] is True


# -- dynamic SSH key provisioning (KubeVirt accessCredentials) -----------------

def access_credentials(docs):
    return docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"].get("accessCredentials")


AGENT_CREDS = {"propagationMethod": {"qemuGuestAgent": {"users": ["cloud-user"]}}}


def test_empty_ssh_key_secret_by_default(default_docs):
    """No key at deploy time: `make openshell-saw-vm-ssh` adds one on demand.
    The chart must not own `data`, or upgrades would wipe keys added later."""
    secret = default_docs[("Secret", "saw-test-ssh-pubkey")]
    assert "data" not in secret and "stringData" not in secret
    assert access_credentials(default_docs) == [{"sshPublicKey": {
        "source": {"secret": {"secretName": "saw-test-ssh-pubkey"}}, **AGENT_CREDS}}]
    # cloud-init must not write keys: the guest agent owns authorized_keys.
    assert "ssh_authorized_keys" not in yaml.safe_dump(cloud_config(default_docs))
    assert "setsebool -P virt_qemu_ga_manage_ssh on" in cloud_config(default_docs)["runcmd"][0]


def test_ssh_key_value_seeds_the_secret():
    docs = render("--set", "sshPublicKey=ssh-ed25519 AAAAtest operator")
    assert docs[("Secret", "saw-test-ssh-pubkey")]["stringData"] == {"key1": "ssh-ed25519 AAAAtest operator"}


def test_existing_ssh_key_secret_takes_precedence():
    docs = render("--set", "sshPublicKeySecret=openshell-ssh-pubkey",
                  "--set", "sshPublicKey=ssh-ed25519 AAAAignored")
    assert access_credentials(docs)[0]["sshPublicKey"]["source"]["secret"]["secretName"] == "openshell-ssh-pubkey"
    assert ("Secret", "saw-test-ssh-pubkey") not in docs


def test_pattern_uses_the_on_demand_ssh_key_secret():
    docs = render(*PATTERN_SAW_SETTINGS)
    assert access_credentials(docs)[0]["sshPublicKey"]["source"]["secret"]["secretName"] == "saw-test-ssh-pubkey"
    assert "data" not in docs[("Secret", "saw-test-ssh-pubkey")]


# -- provider profiles (governance-policy and the installer's copies) ---------

GOVERNANCE_PROFILES = ROOT / "charts" / "governance-policy" / "profiles"
SAW_PROFILES = CHART / "files" / "provider-profiles"


def test_governance_profiles_carry_their_id():
    """OpenShell's profile parser requires `id` (missing field `id` otherwise),
    so the files are only importable with it. The interceptor derives the id
    from the filename and overwrites the field, so it must match."""
    for path in sorted(GOVERNANCE_PROFILES.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        assert doc.get("id") == path.stem, path.name
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", doc["id"]), path.name


def test_every_profile_names_its_binaries():
    """OpenShell 0.1.x: a profile whose endpoints list no binaries allows
    nothing, and removed fields (provider_type) must not linger."""
    for path in sorted(GOVERNANCE_PROFILES.glob("*.yaml")) + sorted(SAW_PROFILES.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        assert "provider_type" not in doc, path.name
        if doc.get("endpoints"):
            assert doc.get("binaries"), path.name


def test_installer_profile_copies_match_governance_policy():
    copies = sorted(SAW_PROFILES.glob("*.yaml"))
    assert [p.name for p in copies] == ["brave.yaml", "nvidia.yaml", "openai.yaml"]
    for path in copies:
        assert path.read_text() == (GOVERNANCE_PROFILES / path.name).read_text(), path.name


def test_installer_disk_ships_provider_profiles(default_docs, ab, tmp_path):
    data = installer_data(default_docs)
    assert data["provider-profile-brave.yaml"] == (SAW_PROFILES / "brave.yaml").read_text()
    for key, value in data.items():
        (tmp_path / key).write_text(value)
    assert set(ab.provider_profiles(tmp_path)) == {"brave", "nvidia", "openai"}


def test_prepare_job_reads_the_admin_secret_of_the_keycloak_in_use():
    """Found live with an existing Keycloak CR named `keycloak`: the Job
    looked for openshell-keycloak-initial-admin and could not register the
    dashboard redirect. openshell-saw-create.sh passes the CR it finds."""
    docs = render("--set", "oidc.issuerUrl=https://sso.example.com/realms/openshell",
                  "--set", "oidc.keycloakName=keycloak", "--set", "oidc.realm=openshell")
    role = next(d for (kind, name), d in docs.items() if kind == "Role" and d["metadata"].get("namespace") == "saw-keycloak")
    assert role["rules"][0]["resourceNames"] == ["keycloak-initial-admin"]
    scripts = next(d for (kind, name), d in docs.items() if kind == "ConfigMap" and name.endswith("-prepare-scripts"))
    assert 'OIDC_KEYCLOAK_NAME="keycloak"' in scripts["data"]["prepare.sh"]


def test_create_script_passes_the_keycloak_it_finds():
    text = (ROOT / "scripts" / "openshell-saw-create.sh").read_text()
    assert "--set oidc.keycloakName=${KC_NAME}" in text and "--set oidc.realm=${KEYCLOAK_REALM}" in text


def test_secret_template_matches_the_default_profile():
    """The pattern's values-secret template must give the default profile's
    providers keys of the right type, or the installer refuses them."""
    template = yaml.safe_load((ROOT / "values-secret.yaml.template").read_text())
    secrets = {s["name"]: {f["name"]: f for f in s["fields"]} for s in template["secrets"]}
    providers = []
    for f in (ROOT / "charts/saw-bom/profiles/data-science").glob("*/providers.yaml"):
        providers += yaml.safe_load(f.read_text())["spec"]["providers"]
    for p in providers:
        fields = secrets[p["credentialSecret"]]
        assert p["credentialSecretKey"] in fields, p["name"]
        configured = fields.get("provider", {}).get("value")
        assert configured in (p["type"], p.get("nemoclawProvider")), (p["name"], configured)


def test_custom_inference_profile_validates_in_the_shipped_installer(tmp_path):
    """saw-bom `profiles: [custom-inference]` with an `inference` Secret for a
    custom OpenAI-compatible endpoint (provider/model/url/api_key)."""
    values = tmp_path / "saw-bom.yaml"
    values.write_text("profiles: [custom-inference]\n")
    result = helm_template(BOM_CHART, "-f", str(values))
    assert result.returncode == 0, result.stderr
    [cm] = [d for d in yaml.safe_load_all(result.stdout) if d]
    assert all("__custom-inference__" in k for k in cm["data"])
    docs = render(*PATTERN_SAW_SETTINGS)
    run_saw = tmp_path / "run-saw"
    for key, value in installer_data(docs).items():
        (run_saw / "installer").mkdir(parents=True, exist_ok=True)
        (run_saw / "installer" / key).write_text(value)
    for key, value in cm["data"].items():
        (run_saw / "profiles").mkdir(exist_ok=True)
        (run_saw / "profiles" / key).write_text(value)
    for secret, data in {"inference": {"api_key": "k1", "provider": "openai", "model": "m",
                                       "url": "https://vllm.models.svc:8443/v1"},
                         "web-search": {"api_key": "k2"}}.items():
        (run_saw / "secrets" / secret).mkdir(parents=True)
        for key, value in data.items():
            (run_saw / "secrets" / secret / key).write_text(value)
    result = subprocess.run([sys.executable, str(run_saw / "installer" / "apply_bom.py"),
                             "validate", "--inputs", str(run_saw)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 workspace(s) ['default']" in result.stdout


def test_inference_secret_carries_an_optional_url():
    """The ExternalSecret reads every key of the Vault entry; `url` is
    optional so cloud-provider entries without it keep working."""
    result = helm_template(ROOT / "charts" / "pattern-secrets")
    assert result.returncode == 0, result.stderr
    es = next(d for d in yaml.safe_load_all(result.stdout) if d and d["metadata"]["name"] == "inference")
    assert es["spec"]["dataFrom"] == [{"extract": {"key": "secret/data/hub/inference"}}]
    assert "data" not in es["spec"]
    tmpl = es["spec"]["target"]["template"]["data"]
    assert set(tmpl) == {"provider", "model", "api_key", "url"}
    assert tmpl["url"] == '{{ index . "url" | default "" }}'


def test_cleanup_hook_can_be_turned_off():
    """helm uninstall (and deleting the Argo CD app) deletes the VM through a
    pre-delete hook unless cleanupOnDelete is false."""
    hooks = lambda docs: [k for k, d in docs.items()
                          if d["metadata"].get("annotations", {}).get("helm.sh/hook") == "pre-delete"]
    assert ("Pod", "saw-test-cleanup") in hooks(render())
    assert hooks(render("--set", "cleanupOnDelete=false")) == []


def test_live_inputs_use_virtiofs_and_drop_the_installer_checksum():
    docs = render("--set", "vm.liveInputs=true")
    spec = docs[("VirtualMachine", "saw-test")]["spec"]["template"]["spec"]
    disks = {d["name"] for d in spec["domain"]["devices"]["disks"]}
    filesystems = {f["name"] for f in spec["domain"]["devices"]["filesystems"]}
    assert disks == {"rootdisk", "cloudinitdisk"}
    assert filesystems == {"saw-installer", "saw-profiles", "saw-sec-0", "saw-sec-1"}
    assert all(item["virtiofs"] == {} for item in spec["domain"]["devices"]["filesystems"])
    annotations = docs[("VirtualMachine", "saw-test")]["spec"]["template"]["metadata"]["annotations"]
    assert "openshell.pattern/installer-checksum" not in annotations
    assert "openshell.pattern/cloudinit-checksum" in annotations
    cfg = cloud_config(docs)
    assert "systemctl enable --now saw-inputs.path saw-inputs.timer" in cfg["runcmd"][0]


def test_signing_mode_defaults_to_warn(default_docs):
    config = json.loads(installer_data(default_docs)["config.json"])
    assert config["signing"]["mode"] == "warn"
    assert config["prune"]["mode"] == "report"
    assert config["prune"]["sandboxes"] is False
    assert "bundle.sigstore.json" not in installer_data(default_docs)
    unit = written(cloud_config(default_docs), "/etc/systemd/system/saw-install.service")
    # saw-stage-installer runs verify-bundle when the golden image has it
    # (PR #54 review, 2); apply_bom.py always runs from the staged copy.
    assert "saw-stage-installer" in unit
    assert unit.index("saw-stage-installer") < unit.index("apply_bom.py install")


def test_enforce_without_trust_material_fails_at_render():
    err = render_error("--set", "signing.mode=enforce")
    assert "signing.mode enforce requires" in err


# -- sandbox web UI routes (sandboxUi, from the SAW-BOM ui.route flag) ---------

def _with_ui(tmp_path, entries, *args):
    values = tmp_path / "ui.yaml"
    values.write_text(yaml.safe_dump({"global": {"clusterDomain": "example.com"},
                                      "accessControl": {"owner": "alice"}, "sandboxUi": entries}))
    return render("-f", str(values), *args)


UI = [{"workspace": "default", "sandbox": "notebook", "proxyPort": 4201, "forwardPort": 14201}]


def test_a_sandbox_ui_gets_a_route_a_service_port_and_a_vm_port(tmp_path):
    docs = _with_ui(tmp_path, UI)
    route = docs[("Route", "saw-test-default-notebook-ui")]
    assert route["spec"]["host"] == "saw-test-default-notebook-ui.apps.example.com"
    assert route["spec"]["port"]["targetPort"] == "ui-4201"
    assert route["spec"]["tls"]["termination"] == "edge"
    service = docs[("Service", "saw-test-gateway")]
    assert {"name": "ui-4201", "port": 4201, "targetPort": 4201, "protocol": "TCP"} in service["spec"]["ports"]
    vm = docs[("VirtualMachine", "saw-test")]
    ports = vm["spec"]["template"]["spec"]["domain"]["devices"]["interfaces"][0]["ports"]
    assert {"name": "ui-4201", "port": 4201, "protocol": "TCP"} in ports


def test_the_installer_gets_the_route_and_the_owner(tmp_path):
    cfg = json.loads(_with_ui(tmp_path, UI)[("ConfigMap", "saw-test-installer")]["data"]["config.json"])
    assert cfg["sandboxUi"] == [{"workspace": "default", "sandbox": "notebook",
                                 "name": "saw-test-default-notebook-ui",
                                 "host": "saw-test-default-notebook-ui.apps.example.com",
                                 "proxyPort": 4201, "forwardPort": 14201, "portName": "ui-4201"}]
    assert cfg["sandboxUiProxy"]["allowedUsers"] == ["alice"]
    # OpenClaw trusts the owner-only proxy: no gateway token in the UI.
    assert cfg["sandboxUiProxy"]["trustedProxy"] == {
        "enabled": True, "cidrs": ["127.0.0.1/32", "::1/128"], "deviceAutoApprove": True}


def test_trusted_proxy_can_be_turned_off(tmp_path):
    off = tmp_path / "off.yaml"
    off.write_text(yaml.safe_dump({"sandboxUiProxy": {"trustedProxy": {"enabled": False}}}))
    cfg = json.loads(_with_ui(tmp_path, UI, "-f", str(off))[("ConfigMap", "saw-test-installer")]
                     ["data"]["config.json"])
    assert cfg["sandboxUiProxy"]["trustedProxy"]["enabled"] is False


def test_the_prepare_job_registers_the_route_callback(tmp_path):
    docs = _with_ui(tmp_path, UI)
    prepare = docs[("ConfigMap", "saw-test-prepare-scripts")]["data"]["prepare.sh"]
    assert 'UI_ROUTE_HOSTS="saw-test-default-notebook-ui.apps.example.com "' in prepare
    # A Job cannot change: it is a Sync hook, recreated on every sync.
    job = docs[("Job", "saw-test-prepare")]
    assert job["metadata"]["annotations"] == {"argocd.argoproj.io/hook": "Sync",
                                              "argocd.argoproj.io/hook-delete-policy": "BeforeHookCreation"}


def test_no_sandbox_ui_changes_nothing(tmp_path):
    docs = render()
    assert not [k for k in docs if k[0] == "Route" and k[1].endswith("-ui")]
    assert not [p for p in docs[("Service", "saw-test-gateway")]["spec"]["ports"] if p["name"].startswith("ui-")]


@pytest.mark.parametrize("entry, message", [
    ({"workspace": "Default", "sandbox": "notebook", "proxyPort": 4201, "forwardPort": 14201}, "DNS labels"),
    ({"workspace": "default", "sandbox": "notebook"}, "needs proxyPort and forwardPort"),
])
def test_bad_sandbox_ui_entries_fail_the_render(tmp_path, entry, message):
    values = tmp_path / "ui.yaml"
    values.write_text(yaml.safe_dump({"sandboxUi": [entry]}))
    result = helm_template(CHART, "--set", "sandboxName=saw-test", "-f", str(values))
    assert result.returncode != 0 and message in result.stderr
