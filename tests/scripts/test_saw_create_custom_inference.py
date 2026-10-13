"""scripts/openshell-saw-create.sh with fake oc/helm: ENDPOINT_URL goes into
the inference Secret's `url`, PROFILES selects the SAW-BOM profiles."""
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "openshell-saw-create.sh"

FAKE_OC = r'''#!/usr/bin/env bash
echo "oc $*" >> "$FAKE_LOG"
case "$1" in
  whoami) echo admin ;;
  # Secrets in the namespace: EXISTING_SECRETS, plus those this run creates.
  get) if [[ "$2" == namespace ]]; then
         [[ -n "${EXISTING_SECRETS:-}" ]] && echo "namespace/$3"
       elif [[ "$2" == network.config ]]; then
         echo '{"status":{"clusterNetwork":[{"cidr":"10.232.0.0/14"}],"serviceNetwork":["172.231.0.0/16"]}}'
       elif [[ "$2" == ingress.config.openshift.io ]]; then
         echo "${TEST_APPS_DOMAIN:-}"
       elif [[ "$2" == service && "$3" == kubernetes ]]; then
         echo '{"spec":{"clusterIP":"172.231.0.1","ports":[{"port":443,"protocol":"TCP"}]}}'
       elif [[ "$2" == endpointslice ]]; then
         echo '{"items":[{"addressType":"IPv4","ports":[{"port":6443,"protocol":"TCP"}],"endpoints":[{"addresses":["10.10.10.10"],"conditions":{"ready":true}}]}]}'
       elif [[ "$2" == secret ]]; then
         [[ " ${EXISTING_SECRETS:-} " == *" $3 "* ]] && echo "secret/$3"
       elif [[ "$2" == keycloak ]]; then
         echo '{"items":[{"metadata":{"name":"openshell-keycloak"}}]}'
       elif [[ "$2" == secrets ]]; then
         if [[ -f "$FAKE_DIR/secrets" ]]; then
           sed 's#^#secret/#' "$FAKE_DIR/secrets"
         fi
         for name in ${EXISTING_SECRETS:-}; do printf 'secret/%s\n' "$name"; done
       fi ;;
  create) echo "kind: Secret # $*"      # --dry-run=client -o yaml
          [[ "$2" == secret ]] && echo "$4" >> "$FAKE_DIR/secrets" ;;
  apply) cat >> "$FAKE_LOG" ;;
esac
exit 0
'''
FAKE_HELM = r'''#!/usr/bin/env bash
echo "helm $*" >> "$FAKE_LOG"
prev=""
for a in "$@"; do
  if [[ "$prev" == "-f" && "$3" == "saw-bom" ]]; then cp "$a" "$FAKE_DIR/bom-values.yaml"; fi
  if [[ "$prev" == "-f" && "$3" == "cinf" ]]; then cp "$a" "$FAKE_DIR/saw-values.yaml"; fi
  prev="$a"
done
exit 0
'''


@pytest.fixture
def run(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("oc", FAKE_OC), ("helm", FAKE_HELM),
                       ("uv", "#!/bin/sh\necho '[]'\n")):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "keycloak-host.sh").write_text(
        '#!/bin/sh\nif [ -n "${LOCAL_KC_HOST:-}" ]; then echo "$LOCAL_KC_HOST"; else exit 1; fi\n')
    (scripts / "keycloak-host.sh").chmod(0o755)
    log = tmp_path / "log"

    def _run(**env):
        full = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_LOG": str(log),
                "FAKE_DIR": str(tmp_path), "OPENSHELL_SAW_NAME": "cinf", "SAW_CHART": "charts/openshell-saw",
                "OWNER": "alice", "OIDC_ISSUER": "none", "SCRIPTS_DIR": str(scripts), **env}
        result = subprocess.run(["bash", str(SCRIPT)], env=full, cwd=ROOT, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        return log.read_text(), tmp_path / "bom-values.yaml"
    return _run


def test_custom_endpoint_and_profile(run):
    log, bom_values = run(PROVIDER="openai", MODEL="m", API_KEY="k",
                          ENDPOINT_URL="https://vllm.models.svc:8443/v1", PROFILES="custom-inference")
    secret = next(line for line in log.splitlines() if line.startswith("oc create secret generic inference"))
    assert "--from-literal=url=https://vllm.models.svc:8443/v1" in secret
    assert "--from-literal=provider=openai" in secret
    assert yaml.safe_load(bom_values.read_text()) == {"profiles": ["custom-inference"]}


def test_several_profiles(run):
    _, bom_values = run(PROVIDER="build", MODEL="m", API_KEY="k", PROFILES="data-science, custom-inference")
    assert yaml.safe_load(bom_values.read_text()) == {"profiles": ["data-science", "custom-inference"]}


def test_defaults_are_unchanged(run):
    log, bom_values = run(PROVIDER="build", MODEL="m", API_KEY="k")
    secret = next(line for line in log.splitlines() if line.startswith("oc create secret generic inference"))
    assert "url=" not in secret
    assert not bom_values.exists()
    bom = next(line for line in log.splitlines() if line.startswith("helm upgrade --install saw-bom"))
    assert " -f " not in bom
    assert "oc get route cinf-dashboard" not in log


def test_values_overlay_and_discovered_topology_are_passed_to_saw_chart(run, tmp_path):
    values = tmp_path / "custom.yaml"
    values.write_text(yaml.safe_dump({"route": {"webui": False}}))
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k", SAW_VALUES_FILE=str(values))
    assert f"-f {values}" in _saw_helm(log)
    assert yaml.safe_load((tmp_path / "saw-values.yaml").read_text()) == {
        "networkPolicy": {"clusterNetworkCIDRs": ["10.232.0.0/14"],
                          "serviceNetworkCIDRs": ["172.231.0.0/16"]},
        "cleanupApi": {"serviceIP": "172.231.0.1",
                       "endpoints": [{"ip": "10.10.10.10", "port": 6443}]}}
    assert log.index("oc get endpointslice") < log.index("oc create")


def test_route_template_overrides_quickstart_auto_hosts(run):
    template = "custom-{app}.apps.example.test"
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k",
                 ROUTE_HOST_TEMPLATE=template, TEST_APPS_DOMAIN="apps.example.test")
    saw = _saw_helm(log)
    assert f"route.hostTemplate={template}" in saw
    assert "route.webuiHost=" not in saw
    assert "route.dashboardHost=" not in saw


def test_route_template_from_values_file_survives_quickstart_auto_hosts(run, tmp_path):
    values = tmp_path / "route.yaml"
    values.write_text(yaml.safe_dump({"route": {"hostTemplate": "tenant-{app}.apps.example.test"}}))
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k",
                 SAW_VALUES_FILE=str(values), TEST_APPS_DOMAIN="apps.example.test")
    saw = _saw_helm(log)
    assert f"-f {values}" in saw
    assert "route.webuiHost=" not in saw
    assert "route.dashboardHost=" not in saw


def test_conflicting_topology_fails_before_cluster_write(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("oc", FAKE_OC), ("helm", FAKE_HELM),
                       ("uv", "#!/bin/sh\necho '[]'\n")):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    values = tmp_path / "conflict.yaml"
    values.write_text(yaml.safe_dump({"networkPolicy": {
        "clusterNetworkCIDRs": ["10.128.0.0/14"]}}))
    log = tmp_path / "log"
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
               FAKE_LOG=str(log), FAKE_DIR=str(tmp_path), OPENSHELL_SAW_NAME="cinf",
               SAW_CHART="charts/openshell-saw", OWNER="alice", OIDC_ISSUER="none",
               PROVIDER="build", MODEL="m", API_KEY="k", SAW_VALUES_FILE=str(values))
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "remove or correct that override" in result.stderr
    assert not any(line.startswith(("oc create", "oc apply", "helm upgrade"))
                   for line in log.read_text().splitlines())


def test_external_issuer_does_not_require_local_keycloak(run):
    issuer = "https://external.example.test/realms/test"
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k", OIDC_ISSUER=issuer)
    assert "oc get keycloak" not in log
    saw = next(line for line in log.splitlines()
               if line.startswith("helm upgrade --install cinf charts/openshell-saw"))
    assert f"oidc.issuerUrl={issuer}" in saw
    assert "dashboard.enabled=false" in saw
    assert "route.webui=false" in saw
    assert "agent=" not in saw and "sandboxImage=" not in saw and "vertexSaJson=" not in saw
    assert "inference.provider=" not in saw and "inference.model=" not in saw
    assert "inference.endpointUrl=" not in saw and "inference.webSearch=" not in saw
    assert "oc get route cinf-dashboard" not in log


def test_keyless_provider_creates_inference_secret(run):
    log, _ = run(PROVIDER="openai", MODEL="local-model", API_KEY="")
    assert "oc create secret generic inference" in log
    assert "--from-literal=provider=openai" in log
    assert "inference.secretName=" not in _saw_helm(log)


def test_profile_rerun_keeps_existing_inference_secret(run):
    log, _ = run(EXISTING_SECRETS="inference", PROFILES="custom-inference",
                 PROVIDER="", MODEL="", API_KEY="")
    assert "oc create secret generic inference" not in log
    assert "inference.secretName=" not in _saw_helm(log)


def test_external_dashboard_opt_in(run):
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k",
                 OIDC_ISSUER="https://external.example.test/realms/test", DASHBOARD="true")
    assert "dashboard.enabled=false" not in _saw_helm(log)
    assert "route.webui=false" not in _saw_helm(log)


def test_explicit_local_issuer_keeps_dashboard(run):
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k",
                 LOCAL_KC_HOST="keycloak.apps.test",
                 OIDC_ISSUER="https://keycloak.apps.test/realms/openshell")
    assert "dashboard.enabled=false" not in _saw_helm(log)
    assert "oidc.keycloakName=openshell-keycloak" in _saw_helm(log)


def test_missing_provider_settings_fail_before_cluster_work(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    uv = bindir / "uv"
    uv.write_text('#!/bin/sh\nexit 0\n')
    uv.chmod(0o755)
    marker = tmp_path / "oc-called"
    oc = bindir / "oc"
    oc.write_text('#!/bin/sh\nprintf called > "$MARKER"\n')
    oc.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", MARKER=str(marker),
               OPENSHELL_SAW_NAME="cinf", SAW_CHART="charts/openshell-saw",
               OWNER="alice", PROVIDER="build", MODEL="", API_KEY="k")
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "PROVIDER and MODEL" in result.stderr


def test_missing_login_token_fails_before_cluster_write(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    uv = bindir / "uv"
    uv.write_text('#!/bin/sh\nexit 0\n')
    uv.chmod(0o755)
    log = tmp_path / "oc.log"
    oc = bindir / "oc"
    oc.write_text('#!/bin/sh\necho "$*" >> "$OC_LOG"\n'
                  'if [ "$1" = whoami ]; then exit 0; fi\n')
    oc.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", OC_LOG=str(log),
               OPENSHELL_SAW_NAME="cinf", SAW_CHART="charts/openshell-saw",
               OWNER="", PROVIDER="build", MODEL="m", API_KEY="k",
               OIDC_TOKEN_DIR=str(tmp_path / "no-token"))
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "Run 'make login'" in result.stderr
    assert all(not line.startswith(("create", "apply", "label"))
               for line in log.read_text().splitlines())


def test_unsupported_web_search_setting_fails_before_cluster_work(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "oc-called"
    oc = bindir / "oc"
    oc.write_text('#!/bin/sh\nprintf called > "$MARKER"\n')
    oc.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", MARKER=str(marker),
               OPENSHELL_SAW_NAME="cinf", SAW_CHART="charts/openshell-saw",
               OWNER="alice", PROVIDER="build", MODEL="m", API_KEY="k",
               WEB_SEARCH="brave")
    result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "WEB_SEARCH is unsupported" in result.stderr
    assert not marker.exists()


def _saw_helm(log):
    return next(line for line in log.splitlines() if line.startswith("helm upgrade --install cinf "))


def test_without_a_web_search_key_the_vm_does_not_wait_for_that_secret(run):
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k")
    helm = _saw_helm(log)
    assert "additionalProviderSecrets=null" in helm
    assert "inference.secretName=" not in helm


def test_a_rerun_keeps_the_existing_web_search_secret(run):
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k",
                 EXISTING_SECRETS="web-search")
    helm = _saw_helm(log)
    assert "inference.secretName=" not in helm
    assert "additionalProviderSecrets=null" not in helm
