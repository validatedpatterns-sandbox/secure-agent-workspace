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
  get) if [[ "$2" == secrets ]]; then
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
  if [[ "$prev" == "-f" ]]; then cp "$a" "$FAKE_DIR/bom-values.yaml"; fi
  prev="$a"
done
exit 0
'''


@pytest.fixture
def run(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("oc", FAKE_OC), ("helm", FAKE_HELM)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "keycloak-host.sh").write_text("#!/bin/sh\nexit 1\n")
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


def test_missing_provider_settings_fail_before_cluster_work(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
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
    assert "PROVIDER, MODEL, and API_KEY" in result.stderr
    assert not marker.exists()


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
