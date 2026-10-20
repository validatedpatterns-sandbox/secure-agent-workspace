"""VP scheduled testing of the harness-enabled ci deployment variant."""

import shutil

import pytest
from script_runner import make_ci_environment, run_script
from validatedpatterns_tests.interop import components, subscription

QUICKSTART_SCRIPTS = (
    "tests/test-oidc-templates.sh",
    "tests/test-egress-firewall.sh",
)


@pytest.mark.parametrize("openshift_dyn_client", ["VP_HUBCONFIG"], indirect=True)
def test_subscription_status_standalone(openshift_dyn_client):
    expected_subs = {
        "openshift-gitops-operator": ["openshift-gitops-operator"],
    }
    subscription.assert_subscription_status(openshift_dyn_client, expected_subs)


@pytest.mark.parametrize("openshift_dyn_client", ["VP_HUBCONFIG"], indirect=True)
def test_site_reachable_hub(openshift_dyn_client):
    components.assert_site_reachable(openshift_dyn_client)


@pytest.mark.parametrize("openshift_dyn_client", ["VP_HUBCONFIG"], indirect=True)
def test_argocd_reachable_standalone(openshift_dyn_client):
    components.assert_argocd_reachable(openshift_dyn_client)


@pytest.mark.parametrize("openshift_dyn_client", ["VP_HUBCONFIG"], indirect=True)
def test_pod_status_standalone(openshift_dyn_client):
    projects = [
        "patterns-operator",
        "vp-gitops",
        "vault",
        "external-secrets",
        "openshell-agents",
        "saw-alice",
    ]
    components.assert_pod_status(openshift_dyn_client, projects, skip_check=[])


@pytest.fixture(scope="module")
def ci_environment(tmp_path_factory):
    directory = tmp_path_factory.mktemp("ci-harness")
    env = make_ci_environment(directory)
    try:
        # The bootstrap has its own readiness deadline and bounded diagnostics.
        run_script("scripts/ci-gateway-login.sh", env,
                   timeout=float(env.get("CI_READINESS_TIMEOUT", "1800")) + 30)
        yield env
    finally:
        # Remove private keys and tokens even when setup or the harness fails.
        shutil.rmtree(directory)


@pytest.mark.parametrize("script", QUICKSTART_SCRIPTS)
def test_quickstart_script(script, ci_environment):
    run_script(script, ci_environment, timeout=900)


def test_harness_e2e(ci_environment):
    run_script("scripts/e2e-harness.sh", ci_environment, timeout=900)
