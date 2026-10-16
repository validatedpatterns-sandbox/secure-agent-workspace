import pytest
from quickstart_scripts import QUICKSTART_SCRIPTS, run_quickstart_script
from validatedpatterns_tests.interop import components, subscription


@pytest.mark.parametrize(
    "openshift_dyn_client",
    ["VP_HUBCONFIG"],
    indirect=True,
)
def test_subscription_status_standalone(openshift_dyn_client):
    expected_subs = {
        "openshift-gitops-operator": ["openshift-gitops-operator"],
    }

    subscription.assert_subscription_status(openshift_dyn_client, expected_subs)


@pytest.mark.parametrize(
    "openshift_dyn_client",
    ["VP_HUBCONFIG"],
    indirect=True,
)
def test_site_reachable_hub(openshift_dyn_client):
    components.assert_site_reachable(openshift_dyn_client)


@pytest.mark.parametrize(
    "openshift_dyn_client",
    ["VP_HUBCONFIG"],
    indirect=True,
)
def test_argocd_reachable_standalone(openshift_dyn_client):
    components.assert_argocd_reachable(openshift_dyn_client)


@pytest.mark.parametrize(
    "openshift_dyn_client",
    ["VP_HUBCONFIG"],
    indirect=True,
)
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


@pytest.mark.parametrize("script", list(QUICKSTART_SCRIPTS))
def test_quickstart_script(script):
    run_quickstart_script(script, QUICKSTART_SCRIPTS[script])
