import pytest
import yaml

from .profile_fixtures import fixture_inputs
from saw_kubernetes import compile_profile_files, ContractError
from saw_kubernetes import provider


def test_custom_bom_uses_bound_model_endpoint_timeout_and_marker():
    files,cfg=fixture_inputs()
    plan=compile_profile_files(files,cfg)
    w,=plan["workspaces"]
    assert w["providers"][0]["credentials"]=={"CUSTOM_INFERENCE_API_KEY":"saw-cred.inference.api_key"}
    spec=w["sandboxes"][0]["spec"]
    assert spec["command"][-1]=="fixture/model"
    assert plan["customInferenceURL"]=='https://models.fixture.test/v1'
    assert plan["customInferenceURL"] in spec["command"][2] and "timeoutSeconds: 300" in spec["command"][2]


@pytest.mark.parametrize("bad",["https://other.example/v1","http://models.fixture.test/v1",
    "https://models.fixture.test:8443/v1","https://models.fixture.test/v1?token=private",
    "https://someone@models.fixture.test/v1"])
def test_bom_cannot_override_site_approved_destination(bad):
    files,cfg=fixture_inputs()
    key=next(k for k in files if k.endswith("sandbox.yaml"))
    doc=yaml.safe_load(files[key]);doc["spec"]["sandboxes"][0]["inference"]["baseUrl"]=bad
    files[key]=yaml.safe_dump(doc)
    with pytest.raises((ContractError, ValueError)): compile_profile_files(files,cfg)


def test_missing_approval_and_widened_proxy_policy_are_rejected():
    files,cfg=fixture_inputs()
    cfg.pop("customInferenceURL")
    with pytest.raises(ContractError): compile_profile_files(files,cfg)
    url="https://models.fixture.test/v1"
    creds={"CUSTOM_INFERENCE_API_KEY":"saw-cred.inference.api_key"}
    policy={"allowHosts":["models.fixture.test"],"profiles":{},"markerPrefix":"saw-cred",
            "bindings":[{"providers":["custom-inference"],"key":"api_key","secret":"inference"}]}
    assert provider.check_policy("custom-inference",creds,policy,url)
    for patch in ({"profiles":{"custom-inference":["elsewhere.example"]}},
                  {"allowHosts":["models.fixture.test","elsewhere.example"]},{"bindings":[]}):
        assert not provider.check_policy("custom-inference",creds,{**policy,**patch},url)


def test_gateway_profile_must_match_the_pinned_destination(tmp_path):
    from saw_kubernetes import Reconciler
    from .test_runtime import FakeGateway
    files,cfg=fixture_inputs()
    plan=compile_profile_files(files,cfg)
    gateway=FakeGateway()
    old=gateway.call
    def call(method, request):
        if method=="GetProviderProfile":
            return {"profile":{"id":"custom-inference","source":"interceptor/governance",
                    "credentials":[{"env_vars":["CUSTOM_INFERENCE_API_KEY"],"name":"api_key"}],
                    "endpoints":[{"host":"foreign.example","port":443,"enforcement":"NETWORK_ENFORCEMENT_MODE_ENFORCE"}]}}
        return old(method,request)
    gateway.call=call
    with pytest.raises(ContractError,match="approved inference boundary"):
        Reconciler(gateway,tmp_path,lambda _:None).reconcile(plan,generation=1)
    assert not gateway.sandboxes and not gateway.providers
