import pytest
import yaml

from .profile_fixtures import fixture_inputs
from saw_kubernetes import compile_profile_files, ContractError


def test_custom_bom_uses_bound_model_endpoint_timeout_and_marker():
    files,cfg=fixture_inputs()
    plan=compile_profile_files(files,cfg)
    w,=plan["workspaces"]
    assert w["providers"][0]["credentialRef"]=={"secret":"inference","key":"api_key"}
    spec=w["sandboxes"][0]["spec"]
    assert spec["command"][-1]=="fixture/model"
    assert plan["customInferenceURL"]=='https://models.fixture.test/v1'
    assert plan["customInferenceURL"] in spec["command"][2] and "timeoutSeconds: 300" in spec["command"][2]


@pytest.mark.parametrize(("binding", "error"), [
    ("browser", "matching approved OpenClaw browser binding"),
    ("toolGate", "read-only tool gate"),
])
def test_custom_browser_requires_approved_bindings(binding, error):
    files, cfg = fixture_inputs()
    del cfg["bindings"]["default/notebook"][binding]
    with pytest.raises(ContractError, match=error):
        compile_profile_files(files, cfg)


@pytest.mark.parametrize("bad",["https://other.example/v1","http://models.fixture.test/v1",
    "https://models.fixture.test:8443/v1","https://models.fixture.test/v1?token=private",
    "https://someone@models.fixture.test/v1"])
def test_bom_cannot_override_site_approved_destination(bad):
    files,cfg=fixture_inputs()
    key=next(k for k in files if k.endswith("sandbox.yaml"))
    doc=yaml.safe_load(files[key]);doc["spec"]["sandboxes"][0]["inference"]["baseUrl"]=bad
    files[key]=yaml.safe_dump(doc)
    with pytest.raises((ContractError, ValueError)): compile_profile_files(files,cfg)


def test_custom_inference_requires_site_approval():
    files,cfg=fixture_inputs()
    cfg.pop("customInferenceURL")
    with pytest.raises(ContractError): compile_profile_files(files,cfg)
    files,cfg=fixture_inputs()
    cfg["credentialBindings"]=[]
    with pytest.raises(ContractError): compile_profile_files(files,cfg)
