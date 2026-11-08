import copy
from pathlib import Path
import pytest
from saw_kubernetes.compiler import compile_profile, ContractError

ROOT = Path(__file__).resolve().parents[2]
def test_portal_bom_route_requires_same_sandboxes_browser_binding():
    profile=ROOT/"tests/fixtures/profiles/audited-openclaw"
    cfg={"namespace":"saw-owner","namespaceUID":"ns","ownerID":"76c95ca5-b9bc-4be7-b764-bc028087ae28",
         "ownerSubject":"owner","mode":"container","gatewayVersion":"0.1.2-rhaiv.6",
         "approvedCredentialFreeProviders":[],"proxyBindings":[{"type":"openai", "secret":"inference", "key":"api_key", "refresh":False}],"bindings":{"agent/audited":{
             "workspace":{"claimName":"tenant-data","uid":"claim","readOnly":False},
             "toolGate":{"ownerLogin":"owner", "trusted":{"claimName":"saw-gate-fixture","uid":"gate","readOnly":True},
                         "audit":{"claimName":"saw-audit-fixture","uid":"audit","readOnly":False}},
             "browser":{"origin":"https://owner.example.test","ownerLogin":"owner"}}}}
    plan=compile_profile(profile,cfg)
    assert plan["workspaces"][0]["sandboxes"][0]["name"]=="audited"
    bad=copy.deepcopy(cfg)
    del bad["bindings"]["agent/audited"]["browser"]
    with pytest.raises(ContractError, match="UI route"):
        compile_profile(profile,bad)


def test_receipt_key_validates_public_spki_and_service():
    from contextlib import closing
    from io import BytesIO
    from saw_kubernetes.receipt import receipt_key
    import base64
    key=base64.b64encode(bytes.fromhex("302a300506032b6570032100")+"x".encode()*32)
    class Writer:
        data=key
        def open(self,url,timeout):
            assert url=="https://writer.archive.svc:8443/v1/receipt-key"
            return closing(BytesIO(self.data))
    assert receipt_key("writer","archive",None,opener=Writer()) == key.decode()
    w=Writer()
    w.data=base64.b64encode(bytes(44))
    with pytest.raises(ValueError,match="Ed25519"):
        receipt_key("writer","archive",None,opener=w)
    with pytest.raises(ValueError,match="service"):
        receipt_key("external.invalid/foo","archive",None,opener=w)
