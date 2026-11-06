import copy
import subprocess
from functools import lru_cache

import pytest
from saw_kubernetes.boundary import BoundaryError, objects
from saw_kubernetes.portal_contract import contract, verify_contract


@lru_cache(maxsize=1)
def public_test_ca():
    return subprocess.check_output(["openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-subj","/CN=saw-test","-keyout","/dev/null"],stderr=subprocess.DEVNULL,text=True)


def resources(reg="0123456789abcdef", owner="12345678-1234-4123-a123-123456789012", address="10.0.0.18"):
    cfg=dict(namespace="runtime",trustedNamespace="saw-ctl-"+reg,ownerID=owner,governanceNamespace="gov",gateway="gw",proxyPolicy="proxy")
    refs=objects(cfg)
    data={p:{"metadata":{"uid":key},"spec":{},"data":{}} for key,(p,_) in refs.items()}
    def obj(k):return data[refs[k][0]]
    obj("proxy")["spec"]={"namespace":cfg["trustedNamespace"],"owner":owner,"image":"locked"}
    obj("gateway")["spec"]={"template":{"metadata":{"annotations":{"checksum/config":"c"*64}}}}
    obj("gatewayService")["spec"]={"type":"ClusterIP","clusterIP":address,"clusterIPs":[address],"ipFamilies":["IPv4"],"ports":[{"port":17670}]}
    pem=public_test_ca()
    obj("publicCA").update(data={"ca.crt":pem},metadata={"labels":{"saw.redhat.com/runtime-owner":owner}})
    data["/api/v1/namespaces/"+cfg["trustedNamespace"]+"/configmaps/gw-proxy-ca"]={"metadata":{},"data":{"ca.crt":pem}}
    return cfg,data,obj


def test_rebind_only_per_registration_identifiers():
    first,old,_=resources()
    second,new,_=resources("fedcba9876543210","87654321-1234-4123-a123-123456789012","10.0.0.99")
    verify_contract(second,new.__getitem__,contract(first,old.__getitem__))


@pytest.mark.parametrize("change",["proxyImage","servicePort","governanceUID","fakeCA","replacementIssuer","extra"])
def test_unreviewed_differences_rejected(change):
    cfg,live,obj=resources()
    expected=copy.deepcopy(contract(cfg,live.__getitem__))
    if change=="proxyImage":obj("proxy")["spec"]["image"]="foreign"
    if change=="servicePort":obj("gatewayService")["spec"]["ports"][0]["port"]=80
    if change=="governanceUID":obj("governance")["metadata"]["uid"]="foreign"
    if change=="fakeCA":obj("publicCA")["data"]["ca.crt"]="-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
    if change=="replacementIssuer":obj("gatewayConfig")["data"]["issuer"]="foreign"
    if change=="extra":expected["newKey"]="injected"
    with pytest.raises(BoundaryError):verify_contract(cfg,live.__getitem__,expected)
