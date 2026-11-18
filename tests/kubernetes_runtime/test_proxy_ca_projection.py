"""Public trust projection: no Secret reads, adoption, replacement or rotation."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('project_ca',ROOT/'charts/saw-kubernetes-proxy/files/project_ca.py')
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


@pytest.fixture(scope='module')
def cert(tmp_path_factory):
    root=tmp_path_factory.mktemp('proxy-ca-test')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=Public test CA','-keyout',str(root/'key.pem'),'-out',str(root/'ca.pem')],
        check=True,capture_output=True)
    value=(root/'ca.pem').read_text()
    (root/'key.pem').unlink()
    return value


@pytest.fixture
def config():
    return dict(ownerID='67a9891d-e281-442f-86c3-41771f5ce049',namespace='saw-test-trusted',
                targetNamespace='saw-test',name='saw-test-proxy-ca')


class Api:
    def __init__(self,config,cert):
        self.objects={f'/api/v1/namespaces/{ns}':{'metadata':{'name':ns,'labels':{mod.OWNER:config['ownerID']}}}
            for ns in [config['namespace'],config['targetNamespace']]}
        self.source=f"/api/v1/namespaces/{config['namespace']}/configmaps/{config['name']}"
        self.target=f"/api/v1/namespaces/{config['targetNamespace']}/configmaps/{config['name']}"
        self.objects[self.source]={'metadata':{'name':config['name'],'namespace':config['namespace']},'data':{'ca.crt':cert}}
        self.calls=[]
        self.race=None

    def call(self,method,path,body=None):
        self.calls.append((method,path))
        assert '/secrets' not in path
        assert method in ['GET','POST']
        if method=='POST':
            target=path+'/'+body['metadata']['name']
            if self.race:
                body=self.race(copy.deepcopy(body))
            self.objects.setdefault(target,copy.deepcopy(body))
        return copy.deepcopy(self.objects.get(path))


def test_repeat_sync_and_only_public_material(config,cert):
    api=Api(config,cert)
    mod.project(api,config)
    before=copy.deepcopy(api.objects)
    mod.project(api,config)
    assert api.objects==before
    assert sum(m=='POST' for m,p in api.calls)==1
    target=api.objects[api.target]
    assert target['immutable'] is True and target['data']=={'ca.crt':cert}
    assert target['metadata']['annotations']['argocd.argoproj.io/sync-options']==mod.KEEP


@pytest.mark.parametrize('mutation',[
    lambda b: b.update(immutable=False),
    lambda b: b.update(data={'ca.crt':'different'}),
    lambda b: b.update(binaryData={'private':'data'}),
    lambda b: b['metadata'].update(ownerReferences=[{'name':'foreign'}]),
    lambda b: b['metadata'].update(deletionTimestamp='now'),
    lambda b: b['metadata'].update(labels={mod.OWNER:'foreign'}),
    lambda b: b['metadata'].update(annotations={}),
    lambda b: b.update(metadata=None),
])
def test_refuses_foreign_changed_or_malformed_target(config,cert,mutation):
    api=Api(config,cert)
    mod.project(api,config)
    mutation(api.objects[api.target])
    before=copy.deepcopy(api.objects)
    with pytest.raises(mod.Failure):mod.project(api,config)
    assert api.objects==before


def test_conflicting_create_race_is_not_adopted(config,cert):
    api=Api(config,cert)
    def race(body):
        body['metadata']['labels'][mod.OWNER]='foreign'
        return body
    api.race=race
    with pytest.raises(mod.Failure,match='explicit trust recovery'):mod.project(api,config)


def test_matching_create_race_is_safe(config,cert):
    api=Api(config,cert)
    api.race=lambda body:body
    mod.project(api,config)


@pytest.mark.parametrize('value',['secret','-----BEGIN PRIVATE KEY-----','not a certificate',None])
def test_invalid_source_rejected_before_any_write(config,cert,value):
    api=Api(config,cert)
    api.objects[api.source]['data']={'ca.crt':value}
    with pytest.raises(mod.Failure):mod.project(api,config)
    assert not any(m=='POST' for m,p in api.calls)


def test_extra_text_cannot_be_projected(config,cert):
    api=Api(config,cert)
    api.objects[api.source]['data']['ca.crt']=cert+'secret trailing text'
    with pytest.raises(mod.Failure):mod.project(api,config)


def test_namespace_ownership_required_before_reading_ca(config,cert):
    api=Api(config,cert)
    api.objects['/api/v1/namespaces/saw-test']['metadata']['labels']={}
    with pytest.raises(mod.Failure,match='ownership'):mod.project(api,config)
    assert all('/configmaps' not in p for m,p in api.calls)


@pytest.mark.parametrize('patch',[{'ownerID':'0'*32},{'targetNamespace':'saw-test-trusted'},
    {'name':'../secrets'},{'targetNamespace':'kube-system'},{'extra':'field'}])
def test_bad_config_never_calls_api(config,cert,patch):
    api=Api(config,cert)
    config.update(patch)
    with pytest.raises(mod.Failure):mod.project(api,config)
    assert not api.calls
