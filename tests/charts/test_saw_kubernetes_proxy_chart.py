import json
from pathlib import Path
import shutil
import pytest
import yaml
from helm_cache import run_helm

ROOT = Path(__file__).resolve().parents[2]
HELM = shutil.which('helm')
pytestmark = [pytest.mark.ci_external, pytest.mark.skipif(not HELM, reason='Helm required')]


def render(*args, enabled=True):
    return run_helm([HELM, 'template', 'proxy', str(ROOT / 'charts/saw-kubernetes-proxy'),
        '-n', 'saw-test-trusted', '--set', 'enabled=' + str(enabled).lower(),
        '--set', 'gateway=saw-test,targetNamespace=saw-test,ownerID=67a9891d-e281-442f-86c3-41771f5ce049',
        '--set', 'policyConfigMap=approved-policy,credentialSecretNames[0]=inference',
        '--set-string', 'policyDigest=' + 'a'*64,
        '--set-json', 'network.bootstrapEgress=[{"to":[{"ipBlock":{"cidr":"10.0.0.1/32"}}],"ports":[{"port":443}]}]',
        '--set-json', 'network.proxyEgress=[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}],"ports":[{"port":443}]}]',
        *args], capture_output=True, text=True)


def test_isolation_and_retained_public_projection():
    result = render()
    assert result.returncode == 0, result.stderr
    docs = list(yaml.safe_load_all(result.stdout))
    assert not any(d['kind'] == 'Secret' for d in docs)
    deployment = next(d for d in docs if d['kind'] == 'Deployment')
    pod = deployment['spec']['template']['spec']
    assert pod['automountServiceAccountToken'] is False
    assert not any(v.get('projected') for v in pod['volumes'])
    assert pod['containers'][0]['args'] == ['serve']
    job = next(d for d in docs if d['kind'] == 'Job')['spec']['template']['spec']
    assert job['initContainers'][0]['args'] == ['init-ca']
    assert job['automountServiceAccountToken'] is False
    for c in [*job['initContainers'], *job['containers'], *pod['containers']]:
        assert '@sha256:' in c['image']
        assert c['securityContext'] == dict(allowPrivilegeEscalation=False,
            readOnlyRootFilesystem=True, capabilities={'drop': ['ALL']})
    runtime = next(d for d in docs if d['kind'] == 'Role' and d['metadata']['namespace']=='saw-test')
    assert all(r['resources'] == ['configmaps'] and set(r['verbs']) <= {'get','create'} for r in runtime['rules'])
    trusted = next(d for d in docs if d['kind']=='Role' and d['metadata']['namespace']=='saw-test-trusted')
    assert not any('update' in r['verbs'] for r in trusted['rules'] if 'secrets' in r['resources'])
    assert not any(d['kind']=='RoleBinding' and d['subjects'][0]['name']=='saw-test-credential-proxy' for d in docs)
    cm = next(d for d in docs if d['kind']=='ConfigMap')
    assert json.loads(cm['data']['config.json'])['name']=='saw-test-proxy-ca'
    assert cm['data']['project_ca.py'].rstrip()==(ROOT/'charts/saw-kubernetes-proxy/files/project_ca.py').read_text().rstrip()
    np = next(d for d in docs if d['kind']=='NetworkPolicy' and d['metadata']['name']=='saw-test-credential-proxy')
    peers = np['spec']['ingress'][0]['from']
    assert all(set(peer)=={'namespaceSelector','podSelector'} for peer in peers)
    assert peers[1]['podSelector']['matchLabels']=={'openshell.ai/gateway-id':'saw-test','openshell.ai/boundary-role':'supervisor'}
    service = next(d for d in docs if d['kind']=='Service')
    assert [p['port'] for p in service['spec']['ports']]==[3128]


def test_opt_in():
    result=render(enabled=False)
    assert result.returncode==0 and not result.stdout.strip()


@pytest.mark.parametrize('value', ['targetNamespace=saw-test-trusted','gateway=kube-system',
    'ownerID=00000000-0000-0000-0000-000000000000','image=repo:latest','helperImage=repo:latest',
    'policyConfigMap=','policyDigest=','credentialSecretNames[1]=inference'])
def test_fail_closed(value):
    result=render('--set-string',value)
    assert result.returncode != 0 and not result.stdout.strip()
