"""Stock gateway integration contracts; no claim of cluster enforcement."""
import json
import shutil
import tomllib
from pathlib import Path

import pytest
import yaml
from helm_cache import run_helm

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / 'charts/openshell-saw-kubernetes'
HELM = shutil.which('helm')
pytestmark = [pytest.mark.ci_external, pytest.mark.skipif(not HELM, reason='Helm required')]
APIS = ['--api-versions', 'agents.x-k8s.io/v1beta1/Sandbox',
        '--api-versions', 'policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy']


def template(*args, apis=True):
    return run_helm([HELM, 'template', 'saw-test', str(CHART), '-n', 'saw-test',
                     '-f', str(ROOT / 'tests/fixtures/saw-kubernetes-values.yaml'),
                     *(APIS if apis else []), *args], capture_output=True, text=True)


def render(*args):
    result = template(*args)
    assert result.returncode == 0, result.stderr
    return {(d['kind'], d['metadata']['name']): d
            for d in yaml.safe_load_all(result.stdout) if d}


def config(docs):
    return tomllib.loads(docs['ConfigMap', 'saw-test-gateway-config']['data']['gateway.toml'])['openshell']


def test_stock_split_topology_and_server_trust():
    docs = render()
    cfg = config(docs)
    assert cfg['version'] == 2
    assert cfg['gateway']['compute_driver'] == 'kubernetes'
    driver = cfg['drivers']['kubernetes']
    assert driver['workspace_mode'] == 'shared'
    assert driver['namespace'] == 'saw-test'
    assert driver['client_tls_secret_name'] == 'gateway-server'
    assert driver['proxy_connect_by_hostname'] is True
    assert driver['sandbox_runtime'] == {'boundary_port': 5500}
    assert driver['resource_admission']['enabled'] is True
    assert driver['resource_admission']['required_labels']['openshell.ai/sandbox-attachable-workspace'] == '${workspace}'
    assert 'supervisor_runtime_class_name' not in driver
    assert 'supervisor_egress_mode' not in driver
    assert 'topology' not in driver
    assert not {kind for kind, _ in docs} & {'VirtualMachine', 'DataVolume', 'Sandbox', 'ClusterPolicy'}


def test_user_oidc_and_trusted_reconciler_auth_fail_closed():
    cfg = config(render())['gateway']
    assert cfg['auth'] == {'allow_unauthenticated_users': False}
    assert cfg['mtls_auth'] == {'enabled': True}
    assert cfg['oidc']['dangerously_allow_insecure_http'] is False
    assert cfg['tls']['client_ca_path'] == '/etc/openshell-tls/client-ca/ca.crt'
    assert cfg['policy_validation_failure_mode'] == 'fail_closed'
    assert cfg['interceptors'][0]['failure_policy'] == 'fail_closed'


def test_gateway_security_mounts_and_persistence():
    docs = render()
    sts = docs['StatefulSet', 'saw-test-gateway']
    spec = sts['spec']['template']['spec']
    assert sts['spec']['replicas'] == 1
    assert 'runtimeClassName' not in spec
    assert spec['securityContext']['runAsNonRoot'] is True
    container = spec['containers'][0]
    assert container['securityContext'] == {'allowPrivilegeEscalation': False,
                                            'readOnlyRootFilesystem': True,
                                            'capabilities': {'drop': ['ALL']}}
    assert container['readinessProbe']['httpGet']['path'] == '/readyz'
    mounts = {m['name']: m for m in container['volumeMounts']}
    assert mounts['config']['subPath'] == 'gateway.toml'
    assert 'checksum/config' in sts['spec']['template']['metadata']['annotations']
    volumes = {v['name']: v for v in spec['volumes']}
    assert volumes['client-ca']['secret']['items'] == [{'key': 'ca.crt', 'path': 'ca.crt'}]
    assert volumes['proxy-ca']['configMap']['name'] == 'saw-proxy-ca'
    names = {v['secret']['secretName'] for v in spec['volumes'] if 'secret' in v}
    assert names == {'gateway-server', 'gateway-client-ca', 'gateway-jwt'}
    assert not any(kind == 'Secret' for kind, _ in docs)
    pvc = docs['PersistentVolumeClaim', 'saw-test-gateway-data']
    assert pvc['metadata']['annotations']['argocd.argoproj.io/sync-options'] == 'Prune=false,Delete=false'
    assert not pvc['metadata'].get('ownerReferences')


def test_existing_claim_is_never_created_or_owned():
    docs = render('--set', 'kubernetes.storage.existingGatewayClaim=retained-gateway')
    assert not any(kind == 'PersistentVolumeClaim' for kind, _ in docs)
    volumes = docs['StatefulSet', 'saw-test-gateway']['spec']['template']['spec']['volumes']
    assert next(v for v in volumes if v['name'] == 'data')['persistentVolumeClaim']['claimName'] == 'retained-gateway'


def test_rbac_cannot_read_provider_secrets_or_control_other_namespaces():
    docs = render()
    role = docs['Role', 'saw-test-gateway']
    secret_reads = [r for r in role['rules'] if 'secrets' in r['resources'] and 'get' in r['verbs']]
    assert secret_reads == [{'apiGroups': [''], 'resources': ['secrets'],
                             'resourceNames': ['gateway-server'], 'verbs': ['get']}]
    assert not any('pods/exec' in r['resources'] or '*' in r['verbs'] for r in role['rules'])
    cluster = docs['ClusterRole', 'saw-test-saw-test-gateway']
    assert not any(set(r['resources']) & {'secrets', 'pods', 'sandboxes', 'networkpolicies'} for r in cluster['rules'])
    assert all(r.get('resourceNames') == ['saw-test'] for r in cluster['rules'] if 'namespaces' in r['resources'])
    assert docs['ServiceAccount', 'saw-test-sandbox']['automountServiceAccountToken'] is False


def test_network_does_not_grant_workload_or_namespace_wide_egress():
    docs = render()
    policies = [d for (kind, _), d in docs.items() if kind == 'NetworkPolicy']
    deny = docs['NetworkPolicy', 'saw-test-default-deny']['spec']
    assert deny['egress'] == deny['ingress'] == []
    granting = [p for p in policies if p['spec'].get('egress')]
    assert len(granting) == 1
    assert granting[0]['spec']['podSelector']['matchLabels']['openshell.pattern/role'] == 'gateway'
    assert not any(p['spec']['podSelector'].get('matchLabels', {}).get('openshell.ai/boundary-role') == 'workload' for p in granting)
    assert docs['Route', 'saw-test-gateway']['spec']['tls'] == {'termination': 'passthrough'}


def test_repeat_renders_have_no_random_keys_or_identity():
    first = template()
    second = template()
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    assert 'PRIVATE KEY' not in first.stdout


@pytest.mark.parametrize('assignment', [
    'kubernetes.experimental=false', 'deployment.mode=confidential',
    'deployment.mode=vm', 'kubernetes.gateway.image=repo:latest',
    'kubernetes.identity.serverTlsSecret=', 'kubernetes.storage.className=',
    'kubernetes.workload.runtimeClassName=kata', 'kubernetes.supervisor.runtimeClassName=kata',
    'oidc.issuerUrl=http://issuer.test', 'kubernetes.proxy.caConfigMap=',
    'kubernetes.governance.endpoint=http://outside.example.test:18081',
    'kubernetes.network.reconcilerNamespace=saw-test',
])
def test_invalid_or_unimplemented_inputs_fail_before_apply(assignment):
    result = template('--set', assignment)
    assert result.returncode != 0
    assert not result.stdout.strip()


def test_unsupported_backend_and_missing_dependencies_fail():
    for args, apis in [(['--set', 'deployment.mode=kata'], True), ([], False)]:
        result = template(*args, apis=apis)
        assert result.returncode != 0
        assert not result.stdout.strip()


@pytest.mark.parametrize('field,url', [
    ('kubernetes.proxy.url', 'http://user:example-secret@proxy.test:3128'),
    ('kubernetes.proxy.url', 'http://proxy.test:3128?token=example-secret:1'),
    ('kubernetes.governance.endpoint', 'https://user:example-secret@gov.test:443'),
    ('oidc.issuerUrl', 'https://user:example-secret@issuer.test/realm'),
    ('oidc.issuerUrl', 'https://issuer.test/realm?token=example-secret'),
])
def test_credentials_cannot_enter_configmap_through_urls(field, url):
    result = template('--set-string', f'{field}={url}')
    assert result.returncode != 0
    assert not result.stdout.strip()
    assert 'example-secret' not in result.stderr


@pytest.mark.parametrize('namespace', ['default', 'kube-system', 'kube-public',
                                      'openshift-monitoring', 'x' * 51])
def test_namespace_wide_deny_cannot_target_platform_namespace(namespace):
    result = template('--namespace', namespace)
    assert result.returncode != 0
    assert not result.stdout.strip()


@pytest.mark.parametrize('rules', [[], [{}], [{'to': [{}], 'ports': [{'port': 443}]}],
    [{'to': [{'namespaceSelector': {}}], 'ports': [{'port': 443}]}],
    [{'to': [{'namespaceSelector': {'matchLabels': {}}}], 'ports': [{'port': 443}]}],
    [{'to': [{'namespaceSelector': {'matchExpressions': []}}], 'ports': [{'port': 443}]}],
    [{'to': [{'ipBlock': {'cidr': '0.0.0.0/0'}}], 'ports': [{'port': 443}]}]])
def test_unbounded_gateway_egress_rejected(rules):
    result = template('--set-json', 'kubernetes.network.gatewayEgress=' + json.dumps(rules))
    assert result.returncode != 0
    assert not result.stdout.strip()
