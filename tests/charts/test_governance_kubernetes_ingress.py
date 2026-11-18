"""Opt-in container gateway ingress cannot widen the existing VM selectors."""
import shutil
from pathlib import Path
import pytest
import yaml
from helm_cache import run_helm

ROOT = Path(__file__).resolve().parents[2]
HELM = shutil.which('helm')
pytestmark = pytest.mark.skipif(not HELM, reason='helm required')


def render(*args):
    return run_helm([HELM, 'template', 'governance-interceptor', str(ROOT / 'charts/governance-interceptor'), *args], capture_output=True, text=True)


def peers(output):
    obj = next(d for d in yaml.safe_load_all(output) if d and d['kind'] == 'NetworkPolicy')
    return obj['spec']['ingress'][0]['from']


def test_default_stays_vm_only_and_opt_in_adds_exact_combined_selector():
    baseline = render()
    assert baseline.returncode == 0, baseline.stderr
    old = peers(baseline.stdout)
    assert len(old) == 2
    result = render('--set', 'kubernetesGateways[0].namespace=saw-k8s-test', '--set', 'kubernetesGateways[0].gatewayId=saw-k8s-test')
    assert result.returncode == 0, result.stderr
    new = peers(result.stdout)
    assert new[:2] == old
    assert new[2:] == [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'saw-k8s-test'}}, 'podSelector': {'matchLabels': {'app.kubernetes.io/instance': 'saw-k8s-test', 'openshell.pattern/role': 'gateway'}}}]


@pytest.mark.parametrize('namespace,gateway', [('', 'test'), ('test', ''), ('*', 'test'), ('test', '*'), ('a' * 64, 'test'), ('test', 'a' * 20)])
def test_rejects_missing_or_broad_identity(namespace, gateway):
    result = render('--set-string', f'kubernetesGateways[0].namespace={namespace}', '--set-string', f'kubernetesGateways[0].gatewayId={gateway}')
    assert result.returncode != 0
    assert 'exact namespace and gatewayId' in result.stderr
