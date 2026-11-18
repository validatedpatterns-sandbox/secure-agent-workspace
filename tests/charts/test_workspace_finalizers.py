"""Both entry points preserve Argo hook state without hiding desired-state drift."""
import json
import shutil
import subprocess

import pytest
from test_portal_container import GLOBAL, SITE, U, render, user


@pytest.mark.parametrize('entry', ['portal', 'static'])
def test_hook_state_does_not_fight_parent_sync_or_hide_cleanup_drift(entry):
    if entry == 'portal':
        docs = render('openshell-rhdh', 'portal', 'rhdh', {})
    else:
        docs = render('saw-users', 'workspaces', 'saw-installation', {
            'global': GLOBAL, 'users': [user()], 'containerSites': {U: SITE},
            'projection': {'enabled': True, 'applicationSetControllerLabels': {
                'app.kubernetes.io/name': 'vp-gitops-applicationset-controller'},
                'egress': [{'ports': [{'protocol': 'TCP', 'port': 443}]}]}})
    appset, = [d for d in docs if d['kind'] == 'ApplicationSet']
    spec = appset['spec']['template']['spec']
    rule, = spec['ignoreDifferences']
    assert set(rule) == {'group', 'kind', 'jqPathExpressions'}
    assert (rule['group'], rule['kind']) == ('argoproj.io', 'Application')
    assert 'RespectIgnoreDifferences=true' in spec['syncPolicy']['syncOptions']
    expression, = rule['jqPathExpressions']
    assert expression == ('.metadata.finalizers[]? | select(. == '
                          '"pre-delete-finalizer.argocd.argoproj.io" or . == '
                          '"pre-delete-finalizer.argocd.argoproj.io/cleanup")')
    if not shutil.which('jq'):
        pytest.skip('jq required for semantic diff-normalization check')

    def normalize(value):
        p = subprocess.run(['jq', '-c', 'del(' + expression + ')'],
                           input=json.dumps(value), text=True, capture_output=True, check=True)
        return json.loads(p.stdout)

    desired = {'metadata': {'finalizers': ['resources-finalizer.argocd.argoproj.io/foreground']},
               'spec': {'source': {'targetRevision': 'reviewed'}}}
    live = json.loads(json.dumps(desired))
    live['metadata']['finalizers'] += ['pre-delete-finalizer.argocd.argoproj.io',
                                      'pre-delete-finalizer.argocd.argoproj.io/cleanup']
    assert normalize(live) == desired
    live['metadata']['finalizers'].pop(0)
    assert normalize(live) != desired  # Removing cascade cleanup must still be repaired.
    live = json.loads(json.dumps(desired))
    live['spec']['source']['targetRevision'] = 'unreviewed'
    assert normalize(live) != desired
    assert normalize({'metadata': {}}) == {'metadata': {}}
