#!/usr/bin/env python3
"""Desired-state changes for the opt-in E2E disable/restore drill.

State is saved before mutations so the shell EXIT trap can restore partial work.
Only Helm and Argo Applications (including Application-managed parents) are supported.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

import yaml


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE)


def patch(app, body):
    command('oc', '-n', app['namespace'], 'patch', 'application', app['name'],
            '--type=merge', '-p', json.dumps(body))


def identity(app):
    return {k: app['metadata'][k] for k in ('name', 'namespace')}


def source_matches(app, namespace):
    spec = app['spec']
    sources = spec.get('sources') or [spec.get('source', {})]
    return (spec.get('destination', {}).get('namespace') == namespace
            and any(source.get('path', '').rstrip('/') == 'charts/saw-bom'
                    for source in sources))


def wait_profiles(args, enabled):
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            cm = json.loads(command('oc', '-n', args.namespace, 'get', 'configmap',
                                    'saw-bom-profiles', '-o', 'json'))
            found = []
            for key, text in cm.get('data', {}).items():
                if key.startswith('profiles__') and key.endswith('__sandbox.yaml'):
                    doc = yaml.safe_load(text)
                    for sb in (doc.get('spec') or {}).get('sandboxes') or []:
                        if sb.get('name') == args.sandbox and f'__{args.workspace}__' in key:
                            found.append(bool(sb.get('harnessRef')))
            if found == [enabled]:
                return
        except (subprocess.CalledProcessError, ValueError, TypeError, AttributeError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('timeout waiting for rendered sandbox harnessRef in saw-bom-profiles')
        time.sleep(args.interval)


def restart(args):
    if not args.live_inputs:
        command('virtctl', 'restart', '-n', args.namespace, args.gateway)


def reconcile(app):
    patch(app, {'operation': {'initiatedBy': {'username': 'harness-e2e'},
                             'sync': {'prune': False}}})


def wait_operation(args, app, check_result=True):
    """A rendered ConfigMap can arrive before Argo finishes its sync operation."""
    deadline = time.monotonic() + args.timeout
    while True:
        current = json.loads(command('oc', '-n', app['namespace'], 'get', 'application',
                                     app['name'], '-o', 'json'))
        if not current.get('operation'):
            phase = current.get('status', {}).get('operationState', {}).get('phase')
            if check_result and phase in ('Failed', 'Error'):
                raise RuntimeError(f'Argo sync failed: {phase}')
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('timeout waiting for Argo sync operation to finish')
        time.sleep(args.interval)


def prepare(args):
    try:
        scope = ['-n', args.argo_namespace] if args.argo_namespace else ['-A']
        applications = json.loads(command('oc', 'get', 'applications', *scope, '-o', 'json'))['items']
    except subprocess.CalledProcessError as exc:
        error = (exc.stderr or '').lower()
        if args.application or not any(message in error for message in (
                "doesn't have a resource type", 'no matches for kind', 'could not find the requested resource')):
            raise RuntimeError('cannot discover Argo Applications; refusing uncertain controller ownership') from None
        # No Argo CRD is normal for a Helm-only installation.
        applications = []
    candidates = [a for a in applications if source_matches(a, args.namespace)
                  and (not args.application or a['metadata']['name'] == args.application)
                  and (not args.argo_namespace or a['metadata']['namespace'] == args.argo_namespace)]
    if len(candidates) > 1:
        raise RuntimeError('ambiguous BOM Argo Applications; use --bom-application and --argo-namespace')
    if args.application and not candidates:
        raise RuntimeError('requested BOM Argo Application not found for charts/saw-bom and destination namespace')
    if not candidates:
        command('helm', 'status', args.release, '-n', args.namespace)
        values = json.loads(command('helm', 'get', 'values', args.release, '-n', args.namespace,
                                    '--all', '-o', 'json'))
        enabled = values.get('harnessEnabled')
        if not isinstance(enabled, bool):
            raise RuntimeError('Helm harnessEnabled must be a boolean')
        state = {'controller': 'helm', 'enabled': enabled}
    else:
        app = candidates[0]
        if app['spec'].get('sources'):
            raise RuntimeError('multi-source Argo BOM Applications are unsupported by this drill')
        chain = []
        seen = set()
        current = app
        while current:
            ident = identity(current)
            key = tuple(ident.values())
            if key in seen:
                raise RuntimeError('cyclic Argo Application ownership')
            seen.add(key)
            if current['metadata'].get('ownerReferences'):
                raise RuntimeError('unsupported Argo controller ownership (e.g. ApplicationSet)')
            if current.get('operation'):
                raise RuntimeError('Argo Application already has a pending operation')
            chain.append({**ident, 'automated': current['spec'].get('syncPolicy', {}).get('automated')})
            meta = current['metadata']
            tracking = meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id', '')
            parent_name = tracking.split(':', 1)[0] if tracking else meta.get('labels', {}).get('argocd.argoproj.io/instance')
            if parent_name == meta['name']:
                parent_name = None  # self tracking is not parent ownership
            if not parent_name:
                current = None
            else:
                parents = [a for a in applications if a['metadata']['name'] == parent_name
                           and a['metadata']['namespace'] == meta['namespace']]
                if len(parents) != 1:
                    raise RuntimeError('unsupported or ambiguous managing Argo Application')
                current = parents[0]
        params = app['spec']['source'].get('helm', {}).get('parameters')
        state = {'controller': 'argo', 'app': identity(app), 'parameters': params, 'chain': chain}
        # Read actual rendered original state, including value files/valuesObject.
        cm = json.loads(command('oc', '-n', args.namespace, 'get', 'configmap', 'saw-bom-profiles', '-o', 'json'))
        original = []
        for key, text in cm.get('data', {}).items():
            if key.startswith('profiles__') and key.endswith('__sandbox.yaml') and f'__{args.workspace}__' in key:
                for sb in (yaml.safe_load(text).get('spec') or {}).get('sandboxes') or []:
                    if sb.get('name') == args.sandbox:
                        original.append(bool(sb.get('harnessRef')))
        if len(original) != 1:
            raise RuntimeError('cannot identify original sandbox harness state in ConfigMap')
        state['enabled'] = original[0]
    Path(args.state).write_text(json.dumps(state))
    if state['controller'] == 'argo':
        # Pause highest parent first so it cannot undo the child pause/override.
        for app in reversed(state['chain']):
            patch(app, {'spec': {'syncPolicy': {'automated': None}}})
    print(f"BOM controller: {state['controller']}; original harnessEnabled={state['enabled']}")


def set_state(args, state, enabled, restoring=False):
    if state['controller'] == 'helm':
        command('helm', 'upgrade', args.release, args.chart, '-n', args.namespace,
                '--reuse-values', '--set', f'harnessEnabled={str(enabled).lower()}')
    else:
        params = state['parameters'] if restoring else [
            p for p in (state['parameters'] or []) if p['name'] != 'harnessEnabled'
        ] + [{'name': 'harnessEnabled', 'value': str(enabled).lower()}]
        patch(state['app'], {'spec': {'source': {'helm': {'parameters': params}}}})
        if restoring:
            # A failed profile poll can leave the preceding sync running.
            # Save restored desired state first, then avoid overlapping syncs.
            wait_operation(args, state['app'], check_result=False)
        reconcile(state['app'])
    wait_profiles(args, enabled)
    if state['controller'] == 'argo':
        wait_operation(args, state['app'])
    restart(args)


def restore(args, state):
    errors = []
    try:
        set_state(args, state, state['enabled'], restoring=True)
    except Exception as exc:
        errors.append(str(exc))
    # Restore automation even when rendered profiles/VM are unavailable.
    for app in state.get('chain', []):
        try:
            patch(app, {'spec': {'syncPolicy': {'automated': app['automated']}}})
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise RuntimeError('; '.join(errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'disable', 'restore', 'original'))
    for name in ('state', 'namespace', 'release', 'chart', 'gateway', 'sandbox', 'workspace'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--application', default='')
    parser.add_argument('--argo-namespace', default='')
    parser.add_argument('--live-inputs', action='store_true')
    parser.add_argument('--timeout', type=float, default=1500)
    parser.add_argument('--interval', type=float, default=15)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args)
    elif Path(args.state).exists() and Path(args.state).stat().st_size:
        state = json.loads(Path(args.state).read_text())
        if args.action == 'original':
            print('present' if state['enabled'] else 'gone')
        elif args.action == 'restore':
            restore(args, state)
        else:
            set_state(args, state, False)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'H9 controller error: {exc}', file=sys.stderr)
        sys.exit(1)
