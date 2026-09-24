"""Behavioral regression tests; no live cluster or user service changes."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'charts/saw-bom/scripts'))
import apply_bom as bom


def watcher():
    return load_script('watch-uninstall')


@pytest.mark.parametrize('code,remaining,expected', [(0, '', 0), (7, 'pattern', 7), (0, 'pattern', 124), (None, 'pattern', 124)])
def test_uninstall_termination(monkeypatch, code, remaining, expected):
    mod = watcher()
    child = Mock(pid=123, poll=Mock(return_value=code))
    monkeypatch.setattr(mod.subprocess, 'Popen', Mock(return_value=child))
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout=remaining, stderr=''))
    monkeypatch.setattr(mod.subprocess, 'run', run)
    kill = Mock()
    monkeypatch.setattr(mod.os, 'killpg', kill)
    ticks = iter(range(1000))
    monkeypatch.setattr(mod.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(mod.time, 'sleep', lambda _: None)
    monkeypatch.setenv('UNINSTALL_TIMEOUT_SECONDS', '10')
    monkeypatch.setattr(sys, 'argv', ['watch', 'ansible-playbook'])
    assert mod.main() == expected
    if code is None:
        child.wait.assert_called()
    else:
        child.wait.assert_not_called()
    kill.assert_called()
    for call in run.call_args_list:
        assert '--request-timeout=10s' in call.args[0]
        assert call.kwargs['timeout'] <= 10


@pytest.mark.parametrize('providers,expected', [(['nvidia'], True), (['nvidia', 'brave'], True), (['brave'], False)])
def test_provider_eligibility(monkeypatch, providers, expected):
    monkeypatch.setenv('PROV_NVIDIA_TYPE', 'custom')
    ws = bom.Workspace(name='default', providers=[bom.Provider(name='nvidia', type='nvidia'), bom.Provider(name='brave', type='brave')])
    assert bom.sandbox_skipped(ws, bom.Sandbox(name='notebook', providers=providers)) is expected


class Shell:
    dry_run = False
    def __init__(self, result):
        self.result = result
        self.commands = []
    def run(self, cmd, **kwargs):
        self.commands.append(cmd)
        return self.result


def test_creation_failure_stops_before_polling():
    shell = Shell((1, '', 'missing provider'))
    deployer = bom.WorkspaceDeployer(shell, None)
    assert deployer.create_sandbox_generic(bom.Sandbox(name='notebook'), 'vllm') is False
    assert not any('exec' in command for command in shell.commands)


def test_readiness_failure_stops_before_onboarding(monkeypatch):
    monkeypatch.setattr(bom.time, 'sleep', lambda _: None)
    shell = Shell((1, '', 'sandbox not found'))
    assert bom.WorkspaceDeployer(shell, None).start_openclaw_gateway('notebook', '', 'vllm') is False
    assert len(shell.commands) == 20
    assert all(command[:3] == ['openshell', 'sandbox', 'get'] for command in shell.commands)


def test_container_lookup_includes_workspace():
    shell = Shell((0, '', ''))
    deployer = bom.WorkspaceDeployer(shell, None)
    deployer.chown_sandbox_home('notebook', 'vllm')
    deployer.chown_sandbox_home('notebook', 'default')
    assert 'openshell-vllm--notebook-' in shell.commands[0][-1]
    assert 'openshell-(default--)?notebook-' in shell.commands[1][-1]


def test_inference_template_optional_url(tmp_path):
    rendered = subprocess.check_output(['helm', 'template', 'secrets', str(ROOT / 'charts/pattern-secrets')], text=True)
    spec = next(d['spec'] for d in yaml.safe_load_all(rendered) if d and d['metadata']['name'] == 'inference')
    assert 'data' not in spec
    template = spec['target']['template']
    assert set(template['data']) == {'provider', 'model', 'api_key', 'url'}
    # Execute Go templates in strict missing-key mode, as ESO does. Only default
    # is needed from Sprig for this template; all values under test are strings.
    program = tmp_path / 'main.go'
    program.write_text('''package main
import("encoding/json";"os";"text/template")
func main(){var v struct{Template string; Data map[string]string}; json.NewDecoder(os.Stdin).Decode(&v)
t:=template.Must(template.New("secret").Option("missingkey=error").Funcs(template.FuncMap{"default":func(a,b string)string{if b=="" {return a};return b}}).Parse(v.Template))
if e:=t.Execute(os.Stdout,v.Data);e!=nil{os.Exit(1)}}''')
    # index on map[string]interface{} yields nil for missing values in ESO;
    # string map here yields empty string, both accepted by Sprig default.
    executable = tmp_path / 'render'
    subprocess.run(['go', 'build', '-o', str(executable), str(program)], check=True, env=dict(os.environ, GOCACHE=str(tmp_path / 'go-cache')))
    import json
    for data in [dict(provider='build', model='m', api_key='k'), dict(provider='custom', model='tinyllama:latest', api_key='k', url='https://example/v1'), dict(provider='build', model='m', api_key='k', url='')]:
        for key, value in template['data'].items():
            r = subprocess.run([str(executable)], input=json.dumps(dict(Template=value, Data=data)), text=True, capture_output=True)
            assert r.returncode == 0
            assert r.stdout == data.get(key, '')
    for key in ['provider', 'model', 'api_key']:
        r = subprocess.run([str(executable)], input=json.dumps(dict(Template=template['data'][key], Data={})), text=True, capture_output=True)
        assert r.returncode != 0

@pytest.mark.parametrize('mode', ['repeat', 'symlink', 'disabled', 'restart-failure', 'timeout'])
def test_dashboard_setup(tmp_path, mode):
    home = tmp_path / 'home'
    units = home / '.config/systemd/user'
    units.mkdir(parents=True)
    source = tmp_path / 'baked-unit'
    source.write_text('do not change')
    for unit in ['openshell-dashboard.service', 'openshell-dashboard-proxy.service']:
        target = units / unit
        if mode == 'symlink':
            target.symlink_to(source)
        else:
            target.write_text('old unit')
            target.chmod(0o444)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    # Exercise actual file replacement, mock privilege escalation and Linux mv's -T.
    mocks = {
        'sudo': '#!/bin/bash\nexec "$@"\n',
        'mv': '#!/bin/bash\nshift\n/bin/mv -f "$@"\n',
        'systemctl': '#!/bin/bash\necho "$*" >> "$CALLS"\n[[ "$MODE" != restart-failure || "$*" != *restart* ]]\n',
        'curl': '#!/bin/bash\n[[ "$MODE" != timeout ]]\n',
        'docker': '#!/bin/bash\nexit 0\n',
        'sleep': '#!/bin/bash\nexit 0\n',
    }
    for name, text in mocks.items():
        path = bindir / name
        path.write_text(text)
        path.chmod(0o755)
    script = (ROOT / 'charts/openshell-saw/files/setup-dashboard.sh').read_text()
    # Keep the real timeout control flow while shortening the test deadline.
    script = script.replace('SECONDS + 120', 'SECONDS + 1')
    env = dict(os.environ, HOME=str(home), PATH=f'{bindir}:{os.environ["PATH"]}', MODE=mode,
               CALLS=str(tmp_path / 'calls'), RUNTIME='docker', DASHBOARD_ENABLED='false' if mode == 'disabled' else 'true',
               OIDC_ISSUER='https://oidc/realms/test', DASHBOARD_IMAGE='dashboard', DASHBOARD_PROXY_IMAGE='proxy',
               DASHBOARD_COOKIE_SECRET='test', DASHBOARD_REDIRECT_URL='https://dashboard/oauth2/callback')
    for _ in range(2 if mode == 'repeat' else 1):
        result = subprocess.run(['bash'], input=script, text=True, env=env, capture_output=True)
        assert (result.returncode == 0) == (mode not in ['restart-failure', 'timeout']), result.stderr
    assert source.read_text() == 'do not change'
    if mode == 'disabled':
        assert not (tmp_path / 'calls').exists()
    else:
        assert not (units / 'openshell-dashboard.service').is_symlink()
        assert (units / 'openshell-dashboard.service').stat().st_mode & 0o777 == 0o644
        assert 'ExecStart=' in (units / 'openshell-dashboard.service').read_text()


@pytest.mark.parametrize('failure', ['provider', 'create', 'ready', 'none'])
def test_main_failure_propagation(tmp_path, monkeypatch, failure):
    monkeypatch.setenv('PROV_OPENAI_TYPE', 'custom')
    from test_apply_bom import _write_profile
    _write_profile(tmp_path, workspace='vllm', providers_yaml={'spec': {'providers': [dict(name='openai', type='openai', nemoclawProvider='custom', url='https://example/v1', model='tinyllama:latest')]}}, sandbox_yaml={'spec': {'sandboxes': [dict(name='notebook', type='openclaw', providers=['openai'])]}})
    monkeypatch.setattr(sys, 'argv', ['apply', '--profiles-dir', str(tmp_path)])
    for name in ['configure_oidc', 'register_mtls_gateway', 'grant_default_workspace_access', 'enable_providers_v2']:
        monkeypatch.setattr(bom.GatewaySetup, name, lambda *a: None)
    monkeypatch.setattr(bom.WorkspaceDeployer, 'create_workspace', lambda *a: None)
    monkeypatch.setattr(bom.WorkspaceDeployer, 'create_provider', lambda *a: failure != 'provider')
    monkeypatch.setattr(bom.WorkspaceDeployer, 'create_sandbox_generic', lambda *a: failure != 'create')
    gateway = Mock(return_value=failure != 'ready')
    monkeypatch.setattr(bom.WorkspaceDeployer, 'start_openclaw_gateway', gateway)
    monkeypatch.setattr(bom.Verifier, 'verify_profiles', lambda *a: True)
    if failure == 'none':
        bom.main()
    else:
        with pytest.raises(SystemExit) as error:
            bom.main()
        assert error.value.code == 1
    if failure in ['provider', 'create']:
        gateway.assert_not_called()

@pytest.mark.parametrize('url,model', [('', 'tinyllama:latest'), ('https://example/v1', '')])
def test_custom_validation_precedes_gateway_setup(tmp_path, monkeypatch, url, model):
    monkeypatch.setenv('PROV_OPENAI_TYPE', 'custom')
    from test_apply_bom import _write_profile
    _write_profile(tmp_path, providers_yaml={'spec': {'providers': [dict(name='openai', type='openai', nemoclawProvider='custom', url=url, model=model)]}})
    monkeypatch.setattr(sys, 'argv', ['apply', '--profiles-dir', str(tmp_path)])
    configure = Mock()
    monkeypatch.setattr(bom.GatewaySetup, 'configure_oidc', configure)
    with pytest.raises(SystemExit, match='requires endpoint URL and model'):
        bom.main()
    configure.assert_not_called()


def test_skipped_sandbox_never_pulls_or_onboards(tmp_path, monkeypatch):
    from test_apply_bom import _write_profile
    _write_profile(tmp_path, providers_yaml={'spec': {'providers': [dict(name='nvidia', type='nvidia', model='nvidia/model'), dict(name='brave', type='brave')]}}, sandbox_yaml={'spec': {'sandboxes': [dict(name='notebook', type='nemoclaw', image='example/image', providers=['nvidia', 'brave'])]}})
    monkeypatch.setenv('PROV_NVIDIA_TYPE', 'custom')
    monkeypatch.setattr(sys, 'argv', ['apply', '--profiles-dir', str(tmp_path)])
    for name in ['configure_oidc', 'register_mtls_gateway', 'grant_default_workspace_access', 'enable_providers_v2']:
        monkeypatch.setattr(bom.GatewaySetup, name, lambda *a: None)
    monkeypatch.setattr(bom.WorkspaceDeployer, 'create_workspace', lambda *a: None)
    provider = Mock()
    create = Mock()
    monkeypatch.setattr(bom.WorkspaceDeployer, 'create_provider', provider)
    monkeypatch.setattr(bom.WorkspaceDeployer, 'create_sandbox_generic', create)
    shell = Mock(return_value=(0, '', ''))
    monkeypatch.setattr(bom.Shell, 'run', shell)
    monkeypatch.setattr(bom.Verifier, 'verify_profiles', lambda *a: True)
    bom.main()
    create.assert_not_called()
    shell.assert_not_called()
    assert provider.call_count == 1
    assert provider.call_args.args[0].name == 'brave'



def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize('host', ['', 'model.example.test'])
def test_governance_hostname_is_opt_in(host):
    args = ['helm', 'template', 'governance', str(ROOT / 'charts/governance-policy'),
            '-f', str(ROOT / 'overrides/governance-policy.yaml')]
    if host: args += ['--set-string', f'customEndpointHost={host}']
    docs = list(yaml.safe_load_all(subprocess.check_output(args, text=True)))
    data = next(d['data'] for d in docs if d and d['metadata']['name'] == 'governance-interceptor-profiles')
    assert ('openai.yaml' in data) is bool(host)
    if host:
        profile = yaml.safe_load(data['openai.yaml'])
        assert profile['endpoints'][0]['host'] == host
        assert profile['endpoints'][0]['tls'] == 'terminate'
        assert profile['credentials'][0]['env_vars'] == ['OPENAI_API_KEY']
        assert profile['binaries'] == ['/usr/local/bin/node', '/usr/bin/curl']


@pytest.mark.parametrize('mode', ['gone', 'delayed', 'api-error', 'timeout', 'api-absent'])
def test_normal_deletion(monkeypatch, mode, capsys):
    mod = load_script('delete-and-wait')
    monkeypatch.setattr(sys, 'argv', ['delete', 'hyperconvergeds.hco.kubevirt.io/test',
                                     '--namespace', 'test', '--timeout', '20',
                                     '--optional-api-group', 'hco.kubevirt.io'])
    ticks = iter(range(1000))
    monkeypatch.setattr(mod.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(mod.time, 'sleep', lambda _: None)
    gets = 0
    calls = []
    def run(cmd, **kwargs):
        nonlocal gets
        calls.append(cmd)
        assert 0 < kwargs['timeout'] <= 10
        out = ''
        if 'api-resources' in cmd:
            out = '' if mode == 'api-absent' else 'hyperconvergeds.hco.kubevirt.io'
        if 'get' in cmd:
            gets += 1
            if mode == 'timeout' or (mode == 'delayed' and gets < 3): out = 'remaining'
        return SimpleNamespace(returncode=1 if mode == 'api-error' else 0,
                               stdout=out, stderr='forbidden')
    monkeypatch.setattr(mod.subprocess, 'run', run)
    assert mod.main() == (1 if mode == 'api-error' else 124 if mode == 'timeout' else 0)
    assert all('patch' not in cmd and 'replace' not in cmd for cmd in calls)
    if mode == 'api-absent': assert len(calls) == 1
    if mode == 'timeout': assert 'finalizers were preserved' in capsys.readouterr().err


@pytest.mark.parametrize('finished', [True, False])
def test_process_group_cleanup_is_bounded(monkeypatch, finished, capsys):
    mod = load_script('watch-uninstall')
    child = Mock(pid=321, poll=Mock(return_value=0 if finished else None))
    child.wait.side_effect = subprocess.TimeoutExpired('playbook', 1)
    kill = Mock()
    monkeypatch.setattr(mod.os, 'killpg', kill)
    mod.stop_process_group(child)
    assert [c.args[1] for c in kill.call_args_list] == [signal.SIGTERM, signal.SIGKILL]
    assert [c.kwargs['timeout'] for c in child.wait.call_args_list] == ([] if finished else [5, 2])
    if not finished: assert 'did not reap' in capsys.readouterr().err


def test_make_uninstall_keeps_controllers_until_cleanup():
    text = (ROOT / 'Makefile-quickstart').read_text()
    pre = text.split('pre-uninstall:\n')[1].split('# Generate SSH')[0]
    uninstall = text.split('uninstall: pre-uninstall')[1].split('# Clean up a single')[0]
    assert 'clean-stale-operators' not in pre
    assert pre.index('secure-agent-workspace-prod') < pre.index('delete vm,dv,job')
    assert 'delete-and-wait.py hyperconvergeds.hco.kubevirt.io/kubevirt-hyperconverged' in pre
    assert '/finalize' not in uninstall and 'kubectl proxy' not in uninstall
    assert 'delete-and-wait.py namespace/$(NS)' in uninstall


def test_cleanup_runs_after_playbook_exit_with_descendants(monkeypatch):
    mod = load_script('watch-uninstall')
    child = Mock(pid=123, poll=Mock(return_value=0))
    kill = Mock()
    monkeypatch.setattr(mod.os, 'killpg', kill)
    mod.stop_process_group(child)
    assert kill.call_count == 2
    child.wait.assert_not_called()


@pytest.mark.parametrize('failure', ['list', 'patch', 'delete'])
def test_watcher_preserves_api_failure(monkeypatch, failure):
    mod = load_script('watch-uninstall')
    monkeypatch.setattr(sys, 'argv', ['watch', 'playbook'])
    monkeypatch.setenv('UNINSTALL_TIMEOUT_SECONDS', '10')
    child = Mock(pid=123, poll=Mock(return_value=None))
    monkeypatch.setattr(mod.subprocess, 'Popen', Mock(return_value=child))
    monkeypatch.setattr(mod.os, 'killpg', Mock())
    def run(cmd, **kwargs):
        verb = 'list' if cmd[2] == 'get' else cmd[2]
        return SimpleNamespace(returncode=1 if verb == failure else 0,
                               stdout='applications.argoproj.io/test', stderr='forbidden')
    monkeypatch.setattr(mod.subprocess, 'run', run)
    assert mod.main() == 1


@pytest.mark.parametrize('mode', ['success', 'hco-error', 'playbook-error', 'namespace-error'])
def test_make_uninstall_stops_after_failure(tmp_path, mode):
    """Run the real recipes with an isolated oc; no Kubernetes calls escape."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    oc = bindir / 'oc'
    oc.write_text(f'#!{sys.executable}\n' + '''
import json,os,sys
args=sys.argv[1:]; mode=os.environ['MODE']
with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(args)+'\\n')
if 'api-resources' in args: print('hyperconvergeds.hco.kubevirt.io')
if 'get' in args and 'patterns' in args and mode=='playbook-error': print('pattern/test')
if mode=='hco-error' and 'delete' in args and 'hyperconvergeds.hco.kubevirt.io/kubevirt-hyperconverged' in args: sys.exit(3)
if mode=='namespace-error' and 'delete' in args and 'namespace/openshell-agents' in args: sys.exit(3)
''')
    oc.chmod(0o755)
    playbook = bindir / 'playbook'
    playbook.write_text('#!/bin/sh\nexit 7\n')
    playbook.chmod(0o755)
    env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}',
               MODE=mode, CALLS=str(tmp_path / 'calls'))
    result = subprocess.run(['make', '-f', 'Makefile-quickstart', 'uninstall',
                             f'ANSIBLE_RUN={playbook}', 'UNINSTALL_TIMEOUT_SECONDS=15'],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=25)
    assert (result.returncode == 0) == (mode == 'success'), result.stdout + result.stderr
    calls = [json.loads(line) for line in (tmp_path / 'calls').read_text().splitlines()]
    if mode in ['hco-error', 'playbook-error']:
        assert not any('subscription' in c for c in calls)
        assert not any('namespace/openshell-agents' in c for c in calls)
    assert not any('/finalize' in ' '.join(c) for c in calls)
    assert not any('patch' in c and 'hyperconverged' in ' '.join(c) for c in calls)


def test_term_resistant_child_is_killed_and_reaped():
    mod = load_script('watch-uninstall')
    child = subprocess.Popen(
        [sys.executable, '-c',
         'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
         'print("ready", flush=True); time.sleep(60)'],
        start_new_session=True, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        started = time.monotonic()
        mod.stop_process_group(child)
        assert time.monotonic() - started < 8
        assert child.poll() == -signal.SIGKILL
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        child.stdout.close()
