"""Run the public E2E CLI against local fakes; never contact a cluster."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
FAKE = r'''#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
p=Path(os.environ['FAKE_STATE']); d=json.loads(p.read_text()); a=sys.argv[1:]; cmd=Path(sys.argv[0]).name
with open(os.environ['FAKE_LOG'],'a') as f: f.write(json.dumps([cmd]+a)+'\n')
def save(): p.write_text(json.dumps(d))
def out(v): print(json.dumps(v))
if cmd=='helm':
 if a[0]=='status': sys.exit(0 if d['controller']=='helm' else 1)
 if a[:2]==['get','values']: out({'harnessEnabled':d['original']})
 if a[0]=='upgrade':
  d['enabled']=a[a.index('--set')+1].endswith('=true');d['changed']=True;save()
elif cmd=='oc':
 if 'get' in a:
  kind=a[a.index('get')+1]
  if kind=='vm': print('saw-profiles' if d.get('live',True) else '')
  elif kind=='applications':
   apps=[]
   if d['controller']=='argo':
    apps=[{'metadata':{'name':'bom','namespace':'gitops','labels':{'argocd.argoproj.io/instance':'parent'}},'spec':{'destination':{'namespace':'saw-demo'},'source':{'path':'charts/saw-bom','helm':{'parameters':d['parameters']}},'syncPolicy':{'automated':{'prune':True,'selfHeal':True}}}}, {'metadata':{'name':'parent','namespace':'gitops'},'spec':{'syncPolicy':{'automated':{'selfHeal':True}}}}]
   out({'items':apps * (2 if d.get('ambiguous') else 1)})
  elif kind=='application': out({'spec':{},'status':{'operationState':{'phase':'Succeeded'}}})
  elif kind=='configmap':
   if d.get('poll_fail') and d.get('changed'): out({'data':{}})
   else: out({'data':{'profiles__ds__default__sandbox.yaml': 'spec:\n  sandboxes:\n  - name: notebook\n'+('    harnessRef: {name: demo}\n' if d['enabled'] else '')}})
 elif 'patch' in a:
  name=a[a.index('patch')+2]; patch=json.loads(a[a.index('-p')+1]);d.setdefault('patches',[]).append([name,patch]);save()
  if name=='bom':
   params=patch.get('spec',{}).get('source',{}).get('helm',{}).get('parameters')
   if params is not None:
    d['parameters']=params;d['changed']=True
    flag=next((x['value'] for x in params if x['name']=='harnessEnabled'),None)
    d['enabled']=d['original'] if flag is None else flag=='true';save()
elif cmd=='virtctl':
 if 'restart' in a:
  if d.get('block'): print('restart reached',flush=True);time.sleep(60)
elif cmd=='openshell':
 if 'exec' not in a:
  if 'list-profiles' in a: out([])
  elif 'list' in a: print('notebook ready')
 else:
  args=a[a.index('--')+1:]; text=' '.join(args)
  if args[:2]==['test','-d'] and args[-1]=='/sandbox/harness': sys.exit(0 if d['enabled'] else 1)
  if 'if test -d /sandbox/harness' in text: print('present' if d['enabled'] else 'gone')
  if 'touch ' in text: sys.exit(1)
  if args==['mount']: print('volume on /sandbox/harness type tmpfs (ro,relatime)')
  if 'plugins list' in text: out({'plugins':[{'format':'bundle','rootDir':'/sandbox/harness','id':'actual-mounted-id','enabled':True,'status':'loaded'}]})
  elif 'plugins inspect' in text:
   if d.get('unsupported'): print('unknown command inspect',file=sys.stderr);sys.exit(2)
   out({'plugin':{'status':d.get('runtime_status','loaded')},'mcpServers':[{'name':d.get('server','search'),'unsupported':d.get('unsupported_entry',False)}],'diagnostics':d.get('diagnostics',[])})
  elif 'mcp status' in text: print('search-extra: error mentioning search')
  elif 'cat /sandbox/harness/mcp.json' in text: out({'mcpServers':{'search':{}}})
  elif 'plugins.load.paths' in text:
   if not d['enabled'] and d.get('config_error'): print(d['config_error'],file=sys.stderr);sys.exit(1)
   print('/sandbox/harness' if d['enabled'] else '[]')
  elif 'harness.yaml' in text: print('spec: {}')
'''


def fixture(tmp_path, **changes):
    state = dict(controller='helm', enabled=True, original=True,
                 parameters=[{'name':'other','value':'keep','forceString':True}])
    state.update(changes)
    path = tmp_path / 'state.json'
    path.write_text(json.dumps(state))
    log = tmp_path / 'commands.jsonl'
    for name in ('openshell','helm','oc','virtctl'):
        script = tmp_path / name
        script.write_text(FAKE)
        script.chmod(0o755)
    env = {**os.environ, 'PATH': str(tmp_path)+os.pathsep+os.environ['PATH'],
           'FAKE_STATE':str(path),'FAKE_LOG':str(log),'DRILL_TIMEOUT':'1',
           'DRILL_POLL_INTERVAL':'0.01','SAW_NS':'saw-demo'}
    return path,log,env


def run(env, *args):
    return subprocess.run(['bash',str(ROOT/'scripts/e2e-harness.sh'),'--gateway','demo',*args],
                          env=env,text=True,capture_output=True,timeout=25)


def test_h3_exact_registration_and_actual_mounted_id(tmp_path):
    _, log, env = fixture(tmp_path,server='search-extra')
    result=run(env)
    assert result.returncode == 1
    assert 'registered' in result.stdout
    commands=log.read_text()
    assert 'plugins inspect' in commands and 'actual-mounted-id' in commands and '--runtime --json' in commands
    assert 'mcp status' not in commands


def test_h3_unsupported_inspection_warns_registration_only(tmp_path):
    _,_,env=fixture(tmp_path,unsupported=True)
    result=run(env)
    assert result.returncode == 0, result.stdout+result.stderr
    assert 'WARNING' in result.stdout and 'registration' in result.stdout
    assert 'readiness' in result.stdout


@pytest.mark.parametrize('controller',['helm','argo'])
def test_drill_restores_original_state_and_waits_before_restart(tmp_path,controller):
    path,log,env=fixture(tmp_path,controller=controller,live=False)
    result=run(env,'--revoke-drill')
    assert result.returncode == 0, result.stdout+result.stderr
    state=json.loads(path.read_text())
    assert state['enabled'] is True
    assert state['parameters']==[{'name':'other','value':'keep','forceString':True}]
    cmds=[json.loads(x) for x in log.read_text().splitlines()]
    restarts=[i for i,c in enumerate(cmds) if c[0]=='virtctl' and 'restart' in c]
    assert len(restarts)>=2
    for i in restarts:
        assert any('configmap' in c for c in cmds[max(0,i-2):i])
    if controller=='argo':
        patches=state['patches']
        assert patches[0][0]=='parent'
        assert any('operation' in p for _,p in patches)
        assert patches[-1][0]=='parent'
        assert patches[-1][1]['spec']['syncPolicy']['automated']=={'selfHeal':True}


@pytest.mark.parametrize('controller',['helm','argo'])
def test_failed_poll_restores_desired_state(tmp_path,controller):
    path,log,env=fixture(tmp_path,controller=controller,poll_fail=True,live=False)
    result=run(env,'--revoke-drill')
    assert result.returncode != 0
    state=json.loads(path.read_text())
    assert state['enabled'] is True
    assert state['parameters']==[{'name':'other','value':'keep','forceString':True}]
    assert not any('restart' in json.loads(x) for x in log.read_text().splitlines())
    assert 'snapshot retained' in result.stderr
    if controller=='argo':
        assert state['patches'][-1][0]=='parent'
        assert state['patches'][-1][1]['spec']['syncPolicy']['automated']=={'selfHeal':True}


@pytest.mark.parametrize('signum',[signal.SIGINT,signal.SIGTERM])
@pytest.mark.parametrize('controller',['helm','argo'])
def test_signal_exits_and_restores(tmp_path,signum,controller):
    path,log,env=fixture(tmp_path,live=False,block=True,controller=controller)
    proc=subprocess.Popen(['bash',str(ROOT/'scripts/e2e-harness.sh'),'--gateway','demo','--revoke-drill'],
                          env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                          start_new_session=True)
    try:
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if log.exists() and 'restart' in log.read_text(): break
            time.sleep(.02)
        # Block only the initial restart; restoration can complete.
        state=json.loads(path.read_text());state['block']=False;path.write_text(json.dumps(state))
        os.killpg(proc.pid,signum)
        stdout,stderr=proc.communicate(timeout=10)
        assert proc.returncode==128+signum,stdout+stderr
        assert json.loads(path.read_text())['enabled'] is True
    finally:
        if proc.poll() is None: os.killpg(proc.pid,signal.SIGKILL);proc.wait()


def test_ambiguous_argo_is_failure(tmp_path):
    _,_,env=fixture(tmp_path,controller='argo',ambiguous=True)
    result=run(env,'--revoke-drill')
    assert result.returncode != 0
    assert 'ambiguous' in result.stderr.lower()+result.stdout.lower()


@pytest.mark.parametrize('changes',[
    {'unsupported_entry':True}, {'runtime_status':'error'},
    {'diagnostics':[{'level':'error','message':'search was not loaded'}]},
])
def test_h3_runtime_inspection_errors_fail(tmp_path,changes):
    _,_,env=fixture(tmp_path,**changes)
    result=run(env)
    assert result.returncode == 1
    assert 'MCP registration inspection failed' in result.stdout


def test_argo_explicit_controller_options(tmp_path):
    path,log,env=fixture(tmp_path,controller='argo',parameters=[
        {'name':'harnessEnabled','value':'true','forceString':True},
        {'name':'other','value':'keep'},
    ])
    result=run(env,'--revoke-drill','--bom-application','bom','--argo-namespace','gitops')
    assert result.returncode == 0, result.stdout+result.stderr
    assert json.loads(path.read_text())['parameters']==[
        {'name':'harnessEnabled','value':'true','forceString':True},
        {'name':'other','value':'keep'},
    ]
    commands=[json.loads(x) for x in log.read_text().splitlines()]
    assert ['oc','get','applications','-n','gitops','-o','json'] in commands


def test_no_controller_is_failure(tmp_path):
    _,_,env=fixture(tmp_path,controller='none')
    result=run(env,'--revoke-drill')
    assert result.returncode != 0


def test_helm_restores_original_false_flag(tmp_path):
    path,_,env=fixture(tmp_path,original=False)
    result=run(env,'--revoke-drill')
    assert result.returncode == 0,result.stdout+result.stderr
    assert json.loads(path.read_text())['enabled'] is False


@pytest.mark.parametrize('message,expected',[
    ('Config path is valid but unset: plugins.load.paths. The runtime default applies until you set an authored value with openclaw config set plugins.load.paths <value>.',0),
    ('Config path is valid but unset: plugins.load.paths. The runtime default applies until you set an authored value with openclaw config set plugins.load.paths <value>.\ngateway connection failed',1),
    ('gateway connection failed',1),
])
def test_drill_accepts_unset_path_but_not_inspection_failure(tmp_path,message,expected):
    path,_,env=fixture(tmp_path,controller='argo',config_error=message)
    result=run(env,'--revoke-drill')
    assert result.returncode==expected,result.stdout+result.stderr
    assert json.loads(path.read_text())['enabled'] is True
