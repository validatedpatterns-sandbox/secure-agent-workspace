"""Run the rendered MTU helper against a simulated Docker/VM network."""
import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('mtu,existing', [(1400, True), (1500, True), (1400, False)])
def test_reconcile_mtu(tmp_path, mtu, existing):
    rendered = subprocess.check_output(['helm', 'template', 'openshell-saw', str(ROOT / 'charts/openshell-saw')], text=True)
    scripts = next(d['data'] for d in yaml.safe_load_all(rendered) if d and d.get('kind') == 'ConfigMap' and d['metadata']['name'] == 'openshell-saw-scripts')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    stub = '''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name; args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f: f.write(json.dumps([name,*args])+'\\n')
if name=='ip':
 if 'route' in args: print('[{"dev":"enp1s0"}]')
 elif '-j' in args: print(json.dumps([{'mtu':int(os.environ['MTU'])}]))
elif name=='docker':
 if args[:2]==['network','inspect']:
  if not Path(os.environ['NETWORK']).exists(): sys.exit(1)
  print('[{"Driver":"bridge","Id":"abcdef1234567890","Options":{}}]')
 elif args[:2]==['network','create']: Path(os.environ['NETWORK']).touch()
 elif args[0]=='ps': print('container1')
 elif args[0]=='inspect': print('[{"State":{"Pid":42},"NetworkSettings":{"Networks":{"openshell-docker":{"IPAddress":"172.18.0.2"}}}}]')
elif name=='nsenter' and '-j' in args:
 print('[{"ifname":"eth0","addr_info":[{"local":"172.18.0.2"}]}]')
elif name=='iptables':
 p=Path(os.environ['RULE'])
 key=json.dumps(args[args.index('FORWARD')+1:])
 rules=p.read_text().splitlines() if p.exists() else []
 if '-C' in args: sys.exit(0 if key in rules else 1)
 if '-A' in args: p.write_text('\\n'.join([*rules,key])+'\\n')
'''
    for name in ['ip', 'docker', 'nsenter', 'iptables']:
        path = bindir / name
        path.write_text(stub)
        path.chmod(0o755)
    network = tmp_path / 'network'
    if existing: network.touch()
    env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}', CALLS=str(tmp_path / 'calls'), MTU=str(mtu), NETWORK=str(network), RULE=str(tmp_path / 'rule'))
    for _ in range(2):
        result = subprocess.run(['bash'], input=scripts['configure-docker-mtu.sh'], env=env, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
    import json
    calls = [json.loads(line) for line in (tmp_path / 'calls').read_text().splitlines()]
    assert ['ip','link','set','dev','br-abcdef123456','mtu',str(mtu)] in calls
    assert ['nsenter','-t','42','-n','ip','link','set','dev','eth0','mtu',str(mtu)] in calls
    rules = [c for c in calls if c[0]=='iptables' and '-A' in c]
    assert len(rules) == 2
    assert {(r[r.index('-i')+1], r[r.index('-o')+1]) for r in rules} == {
        ('br-abcdef123456', 'enp1s0'), ('enp1s0', 'br-abcdef123456')}
    for rule in rules:
        assert rule[-2:] == ['--set-mss', str(mtu - 40)]
    creates = [c for c in calls if c[:3]==['docker','network','create']]
    assert len(creates) == (0 if existing else 1)
    if creates: assert f'com.docker.network.driver.mtu={mtu}' in creates[0]
