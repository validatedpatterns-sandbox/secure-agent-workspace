"""The proxy's bindings must follow the shipped profile catalog and metadata split."""

import json
import shutil
from pathlib import Path

import pytest
from helm_cache import run_helm
import yaml

ROOT = Path(__file__).resolve().parents[2]
SAW = ROOT / "charts/openshell-saw"
PROFILES = ROOT / "charts/governance-policy/profiles"
HELM = shutil.which("helm")


def render(chart, *args):
    result = run_helm([HELM, "template", "saw-test", str(chart), "-n", "saw-test", *args],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_proxy_policy_matches_all_keyed_profile_copies():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"))
    cm = next(d for d in docs if d["kind"] == "ConfigMap" and
              d["metadata"]["name"] == "saw-test-credential-proxy-config")
    policy = json.loads(cm["data"]["config.json"])
    assert policy["markerPrefix"] == "saw-cred"
    assert {(b["secret"], b["key"]) for b in policy["bindings"]} == {
        ("inference", "api_key"), ("web-search", "api_key")}
    copies = SAW / "files/provider-profiles"
    for path in sorted(PROFILES.glob("*.yaml")):
        profile = yaml.safe_load(path.read_text())
        if not profile.get("credentials"):
            continue
        assert (copies / path.name).read_bytes() == path.read_bytes()
        assert set(policy["profiles"][profile["id"]]) == {e["host"] for e in profile["endpoints"]}
    for binding in policy["bindings"]:
        for typ in binding["providers"]:
            for host in policy["profiles"].get(typ, []):
                if "*" not in host:
                    assert host in policy["allowHosts"], (typ, host)


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_proxy_image_requires_digest():
    for image in ("", "quay.io/example/proxy:latest"):
        result = run_helm([HELM, "template", "saw-test", str(SAW), "-n", "saw-test",
                                 "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                                 "--set-string", "credentialProxy.image=" + image],
                                capture_output=True, text=True)
        assert result.returncode != 0
        assert "credentialProxy.image must be a published repo@sha256" in result.stderr


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_provider_metadata_external_secrets_contain_no_key():
    docs = render(ROOT / "charts/pattern-secrets", "--set",
                  "secrets={inference,web-search,inference-openai,inference-anthropic}")
    names = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ExternalSecret"}
    for name, keys in (("inference-meta", {"provider", "model", "url"}),
                       ("web-search-meta", {"provider", "model", "url"}),
                       ("inference-openai-meta", {"provider", "model", "url"}),
                       ("inference-anthropic-meta", {"provider", "model", "url"})):
        assert name in names
        assert set(names[name]["spec"]["target"]["template"]["data"]) == keys
        assert "api_key" not in names[name]["spec"]["target"]["template"]["data"]


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_unattached_search_secret_has_no_proxy_binding_or_mount():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
                  "--set-json", "additionalProviderSecrets=[]")
    configmaps = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ConfigMap"}
    policy = json.loads(configmaps["saw-test-credential-proxy-config"]["data"]["config.json"])
    assert [b["secret"] for b in policy["bindings"]] == ["inference"]
    installer = json.loads(configmaps["saw-test-installer"]["data"]["config.json"])
    assert [b["name"] for b in installer["credentialProxy"]["secrets"]] == ["inference"]
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    volumes = deployment["spec"]["template"]["spec"]["volumes"]
    assert not any(v.get("secret", {}).get("secretName") == "web-search" for v in volumes)


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_gitops_ca_hook_has_a_bounded_failure():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
                  "--set", "cleanupOnDelete=false")
    hook = next(d for d in docs if d["kind"] == "Pod"
                and d["metadata"]["name"] == "saw-credential-proxy-ca-hook")
    assert hook["spec"]["restartPolicy"] == "Never"
    assert hook["spec"]["activeDeadlineSeconds"] == 120


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_gitops_updates_legacy_firewall_before_bootstrapping_the_ca():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"))
    firewall = next(d for d in docs if d["kind"] == "EgressFirewall")
    firewall_annotations = firewall["metadata"]["annotations"]
    assert "argocd.argoproj.io/hook" not in firewall_annotations
    firewall_wave = int(firewall_annotations["argocd.argoproj.io/sync-wave"])
    hooks = [d for d in docs if d["metadata"]["name"] == "saw-credential-proxy-ca-hook"]
    for hook in hooks:
        annotations = hook["metadata"]["annotations"]
        assert annotations["argocd.argoproj.io/hook"] == "Sync"
        assert firewall_wave < int(annotations["argocd.argoproj.io/sync-wave"]) < -1


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_gitops_grants_registry_pull_before_bootstrapping_the_ca():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"))
    pull_binding = next(d for d in docs if d["kind"] == "RoleBinding"
                        and d["roleRef"]["name"] == "system:image-puller")
    assert pull_binding["subjects"] == [{"apiGroup": "rbac.authorization.k8s.io",
                                        "kind": "Group",
                                        "name": "system:serviceaccounts:saw-test"}]
    pull_wave = int(pull_binding["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"])
    hook = next(d for d in docs if d["kind"] == "Pod"
                and d["metadata"]["name"] == "saw-credential-proxy-ca-hook")
    assert pull_wave < int(hook["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"])


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_public_issuer_ca_stays_in_the_guest_mount_list():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
                  "--set", "oidc.clusterCaSecret=saw-ingress-ca",
                  "--set-json", 'credentialProxy.secrets=[{"name":"inference","key":"api_key","providers":["build"]},{"name":"saw-ingress-ca","key":"api_key","providers":["openai"]}]')
    installer = next(d for d in docs if d["kind"] == "ConfigMap"
                     and d["metadata"]["name"] == "saw-test-installer")
    config = json.loads(installer["data"]["config.json"])
    assert config["secrets"] == ["inference", "web-search", "saw-ingress-ca"]
    assert config["caBundleSecret"] == "saw-ingress-ca"
    assert [b["name"] for b in config["credentialProxy"]["secrets"]] == ["inference"]
    proxy = next(d for d in docs if d["kind"] == "ConfigMap"
                 and d["metadata"]["name"] == "saw-test-credential-proxy-config")
    assert [b["secret"] for b in json.loads(proxy["data"]["config.json"])["bindings"]] == ["inference"]


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_gmail_refresh_uses_only_the_shipped_profile_url():
    docs = render(SAW, '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                  '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'),
                  '--set-json', 'additionalProviderSecrets=["gmail"]',
                  '--set-json', 'credentialProxy.secrets=[{"name":"gmail","key":"access_token","providers":["gmail"],"refresh":true}]')
    cm = next(d for d in docs if d['kind'] == 'ConfigMap' and d['metadata']['name'].endswith('credential-proxy-config'))
    [binding] = json.loads(cm['data']['config.json'])['bindings']
    assert binding['refresh'] == {'strategy': 'oauth2_refresh_token', 'tokenURL': 'https://oauth2.googleapis.com/token',
                                  'refreshBeforeSeconds': 300, 'maxLifetimeSeconds': 3600,
                                  'material': {'clientID':'client_id','clientSecret':'client_secret','refreshToken':'refresh_token'}}


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
@pytest.mark.parametrize('types,key', [(['nvidia'], 'api_key'), (['gmail','slack'], 'access_token'), (['gmail'], 'refresh_token')])
def test_invalid_refresh_binding_is_refused(types, key):
    binding = json.dumps([{'name':'gmail','key':key,'providers':types,'refresh':True}])
    result = run_helm([HELM, 'template', 'saw-test', str(SAW), '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                       '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'), '--set-json', 'additionalProviderSecrets=["gmail"]',
                       '--set-json', 'credentialProxy.secrets=' + binding], capture_output=True, text=True)
    assert result.returncode != 0 and 'refresh' in result.stderr


@pytest.mark.ci_external
def test_every_shipped_token_issuer_is_allowlisted():
    allowed = yaml.safe_load((SAW / 'values.yaml').read_text())['egress']['allow']
    from urllib.parse import urlsplit
    for path in PROFILES.glob('*.yaml'):
        for cred in yaml.safe_load(path.read_text()).get('credentials', []):
            if cred.get('refresh'):
                assert urlsplit(cred['refresh']['token_url']).hostname in allowed


@pytest.mark.ci_external
@pytest.mark.skipif(not HELM, reason="helm is not installed")
@pytest.mark.parametrize('mode', ['proxy', 'direct'])
@pytest.mark.parametrize('token_url', ['http://oauth2.googleapis.com/token',
    'https://oauth2.googleapis.com:8443/token', 'https://user@oauth2.googleapis.com/token',
    'https://oauth2.googleapis.com/token?tenant=1', 'https://oauth2.googleapis.com/token#fragment',
    'https://untrusted.example.test/token'])
def test_shipped_refresh_url_is_validated_at_render(tmp_path, token_url, mode):
    chart = tmp_path / 'chart'
    shutil.copytree(SAW, chart)
    path = chart / 'files/provider-profiles/gmail.yaml'
    profile = yaml.safe_load(path.read_text())
    profile['credentials'][0]['refresh']['token_url'] = token_url
    path.write_text(yaml.safe_dump(profile))
    result = run_helm([HELM, 'template', 'saw-test', str(chart),
                       '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                       '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'),
                       '--set', 'credentialProxy.enabled=' + str(mode == 'proxy').lower(),
                       '--set-json', 'additionalProviderSecrets=["gmail"]',
                       '--set-json', 'credentialProxy.secrets=[{"name":"gmail","key":"access_token","providers":["gmail"],"refresh":true}]'],
                      capture_output=True, text=True)
    assert result.returncode != 0 and 'refresh token_url' in result.stderr


@pytest.mark.ci_external
def test_direct_mode_needs_no_image_and_renders_no_proxy_objects():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "--set", "credentialProxy.enabled=false")
    assert not any("credential-proxy" in d["metadata"]["name"] for d in docs)
    vm = next(d for d in docs if d["kind"] == "VirtualMachine")
    vols = vm["spec"]["template"]["spec"]["volumes"]
    sources = {v.get("secret", {}).get("secretName") for v in vols}
    assert {"inference", "web-search"} <= sources
    assert not any(name and name.endswith("-meta") for name in sources)
    slot = next(v for v in vols if v["name"] == "saw-proxy-ca")
    assert slot["configMap"]["name"] == "saw-test-credential-mode"
    cm = next(d for d in docs if d["metadata"]["name"] == "saw-test-credential-mode")
    assert cm["data"] == {"mode": "direct"}
    installer = next(d for d in docs if d["metadata"]["name"] == "saw-test-installer")
    cfg = json.loads(installer["data"]["config.json"])
    assert cfg["credentialMode"] == "direct"
    assert cfg["credentialProxy"] == {"url": "", "markerPrefix": "saw-cred", "secrets": [], "keyGeneration": 1}
    toml = installer["data"]["gateway.toml"]
    for key in ("https_proxy", "proxy_ca_bundle", "proxy_connect_by_hostname"):
        assert key not in toml


@pytest.mark.ci_external
@pytest.mark.parametrize('mode', ['proxy', 'direct'])
@pytest.mark.parametrize('selection', ['unmapped', 'unattached', 'static'])
def test_refresh_egress_ignores_unselected_refresh_providers(mode, selection):
    bindings = [{'name': 'inference', 'key': 'api_key', 'providers': ['nvidia']}]
    if selection != 'unmapped':
        bindings.append({'name': 'mail-credentials', 'key': 'access_token',
                         'providers': ['gmail'], 'refresh': selection != 'static'})
    docs = render(SAW, '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                  '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'),
                  '--set', 'credentialProxy.enabled=' + str(mode == 'proxy').lower(),
                  '--set-json', 'additionalProviderSecrets=' + json.dumps(
                      ['mail-credentials'] if selection == 'static' else []),
                  '--set-json', 'credentialProxy.secrets=' + json.dumps(bindings),
                  '--set-json', 'egress.allow=["integrate.api.nvidia.com"]')
    firewall = next(d for d in docs if d['kind'] == 'EgressFirewall')
    assert not any(r['to'].get('dnsName') == 'oauth2.googleapis.com'
                   for r in firewall['spec']['egress'])


@pytest.mark.ci_external
@pytest.mark.parametrize('mode', ['proxy', 'direct'])
def test_selected_slack_provider_does_not_require_google_egress(mode):
    docs = render(SAW, '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                  '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'),
                  '--set', 'credentialProxy.enabled=' + str(mode == 'proxy').lower(),
                  '--set-json', 'additionalProviderSecrets=["slack"]',
                  '--set-json', 'credentialProxy.secrets=[{"name":"inference","key":"api_key","providers":["nvidia"]},{"name":"slack","key":"bot_token","providers":["slack"]}]',
                  '--set-json', 'egress.allow=["integrate.api.nvidia.com","slack.com"]')
    firewall = next(d for d in docs if d['kind'] == 'EgressFirewall')
    assert not any(r['to'].get('dnsName') == 'oauth2.googleapis.com'
                   for r in firewall['spec']['egress'])


@pytest.mark.ci_external
@pytest.mark.parametrize('mode', ['proxy', 'direct'])
@pytest.mark.parametrize('egress_enabled,issuer_list', [
    (True, 'allow'), (True, 'extraAllow'), (True, 'missing'),
    (False, 'missing'), (False, 'empty')])
def test_selected_refresh_egress_respects_egress_firewall(mode, egress_enabled, issuer_list):
    allowed = [] if issuer_list == 'empty' else ['integrate.api.nvidia.com', 'gmail.googleapis.com']
    extra = []
    if issuer_list == 'allow':
        allowed.append('oauth2.googleapis.com')
    elif issuer_list == 'extraAllow':
        extra.append('oauth2.googleapis.com')
    # Selection follows the provider mapping, even when its Secret is renamed.
    result = run_helm([HELM, 'template', 'saw-test', str(SAW),
                       '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                       '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'),
                       '--set', 'credentialProxy.enabled=' + str(mode == 'proxy').lower(),
                       '--set-json', 'additionalProviderSecrets=["mail-credentials"]',
                       '--set-json', 'credentialProxy.secrets=[{"name":"mail-credentials","key":"access_token","providers":["gmail"],"refresh":true}]',
                       '--set', 'egress.enabled=' + str(egress_enabled).lower(),
                       '--set-json', 'egress.allow=' + json.dumps(allowed),
                       '--set-json', 'egress.extraAllow=' + json.dumps(extra)],
                      capture_output=True, text=True)
    if egress_enabled and issuer_list == 'missing':
        assert result.returncode != 0
        assert 'refresh token_url host must be in egress.allow' in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        docs = [d for d in yaml.safe_load_all(result.stdout) if d]
        firewalls = [d for d in docs if d['kind'] == 'EgressFirewall']
        assert bool(firewalls) == egress_enabled
        if firewalls:
            assert any(r['to'].get('dnsName') == 'oauth2.googleapis.com'
                       for r in firewalls[0]['spec']['egress'])


@pytest.mark.ci_external
@pytest.mark.parametrize('mode', ['proxy', 'direct'])
@pytest.mark.parametrize('selected', [False, True])
def test_refresh_url_safety_only_applies_to_selected_providers(tmp_path, mode, selected):
    chart = tmp_path / 'chart'
    shutil.copytree(SAW, chart)
    path = chart / 'files/provider-profiles/gmail.yaml'
    profile = yaml.safe_load(path.read_text())
    profile['credentials'][0]['refresh']['token_url'] = 'http://oauth2.googleapis.com/token'
    path.write_text(yaml.safe_dump(profile))
    bindings = [{'name': 'inference', 'key': 'api_key', 'providers': ['nvidia']}]
    if selected:
        bindings.append({'name': 'gmail', 'key': 'access_token', 'providers': ['gmail'], 'refresh': True})
    result = run_helm([HELM, 'template', 'saw-test', str(chart),
                       '-f', str(ROOT / 'tests/fixtures/saw-network-topology.yaml'),
                       '-f', str(ROOT / 'tests/fixtures/credential-proxy-values.yaml'),
                       '--set', 'credentialProxy.enabled=' + str(mode == 'proxy').lower(),
                       '--set-json', 'additionalProviderSecrets=' + json.dumps(['gmail'] if selected else []),
                       '--set-json', 'credentialProxy.secrets=' + json.dumps(bindings),
                       '--set', 'egress.enabled=false', '--set-json', 'egress.allow=[]'],
                      capture_output=True, text=True)
    if selected:
        assert result.returncode != 0
        assert 'refresh token_url must be HTTPS' in result.stderr
    else:
        assert result.returncode == 0, result.stderr
