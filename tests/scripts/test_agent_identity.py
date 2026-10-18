"""Compatibility gate reporting must never masquerade as full acceptance."""
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ready_requires_true_ready_condition():
    live = load("test-agent-identity-live")
    assert not live.ready({})
    assert not live.ready({"status": {"conditions": [{"type": "Ready", "status": "False"}]}})
    assert live.ready({"status": {"conditions": [{"type": "Ready", "status": "True"}]}})


def test_tcp_cases_remain_blocked():
    live = load("test-agent-identity-live")
    cases = live.blocked_cases("tcp")
    assert len(cases) == len(live.SCENARIOS)
    assert {c["status"] for c in cases} == {"blocked"}
    assert {c["name"].split("/")[0] for c in cases} == {"tcp"}
    try:
        live.blocked_cases("vsock")
    except ValueError as error:
        assert "tcp" in str(error)
    else:
        raise AssertionError("a non-TCP transport was accepted")
    tcp = [c for c in cases if c["name"].startswith("tcp/")]
    recorded = [c for c in tcp if c["name"].endswith("/bootstrap-failure")]
    assert len(recorded) == 1
    assert "does not execute" in recorded[0]["detail"]
    outage = [c for c in tcp if c["name"].endswith("/infrastructure-outage")]
    assert len(outage) == 1
    assert "does not execute" in outage[0]["detail"]
    lifecycle = [c for c in tcp if c["name"].endswith("/lifecycle-cleanup")]
    assert len(lifecycle) == 1
    assert "does not execute" in lifecycle[0]["detail"]
    disabled = [c for c in tcp if c["name"].endswith("/disabled-mode-live")]
    assert len(disabled) == 1
    assert "does not execute" in disabled[0]["detail"]


def test_exhausted_observation_requires_a_new_reconcile():
    live = load("test-agent-identity-live")
    sample = {"generation": "13", "attempts": "3", "resourceVersion": "6613002",
              "vmi": "0163a2c9", "agentPresent": False, "tokenExpired": True,
              "latestLog": "2026/10/04 06:54:31 retry limit"}
    later = dict(sample, latestLog="2026/10/04 06:55:46 retry limit")
    assert live.exhausted_observation([sample, later]) == "retry limit still enforced"
    try:
        live.exhausted_observation([sample, sample])
    except ValueError as error:
        assert "no new retry-limit" in str(error)
    else:
        raise AssertionError("stale log was accepted")


def test_expiry_denial_requires_fresh_issuance_on_the_same_enrollment():
    live = load("test-agent-identity-live")
    before = {"registrarReady": True, "providers": {"default": "protected"}, "accessExp": 100, "svidExp": 120,
              "generation": "14", "vmi": "vm-1"}
    denied = {"registrarReady": True, "now": 130, "http": 502, "generation": "14", "vmi": "vm-1",
              "agentPresent": True, "credentialsPresent": True}
    restored = {"http": 200, "accessExp": 400, "svidExp": 420, "generation": "14", "vmi": "vm-1",
                "agentPresent": True, "credentialsPresent": True}
    assert "fresh issuance" in live.expiry_denial_result(before, denied, restored)
    denied["http"] = 200
    try:
        live.expiry_denial_result(before, denied, restored)
    except AssertionError as error:
        assert "expired credentials" in str(error)
    else:
        raise AssertionError("expired success was accepted")


def test_research_expiry_requires_a_parsed_failure_and_provider_lists():
    live = load("test-agent-identity-live")
    providers = {"default": "protected saw-demo-cc", "research": "protected saw-demo-cc"}
    before = {"registrarReady": True, "providers": providers, "accessExp": 100, "svidExp": 120,
              "generation": "14", "vmi": "vm-1"}
    denied = {"registrarReady": True, "now": 130, "http": 502, "curlExit": 0,
              "diagnostic": "token_grant_failed", "error": "token_grant_failed",
              "generation": "14", "vmi": "vm-1", "agentPresent": True, "credentialsPresent": True}
    restored = {"providers": providers, "http": 200, "accessExp": 400, "svidExp": 420,
                "generation": "14", "vmi": "vm-1", "agentPresent": True, "credentialsPresent": True}
    assert "without replacing enrollment" in live.research_expiry_result(before, denied, restored)
    denied["http"] = 0
    denied["error"] = "unparsed"
    try:
        live.research_expiry_result(before, denied, restored)
    except AssertionError as error:
        assert "fail-closed" in str(error)
    else:
        raise AssertionError("an unparsed research response was accepted")


def test_cross_vm_rejects_the_other_vms_identity():
    live = load("test-agent-identity-live")
    selectors = {"gateway": ["unix:uid:1000"], "default": ["docker:label:openshell.managed:true"],
                 "research": ["docker:label:openshell.managed:true"]}
    def side(vm, uid):
        expected = "spiffe://saw.test/saw/saw-identity-c/%s/ws/default/sandbox/agent" % vm
        research = expected.replace("/default/", "/research/")
        grant = lambda sub: {"http": 200, "sub": sub, "azp": sub, "client_id": sub, "aud": "saw-protected-service"}
        denied = {"ok": False, "error": "PermissionDenied: no identity issued"}
        return {"vm": vm, "namespace": "saw-identity-c", "trustDomain": "saw.test", "vmUid": uid,
                "agentHash": uid, "agentPresent": True, "parentHash": uid, "admin": False,
                "generation": "1", "guestGeneration": "1", "guestState": "present",
                "paths": ["default", "gateway", "research"], "selectors": selectors,
                "providers": {"default": "protected", "research": "protected"},
                "grants": {"default": grant(expected), "research": grant(research)},
                "attest": {"enforce": "Enforcing", "agentPermissive": False,
                           "contexts": ["system_u:system_r:saw_spire_agent_t:s0"],
                           "unix": {"discover_workload_path": True, "workload_size_limit": -1},
                           "journalRc": 0, "attestorErrors": []},
                "isolation": {"default": {"default": {"ok": True, "sub": expected}, "gateway": denied, "research": denied},
                              "research": {"research": {"ok": True, "sub": research}, "gateway": denied, "default": denied}},
                "cross": {"default": {"gateway": denied, "default": denied, "research": denied},
                          "research": {"gateway": denied, "default": denied, "research": denied}}}
    assert "cross-VM" in live.cross_vm_result(side("identity-c", "uid-c"), side("identity-d", "uid-d"))


def test_supervisor_probe_requires_registered_peer_and_hidden_workload_socket():
    live = load("test-agent-identity-live")
    own = lambda ws: {"ok": True, "sub": "spiffe://test/saw/ns/vm/ws/%s/sandbox/agent" % ws}
    denied = {"ok": False, "denied": True, "error": "PermissionDenied: no identity issued"}
    probes = {"default": {"default": own("default"), "gateway": denied, "research": denied},
              "research": {"research": own("research"), "gateway": denied, "default": denied}}
    sockets = {"default": {"hidden": True}, "research": {"hidden": True}}
    assert "peer identities are rejected" in live.supervisor_identity_result(
        ["gateway", "default", "research"], probes, sockets)
    probes["research"]["default"] = {"ok": False, "error": "socket unavailable"}
    try:
        live.supervisor_identity_result(["gateway", "default", "research"], probes, sockets)
    except AssertionError as error:
        assert "not denied" in str(error)
    else:
        raise AssertionError("an unavailable socket was accepted as selector rejection")
    probes["research"]["default"] = denied
    sockets["default"]["hidden"] = False
    try:
        live.supervisor_identity_result(["gateway", "default", "research"], probes, sockets)
    except AssertionError as error:
        assert "workload can access" in str(error)
    else:
        raise AssertionError("a workload-visible socket was accepted")


def test_vm_recreate_requires_a_new_parent_and_rejects_peer_identities():
    live = load("test-agent-identity-live")
    selectors = {"gateway": ["unix:uid:1000"], "default": ["docker:label:openshell.managed:true"],
                 "research": ["docker:label:openshell.managed:true"]}
    peers = [{"namespace": "saw-alice", "vm": "alice", "pathHash": "peer", "present": True, "banned": False}]
    before = {"vmUid": "old", "agentHash": "old-agent", "selectors": selectors, "peers": peers}
    removed = {"agentBanned": True, "entryIds": [], "peers": peers}
    grant = {"http": 200, "sub": "spiffe://example/sandbox", "azp": "spiffe://example/sandbox",
             "client_id": "spiffe://example/sandbox", "aud": "saw-protected-service"}
    created = {"vmUid": "new", "agentHash": "new-agent", "parentHash": "new-agent", "agentPresent": True,
               "agentBanned": False, "generation": "1", "guestGeneration": "1", "guestState": "present",
               "selectors": selectors, "admin": False, "paths": ["default", "gateway", "research"],
               "providers": {"default": "protected", "research": "protected"},
               "entryIds": ["e1", "e2", "e3"],
               "grants": {"default": grant, "research": dict(grant)},
               "isolation": {"default": {"default": {"ok": True, "sub": grant["sub"]},
                                         "gateway": {"ok": False, "error": "denied"},
                                         "research": {"ok": False, "error": "denied"}},
                             "research": {"research": {"ok": True, "sub": grant["sub"]},
                                          "gateway": {"ok": False, "error": "denied"},
                                          "default": {"ok": False, "error": "denied"}}}}
    later = {"entryIds": ["e1", "e2", "e3"], "vmUid": "new", "generation": "1", "oldEntryIds": [],
             "oldAgentBanned": True, "peers": peers}
    assert "exclusively" in live.vm_recreate_result(before, removed, created, later)
    created["isolation"]["default"]["gateway"] = {"ok": True, "sub": "gateway"}
    try:
        live.vm_recreate_result(before, removed, created, later)
    except AssertionError as error:
        assert "not rejected" in str(error)
    else:
        raise AssertionError("a fetched gateway identity was accepted")


def test_profile_removal_keeps_the_same_agent():
    live = load("test-agent-identity-live")
    selectors = ["docker:label:openshell.managed:true"]
    before = {"registrarReady": True, "paths": ["default", "gateway", "research"],
              "parentHash": "abc", "agentHash": "abc", "generation": "14", "vmi": "vm-1",
              "selectors": selectors, "accessExp": 100}
    held = {"registrarReady": False, "paths": ["default", "gateway", "research"],
            "generation": "14", "vmi": "vm-1"}
    removed = {"paths": ["default", "gateway"], "parentHash": "abc", "agentPresent": True,
               "generation": "14", "vmi": "vm-1"}
    denied = {"now": 130, "accessExp": 100, "researchHttp": 502, "researchSvid": "fetch",
              "defaultHttp": 200}
    restored = {"generation": "14", "vmi": "vm-1", "paths": ["default", "gateway", "research"],
                "parentHash": "abc", "selectors": selectors, "admin": False,
                "researchHttp": 200, "accessExp": 400}
    assert "same agent" in live.profile_removal_result(before, held, removed, denied, restored)
    removed["paths"] = ["default", "gateway", "research"]
    try:
        live.profile_removal_result(before, held, removed, denied, restored)
    except AssertionError as error:
        assert "not removed" in str(error)
    else:
        raise AssertionError("a remaining research registration was accepted")


def test_upgrade_is_idempotent_and_disable_revokes_identity():
    live = load("test-agent-identity-live")
    before = {"vmUid": "vm", "vmi": "vmi", "generation": "1", "agentHash": "abc",
              "entryIds": ["e1", "e2", "e3"], "helmRevision": 1, "agentPresent": True,
              "guestState": "present", "optedIn": True}
    after = dict(before, helmRevision=2)
    assert "preserved" in live.upgrade_idempotent_result(before, after)
    changed = dict(after, generation="2")
    try:
        live.upgrade_idempotent_result(before, changed)
    except AssertionError as error:
        assert "generation" in str(error)
    else:
        raise AssertionError("an enrollment change was accepted as idempotent")
    disabled = {"vmUid": "vm", "optedIn": False, "entryIds": [], "agentBanned": True,
                "agentUnit": False, "agentActive": False, "vmReady": True,
                "recoveryAttempts": ""}
    assert "revoked" in live.disabled_mode_result(before, disabled)
    try:
        live.disabled_mode_result(before, dict(disabled, agentUnit=True))
    except AssertionError as error:
        assert "still installed" in str(error)
    else:
        raise AssertionError("a leftover identity unit was accepted")


def test_networkpolicy_must_stop_and_restore_guest_traffic():
    live = load("test-agent-identity-live")
    before = {"identity-c": "ok", "identity-d": "ok"}
    denied = {"identity-c": "TimeoutError", "identity-d": "TimeoutError"}
    restored = dict(before)
    scope = {"policyPresent": False, "spireReady": True,
             "policiesBefore": [("other", "allow")], "policiesAfter": [("other", "allow")],
             "vmUids": [("saw-alice", "alice", "u1")], "vmUidsAfter": [("saw-alice", "alice", "u1")]}
    assert "dedicated namespace" in live.networkpolicy_result(before, denied, restored, scope)
    try:
        live.networkpolicy_result(before, before, restored, scope)
    except AssertionError as error:
        assert "did not stop" in str(error)
    else:
        raise AssertionError("an ineffective NetworkPolicy was accepted")
    scope["policyPresent"] = True
    try:
        live.networkpolicy_result(before, denied, restored, scope)
    except AssertionError as error:
        assert "left in place" in str(error)
    else:
        raise AssertionError("a leftover NetworkPolicy was accepted")


def test_operator_restore_deletes_only_the_retry_annotation():
    live = load("test-agent-identity-live")
    state = {"context": "test", "namespace": "saw-identity-b", "secret": "identity-b-spire-join-token",
             "attempts": "3", "agentPresent": False, "tokenExpired": True, "faultPresent": False}
    assert live.operator_restore_command(state) == [
        "oc", "--context", "test", "annotate", "-n", "saw-identity-b",
        "secret/identity-b-spire-join-token", "saw.redhat.com/recovery-attempts-"]
    for broken in (dict(state, faultPresent=True), dict(state, attempts="2"),
                   dict(state, agentPresent=True), dict(state, tokenExpired=False)):
        try:
            live.operator_restore_command(broken)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe restore was accepted")


def test_preflight_failure_writes_report_without_cleanup(monkeypatch, tmp_path):
    live = load("test-agent-identity-live")
    calls = []

    def command(args, stdin=None):
        calls.append(args)
        if args[0] == "git":
            return "abc" if "rev-parse" in args else ""
        raise subprocess.CalledProcessError(1, args, stderr="potentially sensitive diagnostic")

    monkeypatch.setattr(live, "command", command)
    assert live.run(SimpleNamespace(context="test", namespace_prefix="saw-test",
                                    artifact_dir=tmp_path, transport="tcp")) == 1
    report = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert report["acceptanceComplete"] is False
    assert report["status"] == "fail"
    assert "potentially sensitive" not in json.dumps(report)
    assert not any("delete" in c for c in calls)


def test_empty_context_is_refused(tmp_path):
    for script, extra in (
        ("deploy-spire-identity.py", ["--values", str(tmp_path)]),
        ("test-agent-identity-live.py", ["--namespace-prefix", "test", "--transport", "tcp",
                                         "--artifact-dir", str(tmp_path)]),
    ):
        import sys
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / script),
                                 "--context", "", *extra], capture_output=True, text=True)
        assert result.returncode == 2
