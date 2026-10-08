"""Ownership checks for the pattern teardown scripts."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fake_oc(tmp_path, namespaces, resources, objects):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "namespaces.json").write_text(json.dumps({"items": namespaces}))
    (fixtures / "resources.txt").write_text("\n".join(resources) + "\n")
    for name, items in objects.items():
        (fixtures / f"{name}.json").write_text(json.dumps({"items": items}))
    oc = bindir / "oc"
    oc.write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  api-resources) cat "${OC_FIXTURES}/resources.txt" ;;
  get)
    if [[ "$2" == namespaces ]]; then
      cat "${OC_FIXTURES}/namespaces.json"
    else
      cat "${OC_FIXTURES}/$2.json"
    fi ;;
  annotate|delete|wait) printf '%s\\n' "$*" >> "${OC_LOG}" ;;
  *) printf 'unexpected oc call: %s\\n' "$*" >&2; exit 9 ;;
esac
''')
    oc.chmod(0o755)
    log = tmp_path / "oc.log"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               OC_FIXTURES=str(fixtures), OC_LOG=str(log))
    return env, log


def test_pre_uninstall_deletes_only_pattern_owned_gateway(tmp_path):
    namespaces = [
        {"metadata": {"name": "saw-alice", "labels": {
            "openshell.pattern/saw": "true", "openshell.pattern/owner": "alice",
            "argocd.argoproj.io/managed-by": "vp-gitops"}}},
        {"metadata": {"name": "saw-bob", "labels": {
            "openshell.pattern/saw": "true", "openshell.pattern/owner": "bob"}}},
    ]
    vm = {"metadata": {"name": "alice", "labels": {
        "app.kubernetes.io/instance": "alice"}}}
    env, log = fake_oc(tmp_path, namespaces,
                       ["virtualmachines.kubevirt.io", "datavolumes.cdi.kubevirt.io",
                        "virtualmachineinstances.kubevirt.io"],
                       {"vm": [vm], "vmi": []})
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-pre-uninstall.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 2
    assert any("delete vm alice -n saw-alice" in call for call in calls)
    assert any("delete dv alice-root -n saw-alice" in call for call in calls)
    assert all("--all" not in call and "saw-bob" not in call for call in calls)


def test_operator_cleanup_keeps_unowned_resources(tmp_path):
    owned = {"metadata": {"name": "owned", "labels": {
        "argocd.argoproj.io/instance": "openshift-cnv"}}}
    other = {"metadata": {"name": "other", "labels": {}}}
    kinds = ["hyperconvergeds.hco.kubevirt.io",
             "subscriptions.operators.coreos.com",
             "clusterserviceversions.operators.coreos.com",
             "installplans.operators.coreos.com"]
    env, log = fake_oc(tmp_path, [{"metadata": {"name": "openshift-cnv"}}],
                       kinds, {kind: [owned, other] for kind in kinds})
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-operator-cleanup.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == len(kinds)
    assert all(" owned -n openshift-cnv " in call for call in calls)
    assert all("--all" not in call and " other " not in call for call in calls)


def test_operator_cleanup_removes_orphaned_hco_crd(tmp_path):
    namespace = {"metadata": {"name": "openshift-cnv", "annotations": {
        "argocd.argoproj.io/tracking-id":
            "secure-agent-workspace-prod:/Namespace:patterns-operator/openshift-cnv"}}}
    crd = {"metadata": {"annotations": {
        "openshell.pattern/cleanup-on-uninstall": "secure-agent-workspace-prod"},
        "labels": {
        "olm.managed": "true",
        "operators.coreos.com/kubevirt-hyperconverged.openshift-cnv": ""}}}
    env, log = fake_oc(tmp_path, [namespace], [], {
        "crd": [crd],
        "hyperconvergeds.hco.kubevirt.io": [],
        "subscriptions.operators.coreos.com": [],
    })
    # The CRD lookup returns one object, unlike list lookups.
    (tmp_path / "fixtures" / "crd.json").write_text(json.dumps(crd))
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-operator-cleanup.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert "wait --for=delete namespace/openshift-cnv --timeout=180s" in calls
    assert "delete crd hyperconvergeds.hco.kubevirt.io --wait=true" in calls


def test_operator_cleanup_preserves_crd_with_hco(tmp_path):
    namespace = {"metadata": {"name": "openshift-cnv", "annotations": {
        "argocd.argoproj.io/tracking-id":
            "secure-agent-workspace-prod:/Namespace:patterns-operator/openshift-cnv"}}}
    crd = {"metadata": {"annotations": {
        "openshell.pattern/cleanup-on-uninstall": "secure-agent-workspace-prod"},
        "labels": {
        "olm.managed": "true",
        "operators.coreos.com/kubevirt-hyperconverged.openshift-cnv": ""}}}
    env, log = fake_oc(tmp_path, [namespace], [], {
        "crd": [],
        "hyperconvergeds.hco.kubevirt.io": [
            {"metadata": {"name": "other-hco"}}],
        "subscriptions.operators.coreos.com": [],
    })
    (tmp_path / "fixtures" / "crd.json").write_text(json.dumps(crd))
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-operator-cleanup.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "delete crd" not in log.read_text()


def test_operator_cleanup_removes_marked_crd_after_namespace_is_gone(tmp_path):
    crd = {"metadata": {"annotations": {
        "openshell.pattern/cleanup-on-uninstall": "secure-agent-workspace-prod"},
        "labels": {
            "olm.managed": "true",
            "operators.coreos.com/kubevirt-hyperconverged.openshift-cnv": "",
        }}}
    env, log = fake_oc(tmp_path, [], [], {
        "hyperconvergeds.hco.kubevirt.io": [],
        "subscriptions.operators.coreos.com": [],
    })
    (tmp_path / "fixtures" / "crd.json").write_text(json.dumps(crd))
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-operator-cleanup.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert "delete crd hyperconvergeds.hco.kubevirt.io --wait=true" in calls
    assert not any(call.startswith("wait ") for call in calls)


def test_operator_cleanup_keeps_unmarked_crd_after_namespace_is_gone(tmp_path):
    crd = {"metadata": {"labels": {
        "olm.managed": "true",
        "operators.coreos.com/kubevirt-hyperconverged.openshift-cnv": ""}}}
    env, log = fake_oc(tmp_path, [], [], {})
    (tmp_path / "fixtures" / "crd.json").write_text(json.dumps(crd))
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-operator-cleanup.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not log.exists()


def test_cnv_mark_preserves_ownership_before_namespace_removal(tmp_path):
    namespace = {"metadata": {"annotations": {
        "argocd.argoproj.io/tracking-id":
            "secure-agent-workspace-prod:/Namespace:patterns-operator/openshift-cnv"}}}
    crd = {"metadata": {"labels": {
        "olm.managed": "true",
        "operators.coreos.com/kubevirt-hyperconverged.openshift-cnv": ""}}}
    env, log = fake_oc(tmp_path, [], [], {})
    (tmp_path / "fixtures" / "namespace.json").write_text(json.dumps(namespace))
    (tmp_path / "fixtures" / "crd.json").write_text(json.dumps(crd))
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-cnv-mark.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "annotate crd hyperconvergeds.hco.kubevirt.io " in log.read_text()


def test_cnv_mark_keeps_crd_for_unowned_namespace(tmp_path):
    namespace = {"metadata": {"annotations": {}}}
    env, log = fake_oc(tmp_path, [], [], {})
    (tmp_path / "fixtures" / "namespace.json").write_text(json.dumps(namespace))
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-cnv-mark.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not log.exists()
