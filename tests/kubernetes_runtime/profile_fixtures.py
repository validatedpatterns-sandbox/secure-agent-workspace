"""Synthetic bindings for the actual Helm-rendered BOMs; no cluster workload."""
import base64
from pathlib import Path
import subprocess

import yaml

from saw_kubernetes.core import shared
from saw_kubernetes.harness import read_bundles

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "example.test/agent@sha256:" + "a" * 64


def browser_slot():
    def pvc(name, read_only):
        return {"claimName": name, "uid": "test-" + name, "readOnly": read_only}

    # Public SPKI for a fixture writer. No signing or provider key in the test.
    key = base64.b64encode(bytes.fromhex("302a300506032b6570032100") + bytes(range(32))).decode()
    return {
        "workspace": pvc("workspace-fixture", False),
        "browser": {"origin": "https://fixture.example", "ownerLogin": "fixture"},
        "toolGate": {
            "receiptKey": key,
            "ownerLogin": "fixture",
            "trusted": pvc("saw-gate-fixture", True),
            "audit": pvc("saw-audit-fixture", False),
        },
    }


def briefing_inputs(image=IMAGE):
    manifests = subprocess.check_output(["helm", "template", "fixture", str(ROOT/"charts/saw-bom"),
        "--set", "profiles[0]=personal-assistant", "--set", "harnessEnabled=true",
        "--set-string", "imageOverrides.assistant="+image], text=True)
    files = yaml.safe_load(manifests)["data"]
    docs, raw, index = shared.split_bom_files(files)
    bundle = read_bundles(raw, index)["daily-briefing"]
    slot = browser_slot()
    slot["toolGate"]["harness"] = {"name": bundle.name, "digest": bundle.digest}
    ws, = shared.parse_profiles(docs)[0].workspaces
    bindings = [{"secret":p.credential_secret,"key":p.credential_secret_key,"type":p.type,
                 "refresh": bool(p.refresh_strategy)} for p in ws.providers if p.enabled]
    cfg = dict(ownerID="b032b2e4-2cd5-47a7-8ef8-ac73e15700b1",namespace="saw-fixture",
               namespaceUID="fixture-ns",ownerSubject="fixture-subject",mode="container",gatewayVersion="0.1.2-rhaiv.6",
               approvedCredentialFreeProviders=[],proxyBindings=bindings,bindings={"personal-assistant/assistant":slot})
    return files, cfg


def fixture_inputs():
    site = yaml.safe_load((ROOT / "tests/fixtures/container-site.yaml").read_text())
    owner, = site["portal"]["containerSites"].values()
    image = owner["profileImageOverrides"]["data-science"]["notebook"]
    rendered = subprocess.check_output(["helm", "template", "fixture", str(ROOT/"charts/saw-bom"),
        "--set", "profiles[0]=custom-inference", "--set", "webSearch.enabled=false",
        "--set-string", "imageOverrides.notebook="+image], text=True)
    cfg = dict(namespace="saw-fixture", namespaceUID="fixture", ownerSubject="fixture-owner", mode="container",
               ownerID="b032b2e4-2cd5-47a7-8ef8-ac73e15700b1", gatewayVersion="0.1.2-rhaiv.6",
               approvedCredentialFreeProviders=[],
               proxyBindings=[{"type":"custom-inference","secret":"inference","key":"api_key","refresh":False}],
               customInferenceURL="https://models.fixture.test/v1", modelInputs={"inference.model":"fixture/model"},
               bindings={"default/notebook":browser_slot()})
    return yaml.safe_load(rendered)["data"], cfg
