"""Synthetic offline fixtures: never load developer credentials or kubeconfigs."""

from pathlib import Path
import importlib.util
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def installer():
    spec = importlib.util.spec_from_file_location("saw_release_apply_bom", ROOT / "installer/apply_bom.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def enrollment():
    return yaml.safe_load((ROOT / "examples/saw/enrollment.yaml").read_text())


@pytest.fixture
def golden_image():
    return {
        "apiVersion": "saw.redhat.com/v1alpha1", "kind": "SawGoldenImage",
        "metadata": {"name": "test-release"},
        "spec": {"namespace": "saw-images",
                 "registryURL": "docker://registry.example.test/saw-vm@sha256:" + "a" * 64,
                 "registrySecret": "import-pull", "caConfigMap": "import-ca",
                 "diskSizeGi": 40, "storageClass": "test-csi"},
    }


@pytest.fixture
def profile_inputs():
    selections = [{"profileRef": {"name": "data-science", "configMapRef": {"name": "profiles"}},
                   "credentialBindings": {
                       "inference-main": {"secretRef": {"name": "nvidia", "key": "api_key"}}}}]
    docs = {
        "workspace.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Workspace",
                           "metadata": {"name": "default"},
                           "spec": {"inference": {"provider": "nvidia", "model": "test-model"}}},
        "providers.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Providers",
                           "metadata": {"profile": "data-science"},
                           "spec": {"providers": [{"name": "nvidia", "type": "nvidia",
                                                   "credentialRef": "inference-main"}]}},
        "sandbox.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Sandboxes",
                         "metadata": {}, "spec": {"sandboxes": [{
                             "name": "notebook", "type": "openclaw", "providers": ["nvidia"],
                             "image": "registry.example.test/test@sha256:" + "b" * 64,
                             "data": {"name": "notebook-data", "mountPath": "/sandbox/persist",
                                      "retainOnDelete": True}}]}},
    }
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "profiles", "namespace": "saw-test"},
          "data": {f"profiles__data-science__default__{file}": yaml.safe_dump(doc)
                   for file, doc in docs.items()}}
    return selections, [cm]
