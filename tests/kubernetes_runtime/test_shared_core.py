"""Cross-backend identity belongs to the suite that ships both adapters."""
import importlib.util
from pathlib import Path
import sys

from saw_kubernetes.core import shared, admin


def test_vm_and_kubernetes_load_the_same_canonical_module(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    path = root / "charts/openshell-saw/files/installer/apply_bom.py"
    spec = importlib.util.spec_from_file_location("test_saw_vm_installer", path)
    installer = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, installer)
    spec.loader.exec_module(installer)
    assert shared is installer._saw_core
    assert shared.Profile is installer.Profile
    assert shared.InstallerError is installer.InstallerError

    assert admin is installer._saw_admin
