"""Quickstart UI routes follow the selected SAW-BOM profiles."""

from pathlib import Path

import pytest

from importlib.util import module_from_spec, spec_from_file_location


ROOT = Path(__file__).resolve().parents[2]
spec = spec_from_file_location("sandbox_ui_values", ROOT / "scripts/sandbox-ui-values.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def test_default_profile_creates_enabled_ui_routes():
    routes = module.ui_routes(ROOT / "charts/saw-bom/profiles", "data-science")
    assert routes == [
        {"workspace": "cuda-dev", "sandbox": "cuda-sandbox",
         "proxyPort": 4201, "forwardPort": 14201},
        {"workspace": "default", "sandbox": "notebook",
         "proxyPort": 4202, "forwardPort": 14202},
    ]


def test_duplicate_profile_routes_are_deduplicated():
    routes = module.ui_routes(ROOT / "charts/saw-bom/profiles",
                              "data-science,custom-inference")
    assert len(routes) == 2


def test_unknown_profile_fails():
    with pytest.raises(ValueError, match="does not exist"):
        module.ui_routes(ROOT / "charts/saw-bom/profiles", "unknown")
