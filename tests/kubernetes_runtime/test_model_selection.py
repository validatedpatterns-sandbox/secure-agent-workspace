import json

import pytest

from saw_kubernetes.prepare_gate import publish_model, verify


def test_publication_fences_stale_and_conflicting_jobs(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for generation, model in [(1, "first"), (2, "second"), (1, "first"), (2, "second")]:
        publish_model(tmp_path, bundle, model, generation)
    assert json.loads((bundle / "model.json").read_text()) == {"generation": 2, "model": "second"}
    verify(bundle, {}, model_selector=True)
    with pytest.raises(ValueError, match="conflicting"):
        publish_model(tmp_path, bundle, "different", 2)
    with pytest.raises(ValueError, match="invalid"):
        publish_model(tmp_path, bundle, "../outside", 3)
    (bundle / "unexpected").touch()
    with pytest.raises(ValueError):
        verify(bundle, {}, model_selector=True)
