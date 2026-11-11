from pathlib import Path
import runpy
from unittest.mock import Mock
import uuid

import pytest

from saw_kubernetes.reconcile import RpcError


bind = runpy.run_path(str(Path(__file__).resolve().parents[2] / "charts/saw-workspace-relay/files/bind.py"))["bind"]
wid = str(uuid.UUID(int=1))
meta = {"id": wid, "name": "default"}
admin = {"principal_subject": "owner", "role": "WORKSPACE_ROLE_ADMIN"}
reader = {"principal_subject": "relay", "role": "WORKSPACE_ROLE_USER"}


def run(responses):
    gateway = Mock()
    gateway.call.side_effect = responses
    bind(gateway, "default", "", "relay", "owner", "registration", True, sleep=lambda _: None)
    return [call.args[0] for call in gateway.call.call_args_list]


def test_controller_creates_workspace_before_assigning_owner():
    workspace = {"workspace": {"metadata": meta}}
    calls = run([RpcError("NOT_FOUND"), workspace, {"members": []}, workspace, {"members": [admin]},
                 {}, {"members": [admin, reader]}])
    assert calls.count("AddWorkspaceMember") == 1
    assert calls[-2:] == ["AddWorkspaceMember", "ListWorkspaceMembers"]


@pytest.mark.parametrize("responses, error", [
    ([{"workspace": {"metadata": meta}}, {}, {"workspace": {"metadata": {**meta, "id": str(uuid.UUID(int=2))}}}],
     "workspace identity mismatch"),
    ([{"workspace": {"metadata": meta}}, {"members": [{**reader, "principal_subject": "owner"}]}], "owner mismatch"),
    ([{"workspace": {"metadata": meta}}, {"members": [{**admin, "principal_subject": "other"}]}], "unexpected membership"),
])
def test_binding_denies_replacement_or_unexpected_roles(responses, error):
    with pytest.raises(ValueError, match=error):
        run(responses)
