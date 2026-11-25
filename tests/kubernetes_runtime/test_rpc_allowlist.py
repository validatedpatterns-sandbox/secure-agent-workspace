"""The gateway adapter refuses RPCs it does not list; test fakes accept any."""
import re
from pathlib import Path

import saw_kubernetes
from saw_kubernetes.adapters import RPC_METHODS


def test_every_rpc_the_runtime_calls_is_allowed():
    called = set()
    for source in Path(saw_kubernetes.__file__).parent.glob("*.py"):
        called |= set(re.findall(r'(?:\.call|_mutate)\(\s*"([A-Z][A-Za-z]+)"', source.read_text()))
    assert {"ListProviderProfiles", "UpdateProvider", "ConfigureProviderRefresh",
            "RotateProviderCredential", "GetProviderRefreshStatus"} <= called
    assert called <= RPC_METHODS
