from saw_kubernetes import provider as governed


def test_brave_search_uses_shipped_governance_profile():
    slot, hosts = governed.requirements("brave")

    assert slot["name"] == "api_key"
    assert slot["env_vars"] == ["BRAVE_API_KEY"]
    assert hosts == ["api.search.brave.com"]

    credentials = {"BRAVE_API_KEY": "saw-cred.web-search.api_key"}
    policy = {
        "markerPrefix": "saw-cred",
        "profiles": {"brave": hosts},
        "allowHosts": hosts,
        "bindings": [{"providers": ["brave"], "secret": "web-search", "key": "api_key"}],
    }

    assert governed.check_policy("brave", credentials, policy)
    assert not governed.check_policy("brave", credentials, {**policy, "allowHosts": []})
