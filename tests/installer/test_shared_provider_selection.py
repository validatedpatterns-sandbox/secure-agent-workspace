"""Agent onboarding choices shared by VM and Kubernetes adapters."""
from dataclasses import asdict

import pytest


def test_selection_prefers_declared_model_without_crossing_attachment_boundary(ab):
    unrelated = ab.Provider("unrelated", "openai", model="wrong")
    first = ab.Provider("first", "openai")
    second = ab.Provider("second", "nvidia", model="right")
    providers = [unrelated, first, second]
    before = [asdict(p) for p in providers]
    assert ab.select_inference_provider(providers, ["first", "second"]) is second
    assert ab.select_inference_provider(providers, ["first"]) is first
    assert ab.select_inference_provider(providers, ["absent"]) is None
    assert [asdict(p) for p in providers] == before


def test_attachment_order_wins_over_workspace_order(ab):
    first = ab.Provider("first", "openai", model="one")
    second = ab.Provider("second", "openai", model="two")
    assert ab.select_inference_provider([first, second], ["second", "first"]) is second
    first.model = second.model = ""
    assert ab.select_inference_provider([first, second], ["second", "first"]) is second


def test_explicit_reference_never_falls_back(ab):
    chosen = ab.Provider("chosen", "openai")
    fallback = ab.Provider("fallback", "nvidia", model="other")
    select = ab.select_inference_provider
    assert select([fallback, chosen], ["fallback", "chosen"], inference_ref="chosen") is chosen
    assert select([fallback], ["fallback", "chosen"], inference_ref="chosen") is None
    assert select([fallback, chosen], ["fallback", "chosen"], inference_ref="missing") is None


@pytest.mark.parametrize("options", [{"enabled": False}, {"credential_free": True}])
def test_unavailable_or_keyless_provider_cannot_onboard_agent(ab, options):
    excluded = ab.Provider("excluded", "openai", model="must-not-use", **options)
    allowed = ab.Provider("allowed", "nvidia")
    select = ab.select_inference_provider
    assert select([excluded, allowed], ["excluded", "allowed"]) is allowed
    assert select([excluded, allowed], ["excluded", "allowed"], inference_ref="excluded") is None
    assert select([excluded], []) is None


def test_legacy_empty_attachments_preserve_available_candidate_order(ab):
    first = ab.Provider("first", "openai")
    second = ab.Provider("second", "nvidia", model="legacy")
    assert ab.select_inference_provider([first, second], []) is second
    second.model = ""
    assert ab.select_inference_provider([first, second], []) is first
    assert ab.select_inference_provider([], []) is None


def test_vm_adapter_keeps_skipped_providers_unavailable(ab):
    applier = object.__new__(ab.ProfileApplier)
    applier.skipped = {("team", "chosen")}
    chosen = ab.Provider("chosen", "openai", model="one")
    fallback = ab.Provider("fallback", "nvidia", model="two")
    ws = ab.Workspace("team", providers=[chosen, fallback])
    sb = ab.Sandbox("chat", providers=["chosen", "fallback"],
                    inference_values={"providerRef": "chosen"})
    assert applier.find_provider(ws, sb.providers, sb) is None
    sb.inference_values = {}
    assert applier.find_provider(ws, sb.providers, sb) is fallback


def test_vm_reexports_canonical_selection_and_onboarding_helpers(ab):
    for name in ("select_inference_provider", "sandbox_protocol", "sandbox_model",
                 "sandbox_endpoint", "openclaw_inference_settings", "NATIVE_BASE_URLS",
                 "PROTOCOL_NATIVE_BASE_URLS", "OPENCLAW_AUTH_CHOICES"):
        assert getattr(ab, name) is getattr(ab._saw_core, name)


@pytest.mark.parametrize("provider, inference, expected", [
    ({"type": "openai"}, {}, ("https://api.openai.com/v1", "openai", "openai-api-key")),
    ({"type": "anthropic"}, {}, ("", "anthropic", "apiKey")),
    ({"type": "nvidia"}, {}, ("https://integrate.api.nvidia.com/v1", "openai", None)),
    ({"type": "openai", "base_url_secret_key": "url"}, {},
     ("https://api.openai.com/v1", "openai", None)),
    ({"type": "openai"}, {"protocol": "openai", "baseUrl": ""},
     ("https://api.openai.com/v1", "openai", "openai-api-key")),
    ({"type": "openai"}, {"protocol": "openai", "baseUrl": "https://api.openai.com/v1"},
     ("https://api.openai.com/v1", "openai", None)),
    ({"type": "custom-inference"}, {"protocol": "openai", "baseUrl": ""},
     ("https://api.openai.com/v1", "openai", None)),
    ({"type": "custom-inference"}, {"protocol": "anthropic", "baseUrl": "https://models.example/v1"},
     ("https://models.example/v1", "anthropic", None)),
])
def test_onboarding_endpoint_and_native_auth_choices(ab, provider, inference, expected):
    p = ab.Provider("inference", **provider)
    sb = ab.Sandbox("chat", inference_values={"model": "resolved", **inference} if inference else {})
    settings = ab.openclaw_inference_settings(sb, p)
    assert (settings["base_url"], settings["protocol"], settings["auth_choice"]) == expected
    assert settings["model"] == ("resolved" if inference else "nvidia/nemotron-3.5-lightning-30b-a3b")


def test_resolved_model_and_endpoint_override_legacy_fields(ab):
    provider = ab.Provider("inference", "openai", model="provider-model", base_url="https://legacy.example/v1")
    sb = ab.Sandbox("chat", model="sandbox-model")
    assert ab.sandbox_model(sb, provider) == "sandbox-model"
    sb.model = ""
    assert ab.sandbox_model(sb, provider) == "provider-model"
    sb.inference_values = {"model": "resolved-model", "protocol": "openai", "baseUrl": "https://new.example/v1"}
    settings = ab.openclaw_inference_settings(sb, provider)
    assert settings == {"model": "resolved-model", "protocol": "openai", "base_url": "https://new.example/v1", "auth_choice": None}
    assert provider.base_url == "https://legacy.example/v1"
