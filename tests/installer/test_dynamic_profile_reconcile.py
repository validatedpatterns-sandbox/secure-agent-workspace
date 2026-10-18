"""Approved dynamic profiles follow changes on the installer disk."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


def desired_profile(host="demo.default.svc.cluster.local"):
    return {
        "id": "saw-demo-cc",
        "endpoints": {"host": host, "port": 8080},
        "credentials": [{
            "name": "access",
            "token_grant": {
                "grant_type": "client_credentials",
                "token_endpoint": f"http://{host}:8080/token",
                "cache_ttl_seconds": 30,
            },
        }],
    }


def exported_profile(desired, *, version=1, scope="workspace", source="user"):
    current = yaml.safe_load(yaml.safe_dump(desired))
    grant = current["credentials"][0]["token_grant"]
    grant.pop("grant_type")
    grant["cache_ttl"] = f"{grant.pop('cache_ttl_seconds')}s"
    current.update(resource_version=version, scope=scope, source=source)
    return current


def applier(ab, document):
    return ab.ProfileApplier(ab.Shell(), {"mtlsGateway": "saw-installer"}, {},
                             {"saw-demo-cc": yaml.safe_dump(document)})


def test_matching_dynamic_profile_does_not_update(ab):
    desired = desired_profile()
    instance = applier(ab, desired)
    calls = []

    def cli(*args, **kwargs):
        calls.append((args, kwargs))
        return ab.Result(0, yaml.safe_dump(exported_profile(desired)))

    instance.cli = cli
    instance.reconcile_dynamic_profile(SimpleNamespace(name="default"), "saw-demo-cc")
    assert len(calls) == 1
    assert calls[0][0][:3] == ("provider", "profile", "export")
    assert calls[0][1]["force"] is True
    assert ("profile", "default", "saw-demo-cc") in instance.desired


def test_matching_token_exchange_profile_does_not_update(ab):
    desired = desired_profile()
    grant = desired["credentials"][0]["token_grant"]
    grant["grant_type"] = "token_exchange"
    grant["subject_token"] = {"source": "provider_credential",
                              "credential": "subject_token"}
    current = exported_profile(desired)
    instance = applier(ab, desired)
    calls = []

    def cli(*args, **kwargs):
        calls.append(args)
        return ab.Result(0, yaml.safe_dump(current))

    instance.cli = cli
    instance.reconcile_dynamic_profile(SimpleNamespace(name="default"), "saw-demo-cc")
    assert [call[2] for call in calls] == ["export"]


def test_changed_dynamic_profile_uses_current_resource_version(ab):
    desired = desired_profile("new.default.svc.cluster.local")
    current = exported_profile(desired_profile("old.default.svc.cluster.local"), version=7)
    instance = applier(ab, desired)
    calls = []
    replacement = {}

    def cli(*args, **kwargs):
        calls.append(args)
        if args[2] == "export":
            return ab.Result(0, yaml.safe_dump(current))
        replacement.update(yaml.safe_load(Path(args[args.index("-f") + 1]).read_text()))
        return ab.Result(0)

    instance.cli = cli
    instance.reconcile_dynamic_profile(SimpleNamespace(name="default"), "saw-demo-cc")
    assert [call[2] for call in calls] == ["export", "update"]
    assert replacement["resource_version"] == 7
    assert replacement["endpoints"]["host"] == "new.default.svc.cluster.local"


def test_missing_dynamic_profile_is_imported(ab):
    instance = applier(ab, desired_profile())
    calls = []

    def cli(*args, **kwargs):
        calls.append(args)
        if args[2] == "export":
            return ab.Result(1, err="provider profile │ not found")
        return ab.Result(0)

    instance.cli = cli
    instance.reconcile_dynamic_profile(SimpleNamespace(name="default"), "saw-demo-cc")
    assert [call[2] for call in calls] == ["export", "import"]


def test_dynamic_profile_does_not_replace_global_profile(ab):
    instance = applier(ab, desired_profile("new.default.svc.cluster.local"))
    global_profile = exported_profile(desired_profile("old.default.svc.cluster.local"),
                                      scope="global", source="catalog")
    instance.cli = lambda *args, **kwargs: ab.Result(0, yaml.safe_dump(global_profile))
    with pytest.raises(ab.InstallerError, match="not a workspace custom profile"):
        instance.reconcile_dynamic_profile(SimpleNamespace(name="default"), "saw-demo-cc")


def test_dynamic_profile_export_error_stops_apply(ab):
    instance = applier(ab, desired_profile())
    instance.cli = lambda *args, **kwargs: ab.Result(1, err="gateway unavailable")
    with pytest.raises(ab.InstallerError, match="could not export"):
        instance.reconcile_dynamic_profile(SimpleNamespace(name="default"), "saw-demo-cc")
