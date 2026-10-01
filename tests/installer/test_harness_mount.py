"""Harness bundles reach the sandbox only as a read-only mount at /sandbox/harness.

Two sources, both put unchanged into one podman named volume per sandbox,
which is what the sandbox mounts:

- harnessRef.image: an OCI image pinned by digest, pulled and unpacked (file
  modes kept). OpenShell 0.1.x refuses image mounts while resource admission
  is on, so the image itself is never mounted.
- harnessRef.name: an inline bundle from the saw-bom ConfigMap.

A changed bundle refills the volume in place and the running sandbox keeps
going; the volume carries the openshell.ai/sandbox-attachable labels 0.1.x
admission requires. The fakes model the podman driver: the fake openshell
records --driver-config-json, the fake podman lists sandbox containers by
their openshell.ai/* labels, reports their `.Mounts` and volume labels, and
refuses to remove a volume a sandbox mounts; `sandbox exec cat` reads
through the mount.
"""
import json

import pytest
import yaml

from test_apply_profiles import creds, make_applier, profiles  # noqa: F401 (fixtures)

IMAGE_V1 = "ghcr.io/example/saw-harness-demo@sha256:" + "1" * 64
IMAGE_V2 = "ghcr.io/example/saw-harness-demo@sha256:" + "2" * 64


def manifest(**spec):
    return yaml.safe_dump({"apiVersion": "saw.redhat.com/v1alpha1", "kind": "HarnessBundle",
                           "metadata": {"name": "demo"}, "spec": {"agent": "openclaw", **spec}})


V1 = {"harness.yaml": manifest(version="1"), "plugin.json": '{"name": "demo"}',
      "skills/demo/SKILL.md": "---\nname: demo\ndescription: v1\n---\n",
      "plugins/old-tool/index.mjs": "export default {id: 'old-tool'}\n",
      "mcp.json": json.dumps({"mcpServers": {"echo": {"type": "stdio", "command": "node"}}})}
V2 = {**V1, "harness.yaml": manifest(version="2"),
      "skills/demo/SKILL.md": "---\nname: demo\ndescription: v2\n---\n"}


def volume_name(ab):
    return ab.harness_volume_name("default", "notebook")


def use_ref(profiles, ref, providers=None):
    for profile in profiles:
        for ws in profile.workspaces:
            for sb in ws.sandboxes:
                if sb.name == "notebook":
                    sb.harness_ref = ref
                    if providers is not None:
                        sb.providers = providers
    return profiles


def notebook(fake_env):
    return fake_env.openshell_state()["sandboxes"]["default/notebook"]


def notebook_creates(fake_env):
    return [c for c in fake_env.openshell_calls()
            if c[:2] == ["sandbox", "create"] and "notebook" in c]


def notebook_deletes(fake_env):
    return [c for c in fake_env.openshell_calls() if c[:3] == ["sandbox", "delete", "notebook"]]


def podman_ops(fake_env):
    return [json.loads(line) for line in (fake_env.state / "podman.log").read_text().splitlines()]


def volume_labels(fake_env, name):
    return json.loads((fake_env.state / "volume-labels.json").read_text()).get(name)


def mcp_tree(url, profile="brave"):
    return {**V1, "harness.yaml": manifest(mcpServers=[{"name": "search", "governanceProfile": profile}]),
            "mcp.json": json.dumps({"mcpServers": {"search": {"type": "streamable-http", "url": url}}})}


def _inline(ab, name, tree):
    files = {f"harness__{name}__{rel.replace('/', '__')}": text.encode() for rel, text in tree.items()}
    return {"bundles": ab.parse_harness_files(files)}


# -- OCI image: unpacked into the sandbox's volume ---------------------------------

def test_an_image_is_unpacked_into_a_volume_not_mounted(ab, fake_env, config, profiles, creds):
    """0.1.x refuses image mounts under resource admission, so the pinned
    image's tree goes into the volume and the volume is mounted."""
    fake_env.set_images({IMAGE_V1: {"__tree__": {**V1, "bin/run.sh": "#!/bin/sh\n"}}})
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert notebook(fake_env)["driverConfig"] == {"podman": {"mounts": [{
        "type": "volume", "source": volume_name(ab), "target": "/sandbox/harness",
        "read_only": True}]}}
    volume = fake_env.state / "volumes" / volume_name(ab)
    assert (volume / "skills/demo/SKILL.md").read_text() == V1["skills/demo/SKILL.md"]
    assert (volume / "bin/run.sh").stat().st_mode & 0o111, "an image keeps file modes"
    assert ["pull", "--quiet", IMAGE_V1] in podman_ops(fake_env)
    assert applier.verify(profiles) == []


def test_the_volume_carries_the_admission_labels(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert volume_labels(fake_env, volume_name(ab)) == {
        "openshell.ai/sandbox-attachable": "true",
        "openshell.ai/sandbox-attachable-workspace": "default",
        "saw.redhat.com/harness-volume": "true"}


def test_an_unchanged_image_is_not_pulled_again(ab, fake_env, config, profiles, creds):
    """The volume already holds it intact, so it is read from there."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, config, creds).apply(profiles)
    make_applier(ab, config, creds).apply(profiles)
    assert sum(op[:1] == ["pull"] and op[-1] == IMAGE_V1 for op in podman_ops(fake_env)) == 1
    assert sum(op[:1] == ["export"] for op in podman_ops(fake_env)) == 1


def test_an_unchanged_image_keeps_the_sandbox(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, config, creds).apply(profiles)
    make_applier(ab, config, creds).apply(profiles)
    assert len(notebook_creates(fake_env)) == 1
    assert not notebook_deletes(fake_env)


def test_a_new_image_digest_refills_the_volume_in_place(ab, fake_env, config, profiles, creds):
    """The volume keeps its identity (0.1.x stops a sandbox whose attached
    volume was recreated), so the sandbox keeps running."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}, IMAGE_V2: {"__tree__": V2}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V2}))
    assert not notebook_deletes(fake_env)
    assert len(notebook_creates(fake_env)) == 1
    assert not any(op[:2] == ["volume", "rm"] and op[-1] == volume_name(ab)
                   for op in podman_ops(fake_env))
    volume = fake_env.state / "volumes" / volume_name(ab)
    assert "v2" in (volume / "skills/demo/SKILL.md").read_text()
    assert applier.verify(profiles) == []


def test_a_sandbox_created_before_its_harness_is_recreated(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds, harness={"bundles": {}}).apply(use_ref(profiles, {}))
    assert "driverConfig" not in notebook(fake_env)
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert notebook(fake_env)["driverConfig"]["podman"]["mounts"][0]["source"] == volume_name(ab)
    assert applier.verify(profiles) == []


def test_verify_reports_a_volume_holding_another_image(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}, IMAGE_V2: {"__tree__": V2}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    failures = make_applier(ab, config, creds).verify(use_ref(profiles, {"image": IMAGE_V2}))
    assert any(f"holds {IMAGE_V1}, not {IMAGE_V2}" in f for f in failures), failures


# -- removing a harness ------------------------------------------------------------

def test_removing_the_harness_ref_unmounts_it_and_removes_the_volume(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    use_ref(profiles, {})
    before = make_applier(ab, config, creds, harness={"bundles": {}}).verify(profiles)
    assert any("still mounted although the sandbox has no harnessRef" in f for f in before), before
    applier = make_applier(ab, config, creds, harness={"bundles": {}})
    applier.apply(profiles)
    assert len(notebook_deletes(fake_env)) == 1
    assert "driverConfig" not in notebook(fake_env)
    assert not (fake_env.state / "volumes" / volume_name(ab)).exists()
    assert applier.verify(profiles) == []


def test_a_volume_still_in_use_is_kept(ab, fake_env, config, profiles, creds):
    """podman refuses to remove a mounted volume; cleanup leaves it be."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    for profile in profiles:
        for ws in profile.workspaces:
            for sb in ws.sandboxes:
                if sb.name == "notebook":
                    sb.enabled = False   # disabled, not pruned: its sandbox stays
    make_applier(ab, config, creds).apply(profiles)
    assert (fake_env.state / "volumes" / volume_name(ab)).is_dir()


def test_an_unlabelled_volume_is_recreated_with_its_sandbox(ab, fake_env, config, profiles, creds):
    """A volume from before the admission labels (labels cannot be added
    later): the sandbox that mounts it goes first, then the volume."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, config, creds).apply(profiles)
    labels_file = fake_env.state / "volume-labels.json"
    labels = json.loads(labels_file.read_text())
    labels[volume_name(ab)] = {}
    labels_file.write_text(json.dumps(labels))
    applier = make_applier(ab, config, creds)
    assert any("lacks the openshell.ai/sandbox-attachable labels" in f
               for f in applier.verify(profiles))
    applier.apply(profiles)
    assert len(notebook_deletes(fake_env)) == 1
    assert volume_labels(fake_env, volume_name(ab))["openshell.ai/sandbox-attachable"] == "true"
    assert applier.verify(profiles) == []


# -- inline bundle -------------------------------------------------------------------

def test_an_inline_bundle_is_mounted_from_a_volume(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds, harness=_inline(ab, "demo", V1))
    applier.apply(use_ref(profiles, {"name": "demo"}))
    mount = notebook(fake_env)["driverConfig"]["podman"]["mounts"][0]
    assert (mount["type"], mount["source"]) == ("volume", volume_name(ab))
    volume = fake_env.state / "volumes" / volume_name(ab)
    assert (volume / "skills/demo/SKILL.md").read_text() == V1["skills/demo/SKILL.md"]
    assert applier.verify(profiles) == []


def test_an_edited_inline_bundle_refills_the_volume_in_place(ab, fake_env, config, profiles, creds):
    use_ref(profiles, {"name": "demo"})
    make_applier(ab, config, creds, harness=_inline(ab, "demo", V1)).apply(profiles)
    edited = {k: v for k, v in V2.items() if not k.startswith("plugins/old-tool/")}
    applier = make_applier(ab, config, creds, harness=_inline(ab, "demo", edited))
    applier.apply(profiles)
    volume = fake_env.state / "volumes" / volume_name(ab)
    assert "v2" in (volume / "skills/demo/SKILL.md").read_text()
    assert not (volume / "plugins/old-tool").exists(), "a dropped file must not linger"
    assert len(notebook_creates(fake_env)) == 1, "the running sandbox keeps its mount"
    assert applier.verify(profiles) == []


def test_a_tampered_inline_volume_is_reported_and_refilled(ab, fake_env, config, profiles, creds):
    use_ref(profiles, {"name": "demo"})
    harness = _inline(ab, "demo", V1)
    make_applier(ab, config, creds, harness=harness).apply(profiles)
    skill = fake_env.state / "volumes" / volume_name(ab) / "skills/demo/SKILL.md"
    skill.write_text("tampered")
    applier = make_applier(ab, config, creds, harness=harness)
    assert applier.verify(profiles), "verify must notice the edited volume"
    applier.apply(profiles)
    assert skill.read_text() == V1["skills/demo/SKILL.md"]
    assert applier.verify(profiles) == []


# -- stdio secrets from image bundles: refused at describe time --------------------

def test_an_image_bundle_that_declares_a_credential_is_refused(
        ab, fake_env, config, profiles, creds):
    """credentialSecret/* cannot be resolved past the privilege boundary, so
    describe fails the bundle outright (before anything is mounted) with a
    message pointing at the provider-keys model."""
    tree = {**V1, "harness.yaml": manifest(mcpServers=[
        {"name": "echo", "credentialSecret": "tavily",
         "credentialSecretKey": "api_key", "credentialEnvVar": "TAVILY_API_KEY"}])}
    fake_env.set_images({IMAGE_V1: {"__tree__": tree}})
    with pytest.raises(ab.InstallerError, match="keys no longer reach the sandbox that way"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not notebook_creates(fake_env)


# -- governance: checked before anything is filled ------------------------------------

def test_an_unserved_governance_profile_stops_before_the_sandbox_is_created(
        ab, fake_env, config, profiles, creds):
    tree = {**V1, "harness.yaml": manifest(plugins=[{"name": "old-tool", "governanceProfile": "nope"}])}
    fake_env.set_images({IMAGE_V1: {"__tree__": tree}})
    with pytest.raises(ab.InstallerError, match="'nope', which the gateway does not serve"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not notebook_creates(fake_env)
    assert not (fake_env.state / "volumes" / volume_name(ab) / "harness.yaml").exists()


def test_a_governed_item_needs_a_provider_of_its_type(ab, fake_env, config, profiles, creds):
    """Without a provider of that type, neither the profile's endpoints nor
    its key reach the sandbox."""
    fake_env.set_images({IMAGE_V1: {"__tree__": mcp_tree("https://api.search.brave.com/mcp")}})
    with pytest.raises(ab.InstallerError, match="has no provider of type 'brave'"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}, ["nvidia"]))
    assert not notebook_creates(fake_env)


def test_a_remote_mcp_server_outside_its_profile_is_refused(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": mcp_tree("https://search.internal/v1/mcp")}})
    with pytest.raises(ab.InstallerError, match="reaches search.internal, which governanceProfile "
                                                "'brave' does not allow"):
        make_applier(ab, config, creds).apply(
            use_ref(profiles, {"image": IMAGE_V1}, ["nvidia", "brave"]))
    assert not notebook_creates(fake_env)


def test_a_remote_mcp_server_inside_its_profile_is_accepted(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": mcp_tree("https://api.search.brave.com/mcp")}})
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V1}, ["nvidia", "brave"]))
    assert applier.verify(profiles) == []


def test_a_stdio_server_gets_its_key_only_through_the_provider(ab, fake_env, config, profiles, creds):
    """No key is written or exported into the sandbox by the installer: the
    server reads the provider's placeholder env var, and the egress proxy
    adds the real key."""
    tree = {**V1, "harness.yaml": manifest(mcpServers=[{"name": "echo", "governanceProfile": "brave"}])}
    fake_env.set_images({IMAGE_V1: {"__tree__": tree}})
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V1}, ["nvidia", "brave"]))
    assert "brave" in notebook(fake_env)["providers"]
    scripts = [c[-1] for c in fake_env.openshell_calls()
               if c[:2] == ["sandbox", "exec"] and c[3] == "notebook"]
    gateway_run = next(s for s in scripts if "nohup openclaw gateway run" in s)
    assert gateway_run.count("export ") == 1, "only the gateway token is exported"
    assert not any("mcp.servers." in s for s in scripts)
    brave_key = creds["default"]["brave"]
    assert brave_key not in "\n".join(" ".join(c) for c in fake_env.openshell_calls()
                                      if c[:2] == ["sandbox", "exec"])
    assert applier.verify(profiles) == []


def test_the_catalog_is_read_once_per_workspace(ab, fake_env, config, profiles, creds):
    tree = {**V1, "harness.yaml": manifest(plugins=[{"name": "old-tool", "governanceProfile": "brave"}])}
    fake_env.set_images({IMAGE_V1: {"__tree__": tree}})
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V1}, ["nvidia", "brave"]))
    calls = [c for c in fake_env.openshell_calls() if c[:2] == ["provider", "list-profiles"]]
    assert calls == [["provider", "list-profiles", "-o", "json"]]
    cuda = next(ws for p in profiles for ws in p.workspaces if ws.name == "cuda-dev")
    applier.governance_catalog(cuda)
    applier.governance_catalog(cuda)
    calls = [c for c in fake_env.openshell_calls() if c[:2] == ["provider", "list-profiles"]]
    assert calls[1:] == [["provider", "list-profiles", "--workspace", "cuda-dev", "-o", "json"]]


# -- OpenClaw is pointed at the mount ---------------------------------------------

def test_openclaw_loads_the_bundle_from_the_mount(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    scripts = "\n".join(c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"])
    assert """openclaw config set plugins.load.paths '["/sandbox/harness", "/sandbox/harness/plugins"]'""" in scripts
    assert "base64 -d" not in scripts, "bundle files never go through exec"


# -- 0.1.x specifics ------------------------------------------------------------------

def test_the_supervisor_container_is_not_mistaken_for_the_workload(
        ab, fake_env, config, profiles, creds):
    """0.1.x runs a supervisor container with the same sandbox labels and
    none of the user's mounts; reading it would recreate the sandbox on
    every apply."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, config, creds).apply(profiles)
    make_applier(ab, config, creds).apply(profiles)
    assert not notebook_deletes(fake_env)
    ps = [op for op in podman_ops(fake_env) if op[:1] == ["ps"]]
    assert ps and all("label=openshell.ai/isolation-role=sandbox" in op for op in ps)


def test_relabelling_checks_governance_before_deleting_the_sandbox(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    labels_file = fake_env.state / "volume-labels.json"
    labels = json.loads(labels_file.read_text())
    labels[volume_name(ab)] = {}
    labels_file.write_text(json.dumps(labels))
    bad = {**V1, "harness.yaml": manifest(plugins=[{"name": "old-tool", "governanceProfile": "nope"}])}
    fake_env.set_images({IMAGE_V2: {"__tree__": bad}})
    with pytest.raises(ab.InstallerError, match="'nope'"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V2}))
    assert not notebook_deletes(fake_env), "a refused bundle must not cost the sandbox"


def test_a_harness_needs_driver_config_allowed(ab, tmp_path):
    toml = tmp_path / "gateway.toml"
    toml.write_text('[openshell.drivers.podman]\nsupervisor_image = "x"\n')
    with pytest.raises(ab.InstallerError, match="allow_driver_config"):
        ab.check_driver_config_allowed(toml)
    toml.write_text('[openshell.drivers.podman]\nallow_driver_config = true\n')
    ab.check_driver_config_allowed(toml)
    ab.check_driver_config_allowed(tmp_path / "missing.toml")
