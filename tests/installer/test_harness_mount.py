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
import hashlib
import json
import os
import subprocess
import time

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
    """Build content-addressed harness__<name>__<hash> keys plus the
    harness__<name>__map key, exactly like templates/configmap-bom.yaml."""
    files, path_map = {}, {}
    for rel, text in tree.items():
        key = f"harness__{name}__{hashlib.sha256(rel.encode()).hexdigest()[:16]}"
        files[key] = text.encode()
        path_map[key.rsplit('__', 1)[1]] = rel
    files[f"harness__{name}__map"] = json.dumps(path_map).encode()
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
    cosign = [json.loads(line) for line in (fake_env.state / "cosign.log").read_text().splitlines()]
    assert ["verify", "--certificate-identity",
            config["harness"]["cosign"]["identity"],
            "--certificate-oidc-issuer", config["harness"]["cosign"]["issuer"],
            IMAGE_V1] in cosign
    assert applier.verify(profiles) == []


def test_an_unsigned_harness_image_is_refused_before_fill(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    (fake_env.state / "unsigned.json").write_text(json.dumps([IMAGE_V1]))
    with pytest.raises(ab.InstallerError, match="is not signed by"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not (fake_env.state / "volumes" / volume_name(ab) / "harness.yaml").exists()
    assert not notebook_creates(fake_env)


def test_a_harness_image_without_cosign_identity_is_refused(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    cfg = {**config, "harness": {"cosign": {"identity": "", "issuer": ""}}}
    with pytest.raises(ab.InstallerError, match="no cosign identity"):
        make_applier(ab, cfg, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not notebook_creates(fake_env)


def test_a_writable_harness_mount_recreates_the_sandbox(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["driverConfig"]["podman"]["mounts"][0]["read_only"] = False
    fake_env.set_openshell_state(state)
    make_applier(ab, config, creds).apply(profiles)
    assert notebook_deletes(fake_env)
    assert notebook(fake_env)["driverConfig"]["podman"]["mounts"][0]["read_only"] is True


def test_drifted_openclaw_harness_config_fails_verify(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    assert applier.verify(profiles) == []
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["openclawConfig"]["plugins.load.paths"] = ["/tmp/evil"]
    fake_env.set_openshell_state(state)
    assert any("plugins.load.paths" in f for f in applier.verify(profiles))


def test_a_bundle_openclaw_has_not_loaded_fails_verify(
        ab, fake_env, config, profiles, creds):
    """`mcp list` never shows bundle servers, so verify reads the bundle row
    of `plugins list --json`: no row (or not loaded) fails the run."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    assert applier.verify(profiles) == []
    (fake_env.state / "plugins-list.json").write_text(json.dumps({"plugins": []}))
    failures = applier.verify(profiles)
    assert any("does not load the harness bundle" in f for f in failures)


def test_an_unparseable_plugins_list_fails_verify(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    assert applier.verify(profiles) == []
    (fake_env.state / "plugins-list.json").write_text("not json\n")
    failures = applier.verify(profiles)
    assert any("could not parse" in f for f in failures)


def live_listing(**overrides):
    """The 2026.9.5 row shape: Source is an origin string, rootDir the path."""
    bundle = {"id": "demo", "name": "demo", "format": "bundle",
              "source": "$OPENCLAW_HOME/harness", "rootDir": "/sandbox/harness",
              "enabled": True, "status": "loaded",
              "bundleCapabilities": ["skills", "mcpServers"]}
    bundle.update(overrides.pop("bundle", {}))
    plugins = [bundle]
    for name, enabled in overrides.pop("native", {"old-tool": True}).items():
        plugins.append({"id": name, "format": "openclaw",
                        "enabled": enabled, "status": "loaded"})
    return json.dumps({"plugins": plugins})


def test_a_bundle_that_is_not_loaded_fails_verify(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    assert applier.verify(profiles) == []
    (fake_env.state / "plugins-list.json").write_text(
        live_listing(bundle={"status": "error"}))
    failures = applier.verify(profiles)
    assert any("does not load the harness bundle 'demo'" in f for f in failures)


def test_a_bundle_without_capabilities_still_passes_verify(
        ab, fake_env, config, profiles, creds):
    """Older shapes may omit bundleCapabilities; the mount row is the proof."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    listing = json.loads(live_listing())
    del listing["plugins"][0]["bundleCapabilities"]
    (fake_env.state / "plugins-list.json").write_text(json.dumps(listing))
    assert applier.verify(profiles) == []


def test_a_disabled_native_plugin_fails_verify(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    use_ref(profiles, {"image": IMAGE_V1})
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    assert applier.verify(profiles) == []
    (fake_env.state / "plugins-list.json").write_text(
        live_listing(native={"old-tool": False}))
    failures = applier.verify(profiles)
    assert any("old-tool" in f for f in failures)


def test_a_failed_volume_import_restores_the_previous_tree(
        ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}, IMAGE_V2: {"__tree__": V2}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    (fake_env.state / "import-fail.json").write_text(json.dumps([volume_name(ab)]))
    with pytest.raises(ab.InstallerError, match="sandbox 'notebook'"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V2}))
    volume = fake_env.state / "volumes" / volume_name(ab)
    assert "v1" in (volume / "skills/demo/SKILL.md").read_text()


def test_the_volume_carries_the_admission_labels(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert volume_labels(fake_env, volume_name(ab)) == {
        "openshell.ai/sandbox-attachable": "true",
        "openshell.ai/sandbox-attachable-workspace": "default",
        "saw.redhat.com/harness-volume": "true"}


def test_an_unchanged_image_is_not_pulled_again(
        ab, fake_env, config, profiles, creds, tmp_path):
    """Across applies the ledger holds the tree digest, so the volume is
    trusted without another pull/export. Without a ledger every apply refills."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(tmp_path / "ledger.json")}}
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, cfg, creds).apply(profiles)
    make_applier(ab, cfg, creds).apply(profiles)
    assert sum(op[:1] == ["pull"] and op[-1] == IMAGE_V1 for op in podman_ops(fake_env)) == 1
    assert sum(op[:1] == ["export"] for op in podman_ops(fake_env)) == 1


def test_an_unchanged_image_keeps_the_sandbox(
        ab, fake_env, config, profiles, creds, tmp_path):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(tmp_path / "ledger.json")}}
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, cfg, creds).apply(profiles)
    make_applier(ab, cfg, creds).apply(profiles)
    assert len(notebook_creates(fake_env)) == 1
    assert not notebook_deletes(fake_env)


def test_a_rerun_configures_the_harness_only_once(ab, fake_env, config, profiles, creds, tmp_path):
    """create_sandbox's own harness config (for an already-running sandbox)
    and start_openclaw's are the same round trip; a rerun must not pay for
    it twice."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(tmp_path / "ledger.json")}}
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, cfg, creds).apply(profiles)
    make_applier(ab, cfg, creds).apply(profiles)
    scripts = [c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"]]
    sets = [s for s in scripts if "openclaw config set plugins.load.paths" in s]
    assert len(sets) == 2, "one configure_harness per apply (create, then rerun); not two per apply"


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


def test_an_oversized_harness_image_is_refused(ab, fake_env, config, profiles, creds, monkeypatch):
    """Reading an image tree fully into memory must have a ceiling: an
    oversized bundle refuses instead of risking the VM's memory."""
    monkeypatch.setattr(ab, "HARNESS_IMAGE_MAX_BYTES", 10)
    big_tree = {**V1, "skills/demo/SKILL.md": "x" * 100}
    fake_env.set_images({IMAGE_V1: {"__tree__": big_tree}})
    with pytest.raises(ab.InstallerError, match="exceeds"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))


def test_an_unused_harness_image_is_removed_after_the_ref_changes(
        ab, fake_env, config, profiles, creds, tmp_path):
    """A harness image no sandbox references any more must not linger on the
    VM forever."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}, IMAGE_V2: {"__tree__": V2}})
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(tmp_path / "ledger.json")}}
    images = lambda: json.loads((fake_env.state / "images.json").read_text())
    make_applier(ab, cfg, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert IMAGE_V1 in images()
    make_applier(ab, cfg, creds).apply(use_ref(profiles, {"image": IMAGE_V2}))
    assert IMAGE_V1 not in images(), "the old image must be GC'd"
    assert IMAGE_V2 in images()


def test_a_sandbox_created_before_its_harness_is_recreated(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds, harness={"bundles": {}}).apply(use_ref(profiles, {}))
    assert "driverConfig" not in notebook(fake_env)
    applier = make_applier(ab, config, creds)
    applier.apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert notebook(fake_env)["driverConfig"]["podman"]["mounts"][0]["source"] == volume_name(ab)
    assert applier.verify(profiles) == []


def test_identity_opt_out_recreates_only_the_stale_workload_mount(
        ab, fake_env, config, profiles, creds):
    """The harness survives an identity opt-out sandbox recreation."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    cfg = {**config, "spiffe": {"enabled": False}}
    use_ref(profiles, {"image": IMAGE_V1})
    make_applier(ab, cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["identityBinds"] = [
        "/spiffe-workload-api:/spiffe-workload-api:ro"]
    fake_env.set_openshell_state(state)

    make_applier(ab, cfg, creds).apply(profiles)
    assert len(notebook_deletes(fake_env)) == 1
    assert len(notebook_creates(fake_env)) == 2
    assert notebook(fake_env)["driverConfig"]["podman"]["mounts"][0]["source"] == volume_name(ab)

    make_applier(ab, cfg, creds).apply(profiles)
    assert len(notebook_creates(fake_env)) == 2


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


def test_a_planted_symlink_is_treated_as_drift_and_refilled(ab, fake_env, config, profiles, creds):
    """A symlink added through a writable mount (e.g. from a second sandbox)
    carries no file content, so the tree digest alone would not notice it.
    It must still force a refill, same as an edited file."""
    use_ref(profiles, {"name": "demo"})
    harness = _inline(ab, "demo", V1)
    make_applier(ab, config, creds, harness=harness).apply(profiles)
    volume = fake_env.state / "volumes" / volume_name(ab)
    (volume / "plugins" / "evil").symlink_to(volume / "skills")
    applier = make_applier(ab, config, creds, harness=harness)
    assert applier.verify(profiles), "verify must notice the planted symlink"
    applier.apply(profiles)
    assert not (volume / "plugins" / "evil").exists(), "the symlink must not survive a refill"
    assert applier.verify(profiles) == []


def test_an_unreadable_planted_file_is_refilled_not_fatal(ab, fake_env, config, profiles, creds):
    """A mode-000 file (planted by another owner in the user namespace) must
    not crash the apply: refill proceeds, backing up what it can read."""
    use_ref(profiles, {"name": "demo"})
    harness = _inline(ab, "demo", V1)
    make_applier(ab, config, creds, harness=harness).apply(profiles)
    volume = fake_env.state / "volumes" / volume_name(ab)
    planted = volume / "plugins" / "secret"
    planted.write_text("locked")
    planted.chmod(0o000)
    applier = make_applier(ab, config, creds, harness=harness)
    assert applier.verify(profiles), "verify must notice the unreadable file"
    applier.apply(profiles)  # refill wipes the volume, taking the planted file with it
    assert applier.verify(profiles) == []


def test_an_inline_forged_marker_does_not_pass_verify(ab, fake_env, config, profiles, creds):
    """Rewriting the tree and the in-volume marker together must still fail:
    the ConfigMap digest is the trust anchor, not the marker."""
    use_ref(profiles, {"name": "demo"})
    harness = _inline(ab, "demo", V1)
    make_applier(ab, config, creds, harness=harness).apply(profiles)
    volume = fake_env.state / "volumes" / volume_name(ab)
    (volume / "skills/demo/SKILL.md").write_text("forged")
    tree = ab.read_volume_tree(volume)
    (volume / ab.HARNESS_MARKER).write_text(json.dumps({
        "source": f"bundle:demo@{harness['bundles']['demo'].digest}",
        "treeDigest": ab.harness_tree_digest(tree)}))
    applier = make_applier(ab, config, creds, harness=harness)
    assert applier.verify(profiles), "forged marker must not satisfy verify"
    applier.apply(profiles)
    assert (volume / "skills/demo/SKILL.md").read_text() == V1["skills/demo/SKILL.md"]


def test_a_stale_ledger_digest_is_not_reused_for_a_changed_image_ref(
        ab, fake_env, config, profiles, creds, tmp_path):
    """A forged on-volume marker claiming the new source, paired with a
    ledger digest that actually belongs to the old source, must not pass as
    intact: the ledger entry is only trusted when its own source matches."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}, IMAGE_V2: {"__tree__": V2}})
    cfg = {**config, "prune": {"mode": "off", "ledgerPath": str(tmp_path / "ledger.json")}}
    make_applier(ab, cfg, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    volume = fake_env.state / "volumes" / volume_name(ab)
    old_digest = ab.harness_tree_digest(ab.read_volume_tree(volume))
    (volume / ab.HARNESS_MARKER).write_text(json.dumps({
        "source": IMAGE_V2, "treeDigest": old_digest}))
    applier = make_applier(ab, cfg, creds)
    assert applier.verify(use_ref(profiles, {"image": IMAGE_V2})), \
        "stale ledger digest + forged marker source must not pass verify"
    applier.apply(use_ref(profiles, {"image": IMAGE_V2}))
    assert "v2" in (volume / "skills/demo/SKILL.md").read_text()
    assert applier.verify(use_ref(profiles, {"image": IMAGE_V2})) == []


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


# -- path safety through image export / volume import ---------------------------------

def test_image_export_path_escape_is_refused_before_fill(
        ab, fake_env, config, profiles, creds):
    """Fake export puts __tree__ keys on the tar as-is; read_harness_tar must
    refuse .. members on the image_tree path (not only in unit tests)."""
    fake_env.set_images({IMAGE_V1: {"__tree__": {**V1, "skills/../../outside": "x"}}})
    with pytest.raises(ab.InstallerError, match="unsafe path"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not (fake_env.state / "volumes" / volume_name(ab) / "harness.yaml").exists()


def test_volume_import_refuses_a_path_escape(fake_env, tmp_path):
    """Fake podman volume import uses tar filter='data', so a crafted escape
    cannot land outside the volume directory."""
    import io
    import os
    import subprocess
    import tarfile
    from pathlib import Path

    vol = "saw-harness-escape-test"
    (fake_env.state / "volumes" / vol).mkdir(parents=True)
    tarball = tmp_path / "evil.tar"
    with tarfile.open(tarball, "w") as tar:
        data = b"pwned"
        info = tarfile.TarInfo("../escaped")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    env = {**os.environ, "FAKE_STATE": str(fake_env.state), "PATH": os.environ["PATH"]}
    fake = Path(__file__).resolve().parent / "fakes" / "podman"
    result = subprocess.run(
        [str(fake), "volume", "import", vol, str(tarball)],
        env=env, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert not (fake_env.state / "volumes" / "escaped").exists()


# -- governance: checked before anything is filled ------------------------------------

def test_an_unserved_governance_profile_stops_before_the_sandbox_is_created(
        ab, fake_env, config, profiles, creds):
    tree = {**V1, "harness.yaml": manifest(plugins=[{"name": "old-tool", "governanceProfile": "nope"}])}
    fake_env.set_images({IMAGE_V1: {"__tree__": tree}})
    with pytest.raises(ab.InstallerError, match="'nope', which the gateway does not serve"):
        make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not notebook_creates(fake_env)
    assert not (fake_env.state / "volumes" / volume_name(ab) / "harness.yaml").exists()


def test_dry_run_still_refuses_bad_governance(ab, fake_env, config, profiles, creds):
    """--dry-run must not report success for a bundle real apply would refuse."""
    tree = {**V1, "harness.yaml": manifest(plugins=[{"name": "old-tool", "governanceProfile": "nope"}])}
    fake_env.set_images({IMAGE_V1: {"__tree__": tree}})
    applier = ab.ProfileApplier(ab.Shell(dry_run=True), config, creds)
    with pytest.raises(ab.InstallerError, match="'nope', which the gateway does not serve"):
        applier.apply(use_ref(profiles, {"image": IMAGE_V1}))
    assert not notebook_creates(fake_env)
    assert not (fake_env.state / "volumes" / volume_name(ab)).exists()


def test_dry_run_still_refuses_an_unsigned_image(ab, fake_env, config, profiles, creds):
    """The cosign check runs under --dry-run too (force), before any pull."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    (fake_env.state / "unsigned.json").write_text(json.dumps([IMAGE_V1]))
    applier = ab.ProfileApplier(ab.Shell(dry_run=True), config, creds)
    with pytest.raises(ab.InstallerError, match="is not signed by"):
        applier.apply(use_ref(profiles, {"image": IMAGE_V1}))
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


def test_the_gateway_secret_is_never_rotated_by_the_installer(ab, fake_env, config, profiles, creds):
    """Regression: a live gateway keeps authenticating with the secret it was
    launched with. The secret is the one kept in the sandbox's config, so
    rewriting the settings on every run never desyncs it from a gateway
    that is left running."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    scripts = [c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"]]
    restart_script = next(s for s in scripts if "nohup openclaw gateway run" in s)
    assert 'openclaw config set gateway.auth.token "\\"$secret\\""' in restart_script
    assert not any("gateway.auth.token" in s and "nohup openclaw gateway run" not in s
                   for s in scripts)


class FakeGateway:
    """A fake `openclaw` on PATH for running a gateway script with a real sh:
    `gateway run` stays up like the real gateway and records each start."""

    def __init__(self, tmp_path):
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.starts = tmp_path / "starts"
        exe = self.bin / "openclaw"
        exe.write_text('#!/bin/sh\n'
                       'case "$*" in\n'
                       f'  "gateway run"*) echo "$$" >> {self.starts}; sleep 60;;\n'
                       'esac\n')
        exe.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}"}
        self.procs = []

    def start_running(self):
        """A gateway already up before the script runs."""
        proc = subprocess.Popen([str(self.bin / "openclaw"), "gateway", "run", "--port", "18789"],
                                env=self.env)
        self.procs.append(proc)
        time.sleep(0.3)
        return proc

    def run(self, script):
        result = subprocess.run(["sh", "-c", script], env=self.env, timeout=30)
        time.sleep(1.5)
        return result.returncode

    def running(self):
        return [pid for pid in self.started() if os.path.exists(f"/proc/{pid}")
                and "gateway" in open(f"/proc/{pid}/cmdline").read()]

    def started(self):
        return self.starts.read_text().split() if self.starts.exists() else []

    def stop(self):
        for proc in self.procs:
            proc.kill()
        subprocess.run(["pkill", "-f", f"{self.bin}/openclaw"], check=False)


@pytest.fixture
def gateway(tmp_path):
    g = FakeGateway(tmp_path)
    yield g
    g.stop()


@pytest.mark.parametrize("sandbox", ["notebook", "cuda-sandbox"])
def test_every_openclaw_sandbox_ends_up_with_a_gateway(
        ab, fake_env, config, profiles, creds, gateway, sandbox):
    """Regression (found in review): the script also contains the text
    `openclaw gateway run`, so `pkill -f`/`pgrep -f` patterns, bracketed or
    not, matched the script's own shell. The harness sandbox (refilled)
    killed its shell before nohup; the one without a harness concluded a
    gateway was already running. Neither got a gateway. This runs the exact
    script start_openclaw sends with a real sh, nothing running yet."""
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    script = next(c[-1] for c in fake_env.openshell_calls()
                  if c[:2] == ["sandbox", "exec"] and c[3] == sandbox
                  and "nohup openclaw gateway run" in c[-1])
    assert gateway.run(script) == 0, "the script's shell must not kill itself"
    assert len(gateway.started()) == 1


def gateway_script(ab, home, refilled=False, cfg=None):
    (home / ".openclaw").mkdir(exist_ok=True)
    return ab.openclaw_gateway_script(cfg or {}, "default", "notebook",
                                      f"OPENCLAW_HOME={home}", refilled=refilled)


def test_a_running_gateway_is_kept_when_nothing_changed(ab, gateway, tmp_path):
    assert gateway.run(gateway_script(ab, tmp_path)) == 0
    assert len(gateway.started()) == 1
    assert gateway.run(gateway_script(ab, tmp_path)) == 0
    assert len(gateway.started()) == 1, "a live gateway (and its sessions) is left alone"


def test_a_running_gateway_without_a_fingerprint_is_replaced(ab, gateway, tmp_path):
    """A gateway started before the fingerprint existed (or by hand) may run
    other settings: it is replaced once."""
    old = gateway.start_running()
    assert gateway.run(gateway_script(ab, tmp_path)) == 0
    assert old.poll() is not None
    assert len(gateway.started()) == 2


def test_a_refill_replaces_the_running_gateway(ab, gateway, tmp_path):
    assert gateway.run(gateway_script(ab, tmp_path)) == 0
    assert gateway.run(gateway_script(ab, tmp_path, refilled=True)) == 0
    assert len(gateway.started()) == 2, "the old gateway is stopped and a new one started"
    assert len(gateway.running()) == 1


def test_changed_settings_replace_the_running_gateway(ab, gateway, tmp_path):
    """A new UI origin or auth setting only applies after a restart."""
    assert gateway.run(gateway_script(ab, tmp_path)) == 0
    cfg = {"sandboxUi": [{"workspace": "default", "sandbox": "notebook",
                          "host": "alice-default-notebook-ui.apps.example.com"}]}
    assert gateway.run(gateway_script(ab, tmp_path, cfg=cfg)) == 0
    assert len(gateway.started()) == 2
    assert len(gateway.running()) == 1


def test_the_gateway_check_does_not_count_the_script_itself(ab, tmp_path):
    """gateway_pids must not list the sh -c running it, even though that
    shell's command line contains `openclaw gateway run`."""
    script = ab._GATEWAY_PIDS_SH + "\n# nohup openclaw gateway run\ngateway_pids | wc -l"
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert out.stdout.strip() == "0"


def test_a_shape_change_unsets_the_stale_config_key(ab, fake_env, config, profiles, creds):
    """plugins/ → skills only must unset plugins.load.paths."""
    use_ref(profiles, {"name": "demo"})
    make_applier(ab, config, creds, harness=_inline(ab, "demo", V1)).apply(profiles)
    skills_only = {k: v for k, v in V1.items()
                   if k == "harness.yaml" or k.startswith("skills/")}
    make_applier(ab, config, creds, harness=_inline(ab, "demo", skills_only)).apply(profiles)
    scripts = [c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"]]
    assert any("openclaw config unset plugins.load.paths" in s for s in scripts)
    assert any("skills.load.extraDirs" in s and "config set" in s for s in scripts)


def test_a_removed_harness_ref_unsets_its_config_keys(ab, fake_env, config, profiles, creds):
    fake_env.set_images({IMAGE_V1: {"__tree__": V1}})
    make_applier(ab, config, creds).apply(use_ref(profiles, {"image": IMAGE_V1}))
    use_ref(profiles, {})
    make_applier(ab, config, creds, harness={"bundles": {}}).apply(profiles)
    scripts = [c[-1] for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "exec"]]
    assert any("openclaw config unset plugins.load.paths" in s for s in scripts)
    assert any("openclaw config unset skills.load.extraDirs" in s for s in scripts)


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


def test_a_harness_failure_does_not_stop_other_sandboxes_or_cleanup(
        ab, fake_env, config, profiles, creds):
    """A failed sandbox must not abort the whole apply: siblings, prune and
    harness-volume cleanup still run; the apply still fails overall."""
    use_ref(profiles, {"name": "unknown-bundle"})
    applier = make_applier(ab, config, creds)
    with pytest.raises(ab.InstallerError, match="unknown-bundle"):
        applier.apply(profiles)
    state = fake_env.openshell_state()
    assert "default/notebook" not in state["sandboxes"], "the broken sandbox is not created"
    assert "cuda-dev/cuda-sandbox" in state["sandboxes"], "a sibling sandbox still applies"


def test_a_harness_needs_driver_config_allowed(ab, tmp_path):
    toml = tmp_path / "gateway.toml"
    toml.write_text('[openshell.drivers.podman]\nsupervisor_image = "x"\n')
    with pytest.raises(ab.InstallerError, match="allow_driver_config"):
        ab.check_driver_config_allowed(toml)
    toml.write_text('[openshell.drivers.podman]\nallow_driver_config = true\n')
    ab.check_driver_config_allowed(toml)
    ab.check_driver_config_allowed(tmp_path / "missing.toml")
