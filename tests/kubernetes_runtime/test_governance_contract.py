"""Execute the real Rust admission guard over the real Helm/compiler output."""
import copy
import json
import os
import shutil
import subprocess

import pytest

from saw_kubernetes import compile_profile_files
from .profile_fixtures import ROOT, briefing_inputs


def test_compiler_harness_output_and_tampering_against_rust_guard(tmp_path):
    if not shutil.which("cargo"):
        if os.environ.get("SAW_REQUIRE_RUST_TESTS") == "1":
            pytest.fail("cargo is required by this CI job")
        pytest.skip("cargo is required for the compiler/governance contract test")
    files, config = briefing_inputs()
    valid = []
    for additional in (0, 16):
        slot = config["bindings"]["personal-assistant/assistant"]
        slot["mounts"] = [{"claimName":f"data-{i}", "uid":f"uid-{i}", "readOnly":True,
                           "mountPath":f"/data/{i}"} for i in range(additional)]
        driver = compile_profile_files(files, config)["workspaces"][0]["sandboxes"][0]["spec"]["template"]["driver_config"]
        assert len(driver["kubernetes"]["volumes"]) == 3 + additional
        assert len(driver["kubernetes"]["containers"]["agent"]["volume_mounts"]) == 5 + additional
        valid.append(driver)
    invalid = []
    for index, field, value in [
        (3,"name","saw-workspace"), (3,"read_only",False), (3,"mount_path","/etc"),
        (3,"sub_path","bundle"), (3,"sub_path","harness-../outside"),
        (3,"sub_path","harness-"+"g"*64), (3,"sub_path","harness-"+"a"*63),
        (3,"extra",True), (4,"name","saw-audit"), (4,"sub_path","other"),
        (4,"read_only",True), (4,"mount_path","/sandbox/harness"),
    ]:
        driver = copy.deepcopy(valid[0])
        driver["kubernetes"]["containers"]["agent"]["volume_mounts"][index][field] = value
        invalid.append(driver)
    for count in (1, 3):
        driver = copy.deepcopy(valid[0])
        mounts = driver["kubernetes"]["containers"]["agent"]["volume_mounts"]
        if count == 1:
            mounts.pop()
        else:
            mounts.append(copy.deepcopy(mounts[-1]))
        invalid.append(driver)
    extension = ROOT/"image-builder-charts/helm/governance-interceptor-image/files/saw-extension/driver_config.rs"
    (tmp_path/"src").mkdir()
    (tmp_path/"Cargo.toml").write_text('[package]\nname="compiler-guard-contract"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nserde_json="1"\n')
    (tmp_path/"src/lib.rs").write_text("""
use std::collections::HashMap;
use serde_json::Value;
struct InterceptorResult { allowed: bool }
fn allow() -> InterceptorResult { InterceptorResult { allowed: true } }
fn deny(_: &str) -> InterceptorResult { InterceptorResult { allowed: false } }
mod driver {
""" + extension.read_text() + """
#[test]
fn compiled_harness_contract() {
    let principal = HashMap::from([("kind".into(),"user".into()), ("provider".into(),"mtls".into()),
                                   ("roles".into(),"openshell-admin".into())]);
""" + '\n'.join(
        '    assert_eq!(validate_driver_config(Some(&serde_json::from_str::<Value>(r#"'
        + json.dumps(driver) + '"#).unwrap()), &principal).allowed, ' + str(allowed).lower() + ');'
        for allowed, drivers in [(True, valid), (False, invalid)] for driver in drivers
    ) + "\n}\n}\n")
    result = subprocess.run(["cargo","test","--offline","--manifest-path",str(tmp_path/"Cargo.toml")],
                            capture_output=True, text=True)
    if result.returncode and ("no matching package named" in result.stderr or
            "attempting to make an HTTP request, but --offline was specified" in result.stderr):
        if os.environ.get("SAW_REQUIRE_RUST_TESTS") == "1":
            pytest.fail("fetch serde_json before running the required Rust contract test")
        pytest.skip("serde_json is not cached; run with the CI Rust toolchain")
    assert result.returncode == 0, result.stdout + result.stderr
