"""GitHub and OpenShift share the interceptor recipe and admission patches."""

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "image-builder-charts" / "helm" / "governance-interceptor-image"
DOCKERFILE = CHART / "files/Dockerfile"
HELM = shutil.which("helm")

# Source patches must remain in both build paths.
PATCH_LINES = [
    # Existing workaround for NVIDIA/OpenShell#3929.
    "! grep -q 'insert(PROFILE_HASH_ANNOTATION' src/main.rs",
    # Harness driver-config guard: admin-only driver config, read-only mounts.
    "&& grep -q 'let gate = validate_sandbox_driver_config(' src/main.rs",
    "'fn validate_driver_config('",
    "'const HARNESS_ADMIN_ROLE: &str = \"openshell-admin\";'",
    "'        return deny(\"driver config may only be submitted by a platform admin mTLS identity\");'",
    "'        return deny(\"driver config must be a read-only saw-harness volume at /sandbox/harness\");'",
]


def inline_dockerfile():
    out = subprocess.run([HELM, "template", "img", str(CHART)],
                         capture_output=True, text=True, check=True).stdout
    bc = next(d for d in yaml.safe_load_all(out) if d and d["kind"] == "BuildConfig")
    return bc["spec"]["source"]["dockerfile"]


@pytest.mark.parametrize("line", PATCH_LINES)
def test_dockerfile_carries_every_source_patch(line):
    assert line in DOCKERFILE.read_text()


@pytest.mark.skipif(not HELM, reason="helm is not installed")
@pytest.mark.parametrize("line", PATCH_LINES)
def test_buildconfig_carries_every_source_patch(line):
    assert line in inline_dockerfile()


def test_the_guard_runs_before_the_build():
    """A patch appended after `cargo build` would never reach the binary."""
    text = DOCKERFILE.read_text()
    assert text.index("validate_driver_config") < text.index("RUN cargo test")


def test_the_guard_admin_role_is_the_role_the_saw_gateways_grant():
    """The guard hardcodes the role name; the gateway takes it from values
    (oidc.adminRole, and the OU of the installer's mTLS certificate). They
    must not drift, or the installer loses the right to mount a harness."""
    values = yaml.safe_load((ROOT / "charts" / "openshell-saw" / "values.yaml").read_text())
    role = values["oidc"]["adminRole"]
    assert f"'const HARNESS_ADMIN_ROLE: &str = \"{role}\";'" in DOCKERFILE.read_text()
    installer = (ROOT / "charts" / "openshell-saw" / "files" / "installer" / "apply_bom.py").read_text()
    assert f'ADMIN_CERT_SUBJECT = "/O=openshell/OU={role}/CN=saw-installer"' in installer


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_gateway_allows_driver_guard_without_noninterceptable_template_rpc():
    out = subprocess.run(
        [HELM, "template", "guard-test", str(ROOT / "charts/openshell-saw"),
         "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
         "--set", "global.clusterDomain=example.test"],
        capture_output=True, text=True, check=True).stdout
    config = next(d["data"]["gateway.toml"] for d in yaml.safe_load_all(out)
                  if d and "gateway.toml" in d.get("data", {}))
    gateway = tomllib.loads(config)["openshell"]["gateway"]
    governance = next(i for i in gateway["interceptors"] if i["name"] == "governance")
    assert governance["binding_policy"] == "allowlist"
    bindings = {b["rpc"]: b["phases"] for b in governance["bindings"]}
    assert "validate" in bindings["openshell.v1.OpenShell/CreateSandbox"]
    assert "openshell.v1.OpenShell/CreateSandboxTemplate" not in bindings


RUST_BEHAVIOR_TESTS = r'''#[cfg(test)]
mod harness_driver_tests {
    use super::*;
    use serde_json::json;

    fn admin() -> HashMap<String, String> {
        HashMap::from([("kind".into(), "user".into()), ("provider".into(), "mtls".into()),
            ("roles".into(), "viewer, openshell-admin".into())])
    }
    fn mount() -> Value {
        json!({"podman":{"mounts":[{"type":"volume", "source":"saw-harness-default-notebook-12345678",
            "target":"/sandbox/harness", "read_only":true}]}})
    }
    #[test]
    fn rejects_unresolved_workload_templates() {
        for key in ["workloadTemplate", "workload_template"] {
            let mut operation = json!({});
            operation[key] = json!("stored-template");
            assert!(!validate_sandbox_driver_config(&operation, &admin()).allowed);
            assert!(!validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);
            operation[key] = json!("");
            assert!(validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);
        }
        for key in ["driverConfig", "driver_config"] {
            let mut operation = json!({"spec":{"template":{}}});
            operation["spec"]["template"][key] = mount();
            assert!(validate_sandbox_driver_config(&operation, &admin()).allowed);
            assert!(!validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);
        }
    }
    #[test]
    fn accepts_installer_and_absent_or_empty_config() {
        assert!(validate_driver_config(Some(&mount()), &admin()).allowed);
        assert!(validate_driver_config(None, &HashMap::new()).allowed);
        assert!(validate_driver_config(Some(&json!({})), &HashMap::new()).allowed);
    }
    #[test]
    fn rejects_oidc_admin_and_nonadmin_mtls() {
        let mut principal = admin();
        principal.insert("provider".into(), "oidc".into());
        assert!(!validate_driver_config(Some(&mount()), &principal).allowed);
        principal = admin();
        principal.insert("roles".into(), "viewer".into());
        assert!(!validate_driver_config(Some(&mount()), &principal).allowed);
        principal = admin();
        principal.insert("kind".into(), "service".into());
        assert!(!validate_driver_config(Some(&mount()), &principal).allowed);
    }
    #[test]
    fn rejects_bind_wrong_source_target_and_mode() {
        for (key, value) in [("type", json!("bind")), ("source", json!("other")),
            ("source", json!("saw-harness-")), ("source", json!("")),
            ("target", json!("/other")), ("read_only", json!(false)), ("read_only", json!("true"))] {
            let mut config = mount();
            config["podman"]["mounts"][0][key] = value;
            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");
        }
        let mut config = mount();
        config["podman"]["mounts"][0].as_object_mut().unwrap().remove("read_only");
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
    }
    #[test]
    fn rejects_other_drivers_options_and_extra_mounts() {
        for config in [json!({"docker":{"mounts":[]}}), json!({"podman":{"mounts":[]}}),
            json!({"podman":{}}), json!({"podman":{"privileged":true}})] {
            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");
        }
        let mut config = mount();
        config["podman"]["privileged"] = json!(true);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = mount();
        config["podman"]["mounts"][0]["options"] = json!(["rw"]);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = mount();
        let duplicate = config["podman"]["mounts"][0].clone();
        config["podman"]["mounts"].as_array_mut().unwrap().push(duplicate);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
    }
    #[test]
    fn rejects_malformed_envelopes() {
        for config in [json!(null), json!(true), json!("bad"), json!([]),
            json!({"podman":null}), json!({"podman":{"mounts":null}}),
            json!({"podman":{"mounts":[null]}})] {
            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");
        }
    }
}
'''


def appended_rust(text):
    block = text.split("RUN printf '%s\\n'", 1)[1].split(">> src/main.rs", 1)[0]
    return "\n".join(re.findall(r"^\s*'(.*)'(?: \\)?$", block, re.MULTILINE)) + "\n"


@pytest.mark.parametrize("builder", ["dockerfile", "buildconfig"])
def test_exact_embedded_guard_behavior(builder, tmp_path):
    if not shutil.which("cargo"):
        pytest.skip("cargo is required to execute the embedded Rust guard tests")
    if builder == "buildconfig" and not HELM:
        pytest.skip("helm is required to render the BuildConfig")
    text = DOCKERFILE.read_text() if builder == "dockerfile" else inline_dockerfile()
    guard = appended_rust(text)
    (tmp_path / "src").mkdir()
    (tmp_path / "Cargo.toml").write_text('[package]\nname="guard-test"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nserde_json="1"\n')
    (tmp_path / "src/lib.rs").write_text(
        "use std::collections::HashMap;\nuse serde_json::Value;\n"
        "struct InterceptorResult { allowed: bool }\n"
        "fn allow() -> InterceptorResult { InterceptorResult { allowed: true } }\n"
        "fn deny(_: &str) -> InterceptorResult { InterceptorResult { allowed: false } }\n"
        + guard + ("" if "mod harness_driver_tests" in guard else RUST_BEHAVIOR_TESTS))
    result = subprocess.run(["cargo", "test", "--offline", "--manifest-path", str(tmp_path / "Cargo.toml")],
                            capture_output=True, text=True)
    if result.returncode and ("no matching package named" in result.stderr
                              or "attempting to make an HTTP request, but --offline was specified" in result.stderr):
        pytest.skip("serde_json dependencies are not cached; full image builders execute these tests in CI")
    assert result.returncode == 0, result.stdout + result.stderr


def test_builder_pins_and_runs_embedded_tests():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["source"]["git"]["ref"] == "v0.1.2"
    assert "ARG OPENSHELL_REF=v0.1.2" in DOCKERFILE.read_text()
    texts = [DOCKERFILE.read_text()]
    if HELM:
        texts.append(inline_dockerfile())
    for text in texts:
        assert RUST_BEHAVIOR_TESTS in appended_rust(text)
        assert "cargo test --locked --release --target-dir /out harness_driver_tests" in text
        assert "cargo build --locked --release --target-dir /out" in text


def test_pr_builds_are_unauthenticated_and_check_pin():
    action = yaml.safe_load((ROOT / ".github/actions/build-push-image/action.yml").read_text())
    steps = action["runs"]["steps"]
    login = next(step for step in steps if step.get("uses", "").startswith("docker/login-action"))
    build = next(step for step in steps if step.get("uses", "").startswith("docker/build-push-action"))
    assert login["if"] == build["with"]["push"]
    workflow = (ROOT / ".github/workflows/build-governance-interceptor.yml").read_text()
    assert "test \"$REF\" = \"$DEFAULT_REF\"" in workflow
    assert ".github/workflows/build-governance-interceptor.yml" in workflow
    assert ".github/actions/build-push-image/**" in workflow
    assert "file: ${{ runner.temp }}/governance-build.Dockerfile" in workflow
    assert "target: builder" in workflow
    assert "push: false" in workflow


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_both_builds_share_recipe_with_configurable_inputs():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-governance-interceptor.yml").read_text())
    action = next(s for s in workflow["jobs"]["build"]["steps"]
                  if s.get("uses") == "./.github/actions/build-push-image")
    assert ROOT / action["with"]["dockerfile"] == DOCKERFILE
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART),
        "--set", "source.git.uri=https://example.test/OpenShell.git", "--set", "source.git.ref=abc123",
        "--set", "build.builderImage=rust:test", "--set", "build.runtimeImage=ubi:test",
        "--set", "build.contextDir=examples/test"], text=True)
    build = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "BuildConfig")
    assert build["spec"]["source"]["dockerfile"].rstrip() == DOCKERFILE.read_text().rstrip()
    args = {a["name"]: a["value"] for a in build["spec"]["strategy"]["dockerStrategy"]["buildArgs"]}
    assert args == {"OPENSHELL_URI": "https://example.test/OpenShell.git", "OPENSHELL_REF": "abc123",
        "BUILDER_IMAGE": "rust:test", "RUNTIME_IMAGE": "ubi:test", "CONTEXT_DIR": "examples/test"}


def test_shared_recipe_preserves_both_runtime_variants():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["build"]["runtimeImage"] == "registry.access.redhat.com/ubi9-micro:latest"
    assert values["build"]["ghcrRuntimeImage"] == "debian-runtime"
    text = DOCKERFILE.read_text()
    assert "debian:bookworm-slim AS debian-runtime" in text
    assert "apt-get install -y ca-certificates" in text
    assert "FROM ${RUNTIME_IMAGE}\nCOPY --from=builder" in text
    assert "--platform=linux/amd64" not in text


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_default_build_output_is_internal_and_push_requires_explicit_destination():
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART)], text=True)
    build = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "BuildConfig")
    assert build["spec"]["output"]["to"] == {"kind": "ImageStreamTag", "name": "governance-interceptor:v0.1.2"}
    assert "pushSecret" not in build["spec"]["output"]
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART),
        "--set", "output.imageStreamTag=", "--set", "output.externalImage=ghcr.io/example/governance-interceptor:v0.1.2"], text=True)
    build = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "BuildConfig")
    assert build["spec"]["output"]["to"]["name"] == "ghcr.io/example/governance-interceptor:v0.1.2"
