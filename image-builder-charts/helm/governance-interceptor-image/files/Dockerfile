# OpenShell 0.1.x needs Rust 1.94 (rust-version in its Cargo.toml).
ARG BUILDER_IMAGE=rust:1.94-bookworm
ARG RUNTIME_IMAGE=debian-runtime

FROM ${BUILDER_IMAGE} AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev git make cmake g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build
ARG OPENSHELL_REF=v0.1.2
ARG OPENSHELL_URI=https://github.com/NVIDIA/OpenShell.git
ARG CONTEXT_DIR=examples/governance-interceptor
RUN git init . \
    && git remote add origin "${OPENSHELL_URI}" \
    && git fetch --depth 1 origin "${OPENSHELL_REF}" \
    && git checkout --detach FETCH_HEAD

WORKDIR /build/${CONTEXT_DIR}
# Workaround for NVIDIA/OpenShell#3929 (v0.1.2): the gateway hashes provider
# profile annotations in map order, so a profile with more than one annotation
# gives a different provider_env_revision on every call and no sandbox with a
# provider becomes ready ("Startup configuration did not stabilize"). Keep only
# the signature JWT, which already carries the hash (claim) and key id (header);
# the gateway treats the annotations as opaque. Drop this once #3929 is fixed.
RUN grep -q 'insert(PROFILE_HASH_ANNOTATION' src/main.rs \
    && grep -q 'PROFILE_SIGNATURE_KID_ANNOTATION.to_string()' src/main.rs \
    && perl -0pi -e 's/\n    profile\n        \.annotations\n        \.insert\(PROFILE_HASH_ANNOTATION\.to_string\(\), profile_hash\);\n    profile\.annotations\.insert\(\n        PROFILE_SIGNATURE_KID_ANNOTATION\.to_string\(\),\n        policy_signer\.kid\(\)\.to_string\(\),\n    \);\n/\n/' src/main.rs \
    && ! grep -q 'insert(PROFILE_HASH_ANNOTATION' src/main.rs
# Harness driver-config guard. allow_driver_config is a
# fleet-wide switch, and OpenShell's resource admission never inspects who sent
# a driver_config envelope or what mount mode it asks for
# (crates/openshell-core/src/resource_admission.rs). The interceptor sees both,
# so only an mTLS platform admin may mount one read-only saw-harness volume
# at /sandbox/harness. Template-based creates are refused because
# workload_template resolves after the seam and template RPCs are not interceptable.
RUN grep -q 'Ok(validate_create_sandbox(' src/main.rs \
    && perl -0pi -e 's#            \("CreateSandbox", interceptor_evaluation::Phase::Validate\(_\)\) => \{\n                Ok\(validate_create_sandbox\(#            ("CreateSandbox", interceptor_evaluation::Phase::Validate(_)) => {\n                let gate = validate_sandbox_driver_config(&operation, &evaluation.principal);\n                if !gate.allowed {\n                    return Ok(gate);\n                }\n                Ok(validate_create_sandbox(#' src/main.rs \
    && grep -q 'let gate = validate_sandbox_driver_config(' src/main.rs
RUN printf '%s\n' \
'' \
'const HARNESS_ADMIN_ROLE: &str = "openshell-admin";' \
'fn validate_sandbox_driver_config(operation: &Value, principal: &HashMap<String, String>) -> InterceptorResult {' \
'    if operation.get("workloadTemplate").or_else(|| operation.get("workload_template"))' \
'        .and_then(Value::as_str).is_some_and(|name| !name.is_empty()) {' \
'        return deny("workload templates are not allowed: driver config cannot be verified before template resolution");' \
'    }' \
'    validate_driver_config(operation.pointer("/spec/template/driverConfig")' \
'        .or_else(|| operation.pointer("/spec/template/driver_config")), principal)' \
'}' \
'' \
'/// Admit only the installer identity and its single read-only harness volume.' \
'fn validate_driver_config(' \
'    driver_config: Option<&Value>,' \
'    principal: &HashMap<String, String>,' \
') -> InterceptorResult {' \
'    let Some(config) = driver_config else { return allow(); };' \
'    let Some(drivers) = config.as_object() else {' \
'        return deny("driver config must be an object");' \
'    };' \
'    if drivers.is_empty() { return allow(); }' \
'    let is_admin = principal.get("kind").map(String::as_str) == Some("user")' \
'        && principal.get("provider").map(String::as_str) == Some("mtls")' \
'        && principal.get("roles").is_some_and(|roles| {' \
'            roles.split(",").any(|role| role.trim() == HARNESS_ADMIN_ROLE)' \
'        });' \
'    if !is_admin {' \
'        return deny("driver config may only be submitted by a platform admin mTLS identity");' \
'    }' \
'    let Some(podman) = drivers.get("podman").and_then(Value::as_object) else {' \
'        return deny("driver config must contain only podman harness mounts");' \
'    };' \
'    if drivers.len() != 1 || podman.len() != 1 {' \
'        return deny("driver config contains unsupported drivers or options");' \
'    }' \
'    let Some(mounts) = podman.get("mounts").and_then(Value::as_array) else {' \
'        return deny("driver config mounts must be an array");' \
'    };' \
'    if mounts.len() != 1 {' \
'        return deny("driver config must contain exactly one harness mount");' \
'    }' \
'    let Some(mount) = mounts[0].as_object() else {' \
'        return deny("driver config mount must be an object");' \
'    };' \
'    let valid_source = mount.get("source").and_then(Value::as_str)' \
'        .is_some_and(|source| source.starts_with("saw-harness-") && source.len() > "saw-harness-".len());' \
'    if mount.len() != 4' \
'        || mount.get("type").and_then(Value::as_str) != Some("volume")' \
'        || !valid_source' \
'        || mount.get("target").and_then(Value::as_str) != Some("/sandbox/harness")' \
'        || mount.get("read_only") != Some(&Value::Bool(true))' \
'    {' \
'        return deny("driver config must be a read-only saw-harness volume at /sandbox/harness");' \
'    }' \
'    allow()' \
'}' \
'#[cfg(test)]' \
'mod harness_driver_tests {' \
'    use super::*;' \
'    use serde_json::json;' \
'' \
'    fn admin() -> HashMap<String, String> {' \
'        HashMap::from([("kind".into(), "user".into()), ("provider".into(), "mtls".into()),' \
'            ("roles".into(), "viewer, openshell-admin".into())])' \
'    }' \
'    fn mount() -> Value {' \
'        json!({"podman":{"mounts":[{"type":"volume", "source":"saw-harness-default-notebook-12345678",' \
'            "target":"/sandbox/harness", "read_only":true}]}})' \
'    }' \
'    #[test]' \
'    fn rejects_unresolved_workload_templates() {' \
'        for key in ["workloadTemplate", "workload_template"] {' \
'            let mut operation = json!({});' \
'            operation[key] = json!("stored-template");' \
'            assert!(!validate_sandbox_driver_config(&operation, &admin()).allowed);' \
'            assert!(!validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);' \
'            operation[key] = json!("");' \
'            assert!(validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);' \
'        }' \
'        for key in ["driverConfig", "driver_config"] {' \
'            let mut operation = json!({"spec":{"template":{}}});' \
'            operation["spec"]["template"][key] = mount();' \
'            assert!(validate_sandbox_driver_config(&operation, &admin()).allowed);' \
'            assert!(!validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);' \
'        }' \
'    }' \
'    #[test]' \
'    fn accepts_installer_and_absent_or_empty_config() {' \
'        assert!(validate_driver_config(Some(&mount()), &admin()).allowed);' \
'        assert!(validate_driver_config(None, &HashMap::new()).allowed);' \
'        assert!(validate_driver_config(Some(&json!({})), &HashMap::new()).allowed);' \
'    }' \
'    #[test]' \
'    fn rejects_oidc_admin_and_nonadmin_mtls() {' \
'        let mut principal = admin();' \
'        principal.insert("provider".into(), "oidc".into());' \
'        assert!(!validate_driver_config(Some(&mount()), &principal).allowed);' \
'        principal = admin();' \
'        principal.insert("roles".into(), "viewer".into());' \
'        assert!(!validate_driver_config(Some(&mount()), &principal).allowed);' \
'        principal = admin();' \
'        principal.insert("kind".into(), "service".into());' \
'        assert!(!validate_driver_config(Some(&mount()), &principal).allowed);' \
'    }' \
'    #[test]' \
'    fn rejects_bind_wrong_source_target_and_mode() {' \
'        for (key, value) in [("type", json!("bind")), ("source", json!("other")),' \
'            ("source", json!("saw-harness-")), ("source", json!("")),' \
'            ("target", json!("/other")), ("read_only", json!(false)), ("read_only", json!("true"))] {' \
'            let mut config = mount();' \
'            config["podman"]["mounts"][0][key] = value;' \
'            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");' \
'        }' \
'        let mut config = mount();' \
'        config["podman"]["mounts"][0].as_object_mut().unwrap().remove("read_only");' \
'        assert!(!validate_driver_config(Some(&config), &admin()).allowed);' \
'    }' \
'    #[test]' \
'    fn rejects_other_drivers_options_and_extra_mounts() {' \
'        for config in [json!({"docker":{"mounts":[]}}), json!({"podman":{"mounts":[]}}),' \
'            json!({"podman":{}}), json!({"podman":{"privileged":true}})] {' \
'            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");' \
'        }' \
'        let mut config = mount();' \
'        config["podman"]["privileged"] = json!(true);' \
'        assert!(!validate_driver_config(Some(&config), &admin()).allowed);' \
'        config = mount();' \
'        config["podman"]["mounts"][0]["options"] = json!(["rw"]);' \
'        assert!(!validate_driver_config(Some(&config), &admin()).allowed);' \
'        config = mount();' \
'        let duplicate = config["podman"]["mounts"][0].clone();' \
'        config["podman"]["mounts"].as_array_mut().unwrap().push(duplicate);' \
'        assert!(!validate_driver_config(Some(&config), &admin()).allowed);' \
'    }' \
'    #[test]' \
'    fn rejects_malformed_envelopes() {' \
'        for config in [json!(null), json!(true), json!("bad"), json!([]),' \
'            json!({"podman":null}), json!({"podman":{"mounts":null}}),' \
'            json!({"podman":{"mounts":[null]}})] {' \
'            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");' \
'        }' \
'    }' \
'}' \
>> src/main.rs
RUN cargo test --locked --release --target-dir /out harness_driver_tests \
    && cargo build --locked --release --target-dir /out

FROM debian:bookworm-slim AS debian-runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

FROM ${RUNTIME_IMAGE}
COPY --from=builder /out/release/governance-interceptor /usr/local/bin/governance-interceptor
ENTRYPOINT ["governance-interceptor"]
