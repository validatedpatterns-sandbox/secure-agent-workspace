// SAW admission extension. Called through the stock governance interceptor API.
use super::*;

const SAW_ADMIN_ROLE: &str = "openshell-admin";
pub(crate) fn validate_sandbox_driver_config(operation: &Value, principal: &HashMap<String, String>) -> InterceptorResult {
    if operation.get("workloadTemplate").or_else(|| operation.get("workload_template"))
        .and_then(Value::as_str).is_some_and(|name| !name.is_empty()) {
        return deny("workload templates are not allowed: driver config cannot be verified before template resolution");
    }
    validate_driver_config(operation.pointer("/spec/template/driverConfig")
        .or_else(|| operation.pointer("/spec/template/driver_config")), principal)
}

fn valid_volume(mount: &Value, prefix: &str, target: &str, read_only: bool) -> bool {
    let Some(fields) = mount.as_object() else { return false; };
    fields.len() == 4
        && fields.get("type").and_then(Value::as_str) == Some("volume")
        && fields.get("source").and_then(Value::as_str)
            .is_some_and(|source| source.starts_with(prefix) && source.len() > prefix.len())
        && fields.get("target").and_then(Value::as_str) == Some(target)
        && fields.get("read_only") == Some(&Value::Bool(read_only))
}

fn validate_driver_config(
    driver_config: Option<&Value>,
    principal: &HashMap<String, String>,
) -> InterceptorResult {
    let Some(config) = driver_config else { return allow(); };
    let Some(drivers) = config.as_object() else {
        return deny("driver config must be an object");
    };
    if drivers.is_empty() { return allow(); }
    let is_admin = principal.get("kind").map(String::as_str) == Some("user")
        && principal.get("provider").map(String::as_str) == Some("mtls")
        && principal.get("roles").is_some_and(|roles| {
            roles.split(",").any(|role| role.trim() == SAW_ADMIN_ROLE)
        });
    if !is_admin {
        return deny("driver config may only be submitted by a platform admin mTLS identity");
    }
    if let Some(kubernetes) = drivers.get("kubernetes") {
        return if drivers.len() == 1 && valid_kubernetes_driver(kubernetes) { allow() }
            else { deny("Kubernetes driver config must use the approved retained-PVC envelope") };
    }
    let Some(podman) = drivers.get("podman").and_then(Value::as_object) else {
        return deny("driver config must contain only podman agent mounts");
    };
    if drivers.len() != 1 || podman.len() != 1 {
        return deny("driver config contains unsupported drivers or options");
    }
    let Some(mounts) = podman.get("mounts").and_then(Value::as_array) else {
        return deny("driver config mounts must be an array");
    };
    let valid = match mounts.as_slice() {
        [gate, audit] => valid_volume(gate, "saw-gate-", "/sandbox/.saw/trusted", true)
            && valid_volume(audit, "saw-audit-", "/sandbox/.saw/audit", false),
        [harness, gate, audit] => valid_volume(harness, "saw-harness-", "/sandbox/harness", true)
            && valid_volume(gate, "saw-gate-", "/sandbox/.saw/trusted", true)
            && valid_volume(audit, "saw-audit-", "/sandbox/.saw/audit", false),
        _ => false,
    };
    if !valid {
        return deny("driver config must contain gate and audit volumes, with an optional read-only harness");
    }
    allow()
}

// SAW integration policy: only a platform mTLS admin may select retained PVCs.
// Live namespace/PVC UID and attachment approval stay in the reconciler/driver.
fn k8s_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len()-1].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == 45)
}
fn k8s_quantity(value: &Value) -> bool {
    let Some(text) = value.as_str() else { return false; };
    let digits = text.bytes().take_while(|b| b.is_ascii_digit()).count();
    digits > 0 && text.as_bytes()[0] != 48
        && ["", "m", "Ki", "Mi", "Gi", "Ti"].contains(&&text[digits..])
}
fn valid_kubernetes_driver(config: &Value) -> bool {
    let Some(driver) = config.as_object() else { return false; };
    if driver.keys().any(|k| !["volumes", "containers"].contains(&k.as_str())) { return false; }
    let Some(volumes) = driver.get("volumes").and_then(Value::as_array) else { return false; };
    let Some(containers) = driver.get("containers").and_then(Value::as_object) else { return false; };
    let Some(agent) = containers.get("agent").and_then(Value::as_object) else { return false; };
    if containers.len() != 1 || agent.len() != 2 { return false; }
    let Some(mounts) = agent.get("volume_mounts").and_then(Value::as_array) else { return false; };
    let Some(resources) = agent.get("resources").and_then(Value::as_object) else { return false; };
    for (group, values) in resources {
        if !["requests", "limits"].contains(&group.as_str()) { return false; }
        let Some(values) = values.as_object() else { return false; };
        if values.iter().any(|(k,v)| !["cpu", "memory", "ephemeral-storage"].contains(&k.as_str()) || !k8s_quantity(v)) { return false; }
    }
    let gate = mounts.get(1).and_then(|m| m.get("name")).and_then(Value::as_str) == Some("saw-gate");
    let reserved = if gate { 3 } else { 1 };
    if volumes.len() < reserved || volumes.len() > reserved + 16 || mounts.len() < volumes.len() { return false; }
    // The briefing harness reuses two approved PVCs. These are the only aliases
    // allowed; base mounts still have a one-to-one ordered volume mapping.
    let aliases = &mounts[volumes.len()..];
    if !aliases.is_empty() {
        if !gate || aliases.len() != 2 { return false; }
        for (mount, name, path, ro) in [
            (&aliases[0], "saw-gate", "/sandbox/harness", true),
            (&aliases[1], "saw-workspace", "/sandbox/briefing", false),
        ] {
            let Some(fields) = mount.as_object() else { return false; };
            if fields.len() != 4 || fields.get("name").and_then(Value::as_str) != Some(name)
                || fields.get("mount_path").and_then(Value::as_str) != Some(path)
                || fields.get("read_only").and_then(Value::as_bool) != Some(ro) { return false; }
            let Some(sub) = fields.get("sub_path").and_then(Value::as_str) else { return false; };
            if ro {
                let Some(digest) = sub.strip_prefix("harness-") else { return false; };
                if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return false; }
            } else if sub != "briefing" { return false; }
        }
    }
    let mut paths: Vec<String> = Vec::new();
    let mut claims: Vec<String> = Vec::new();
    for (index, (volume, mount)) in volumes.iter().zip(mounts.iter()).enumerate() {
        let Some(v) = volume.as_object() else { return false; };
        let Some(m) = mount.as_object() else { return false; };
        let name = match (index, gate) {
            (0, _) => "saw-workspace".into(), (1, true) => "saw-gate".into(), (2, true) => "saw-audit".into(),
            _ => format!("data-{}", index-reserved),
        };
        let reserved_mount = gate && (index == 1 || index == 2);
        if v.len() != 2 || m.len() != (if reserved_mount { 4 } else { 3 }) || v.get("name").and_then(Value::as_str) != Some(name.as_str())
            || m.get("name").and_then(Value::as_str) != Some(name.as_str()) { return false; }
        let Some(pvc) = v.get("persistent_volume_claim").and_then(Value::as_object) else { return false; };
        if pvc.len() != 2 { return false; }
        let Some(claim) = pvc.get("claim_name").and_then(Value::as_str) else { return false; };
        let Some(read_only) = pvc.get("read_only").and_then(Value::as_bool) else { return false; };
        if (!reserved_mount && (claim.starts_with("saw-gate-") || claim.starts_with("saw-audit-")))
            || !k8s_name(claim) || claims.iter().any(|c| c == claim)
            || m.get("read_only").and_then(Value::as_bool) != Some(read_only) { return false; }
        let Some(path) = m.get("mount_path").and_then(Value::as_str) else { return false; };
        if index == 0 {
            if path != "/sandbox/workspace" || read_only { return false; }
        } else if gate && index == 1 {
            if m.get("sub_path").and_then(Value::as_str) != Some("bundle") || path != "/sandbox/.saw/trusted" || !read_only || !claim.starts_with("saw-gate-") { return false; }
        } else if gate && index == 2 {
            if m.get("sub_path").and_then(Value::as_str) != Some("log") || path != "/sandbox/.saw/audit" || read_only || !claim.starts_with("saw-audit-") { return false; }
        } else if !(path == "/data" || path.starts_with("/data/"))
            || path[1..].split("/").any(|p| p.is_empty() || p == "." || p == "..")
            || path.chars().any(|c| c.is_control()) { return false; }
        if paths.iter().any(|p| p == path || path.starts_with(&format!("{p}/")) || p.starts_with(&format!("{path}/"))) { return false; }
        paths.push(path.to_string());
        claims.push(claim.to_string());
    }
    true
}
#[cfg(test)]
mod agent_driver_tests {
    use super::*;
    use serde_json::json;

    fn admin() -> HashMap<String, String> {
        HashMap::from([("kind".into(), "user".into()), ("provider".into(), "mtls".into()),
            ("roles".into(), "viewer, openshell-admin".into())])
    }
    fn gate_and_audit() -> Value {
        json!({"podman":{"mounts":[
            {"type":"volume", "source":"saw-gate-default-notebook-12345678",
             "target":"/sandbox/.saw/trusted", "read_only":true},
            {"type":"volume", "source":"saw-audit-default-notebook-12345678",
             "target":"/sandbox/.saw/audit", "read_only":false}
        ]}})
    }
    fn with_harness() -> Value {
        let mut config = gate_and_audit();
        config["podman"]["mounts"].as_array_mut().unwrap().insert(0,
            json!({"type":"volume", "source":"saw-harness-default-notebook-12345678",
                   "target":"/sandbox/harness", "read_only":true}));
        config
    }
    #[test]
    fn rejects_unresolved_workload_templates() {
        for key in ["workloadTemplate", "workload_template"] {
            let mut operation = json!({});
            operation[key] = json!("stored-template");
            assert!(!validate_sandbox_driver_config(&operation, &admin()).allowed);
            operation[key] = json!("");
            assert!(validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);
        }
        for key in ["driverConfig", "driver_config"] {
            let mut operation = json!({"spec":{"template":{}}});
            operation["spec"]["template"][key] = with_harness();
            assert!(validate_sandbox_driver_config(&operation, &admin()).allowed);
            assert!(!validate_sandbox_driver_config(&operation, &HashMap::new()).allowed);
        }
    }
    #[test]
    fn accepts_exact_installer_combinations_and_empty_config() {
        assert!(validate_driver_config(Some(&gate_and_audit()), &admin()).allowed);
        assert!(validate_driver_config(Some(&with_harness()), &admin()).allowed);
        assert!(validate_driver_config(None, &HashMap::new()).allowed);
        assert!(validate_driver_config(Some(&json!({})), &HashMap::new()).allowed);
    }
    #[test]
    fn rejects_oidc_admin_and_nonadmin_mtls() {
        let mut principal = admin();
        principal.insert("provider".into(), "oidc".into());
        assert!(!validate_driver_config(Some(&gate_and_audit()), &principal).allowed);
        principal = admin();
        principal.insert("roles".into(), "viewer".into());
        assert!(!validate_driver_config(Some(&gate_and_audit()), &principal).allowed);
        principal = admin();
        principal.insert("kind".into(), "service".into());
        assert!(!validate_driver_config(Some(&gate_and_audit()), &principal).allowed);
    }
    #[test]
    fn rejects_wrong_source_target_type_and_mode() {
        for index in 0..2 {
            for (key, value) in [("type", json!("bind")), ("source", json!("other")),
                ("source", json!("saw-gate-")), ("target", json!("/other")),
                ("read_only", json!("wrong"))] {
                let mut config = gate_and_audit();
                config["podman"]["mounts"][index][key] = value;
                assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");
            }
        }
        let mut config = gate_and_audit();
        config["podman"]["mounts"][0]["read_only"] = json!(false);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = gate_and_audit();
        config["podman"]["mounts"][1]["read_only"] = json!(true);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
    }
    #[test]
    fn rejects_other_drivers_options_and_mount_combinations() {
        for config in [json!({"docker":{"mounts":[]}}), json!({"podman":{"mounts":[]}}),
            json!({"podman":{}}), json!({"podman":{"privileged":true}})] {
            assert!(!validate_driver_config(Some(&config), &admin()).allowed, "accepted {config}");
        }
        let mut config = gate_and_audit();
        config["podman"]["privileged"] = json!(true);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = gate_and_audit();
        config["podman"]["mounts"][0]["options"] = json!(["rw"]);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = gate_and_audit();
        config["podman"]["mounts"].as_array_mut().unwrap().swap(0, 1);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = gate_and_audit();
        config["podman"]["mounts"].as_array_mut().unwrap().pop();
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
        config = with_harness();
        config["podman"]["mounts"].as_array_mut().unwrap().push(json!(null));
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
    fn k8s() -> Value {
        json!({"kubernetes":{
            "volumes":[{"name":"saw-workspace","persistent_volume_claim":{"claim_name":"alice-workspace","read_only":false}}],
            "containers":{"agent":{"volume_mounts":[{"name":"saw-workspace","mount_path":"/sandbox/workspace","read_only":false}],"resources":{"requests":{"cpu":"250m","memory":"512Mi"}}}}
        }})
    }
    #[test]
    fn kubernetes_tool_gate_requires_fixed_pair_and_admin() {
        let mut config = k8s();
        let driver = &mut config["kubernetes"];
        for (name, sub, path, ro) in [("saw-gate","bundle","/sandbox/.saw/trusted",true),
                                      ("saw-audit","log","/sandbox/.saw/audit",false)] {
            driver["volumes"].as_array_mut().unwrap().push(json!({"name":name,"persistent_volume_claim":{"claim_name":format!("{name}-test"),"read_only":ro}}));
            driver["containers"]["agent"]["volume_mounts"].as_array_mut().unwrap().push(json!({"name":name,"mount_path":path,"sub_path":sub,"read_only":ro}));
        }
        assert!(validate_driver_config(Some(&config), &admin()).allowed);
        for (pointer, value) in [
            ("/kubernetes/containers/agent/volume_mounts/1/sub_path",json!("..")),
            ("/kubernetes/containers/agent/volume_mounts/2/mount_path",json!("/etc")),
            ("/kubernetes/volumes/2/persistent_volume_claim/claim_name",json!("workspace")),
        ] {
            let mut bad = config.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(!validate_driver_config(Some(&bad), &admin()).allowed);
        }
        config["kubernetes"]["volumes"][1]["persistent_volume_claim"]["read_only"] = json!(false);
        config["kubernetes"]["containers"]["agent"]["volume_mounts"][1]["read_only"] = json!(false);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
    }
    #[test]
    fn kubernetes_requires_admin_and_allows_only_pvc_shape() {
        let mut config = k8s();
        assert!(validate_driver_config(Some(&config), &admin()).allowed);
        assert!(!validate_driver_config(Some(&config), &HashMap::new()).allowed);
        let mut oidc = admin(); oidc.insert("provider".into(), "oidc".into());
        assert!(!validate_driver_config(Some(&config), &oidc).allowed);
        config["kubernetes"]["volumes"].as_array_mut().unwrap().push(json!({"name":"data-0","persistent_volume_claim":{"claim_name":"alice-data","read_only":true}}));
        config["kubernetes"]["containers"]["agent"]["volume_mounts"].as_array_mut().unwrap().push(json!({"name":"data-0","mount_path":"/data/models","read_only":true}));
        assert!(validate_driver_config(Some(&config), &admin()).allowed);
        for path in ["/etc", "/sandbox/plugin", "/data/../etc", "/data//bad", "/data/x/", "/data/./x", "/data/x\n"] {
            let mut bad = config.clone();
            bad["kubernetes"]["containers"]["agent"]["volume_mounts"][1]["mount_path"] = json!(path);
            assert!(!validate_driver_config(Some(&bad), &admin()).allowed);
        }
        config["kubernetes"]["containers"]["agent"]["volume_mounts"][1]["read_only"] = json!(false);
        assert!(!validate_driver_config(Some(&config), &admin()).allowed);
    }
    #[test]
    fn kubernetes_rejects_privilege_paths_and_malformed_options() {
        for (pointer, value) in [
            ("/kubernetes/volumes/0", json!({"name":"saw-workspace","host_path":{"path":"/"}})),
            ("/kubernetes/volumes/0/persistent_volume_claim", json!({"claim_name":"alice-workspace"})),
            ("/kubernetes/containers/agent", json!({"volume_mounts":[],"resources":{},"security_context":{"privileged":true}})),
            ("/kubernetes/containers", json!({"agent":{},"extra":{}})),
            ("/kubernetes/volumes", json!([])),
            ("/kubernetes/containers/agent/volume_mounts/0/mount_path", json!("/sandbox")),
            ("/kubernetes/volumes/0/persistent_volume_claim/claim_name", json!("../secret")),
            ("/kubernetes/containers/agent/resources", json!({"requests":{"cpu":"0"}})),
            ("/kubernetes/containers/agent/resources", json!({"requests":{"gpu":"1"}})),
            ("/kubernetes/containers/agent/resources", json!({"requests":{"cpu":1}}))
        ] {
            let mut bad=k8s(); *bad.pointer_mut(pointer).unwrap()=value;
            assert!(!validate_driver_config(Some(&bad), &admin()).allowed, "accepted {bad}");
        }
        for pod in [json!({}),json!({"runtime_class_name":""}),json!({"host_network":true}),json!({"runtime_class_name":"custom-runtime"})] {
            let mut bad=k8s(); bad["kubernetes"]["pod"]=pod;
            assert!(!validate_driver_config(Some(&bad), &admin()).allowed);
        }
        let mut bad=k8s(); bad["podman"]=json!({});
        assert!(!validate_driver_config(Some(&bad), &admin()).allowed);
    }
}
