"""Initial G-series offline contracts; these are not live ESO/CDI qualification."""

import json
from copy import deepcopy

import pytest
import yaml
from click.testing import CliRunner

from openshell_saw import config
from openshell_saw.blueprints import (
    ValidationError,
    load_document,
    render_enrollment,
    render_image,
    validate_enrollment,
)
from openshell_saw.cli import main


def select(resources, kind):
    return [r for r in resources if r["kind"] == kind]


@pytest.mark.parametrize("text", [
    "a: 1\na: 2", "a: {b: 1, b: 2}", "true: a", "[a]", "null", "",
    "a: &x {b: c}\nc: *x", "---\na: b\n---\nc: d", "a: [",
    '!!python/object/apply:os.system ["false"]', "x: " + "x" * (512 * 1024),
    "a: " + "[" * 100 + "0" + "]" * 100,
])
def test_strict_yaml_rejects_unsafe_or_ambiguous_input(text):
    with pytest.raises(ValidationError):
        load_document(text)


def test_yaml_error_does_not_echo_secret():
    with pytest.raises(ValidationError) as exc:
        load_document("x: [CREDENTIAL_CANARY")
    assert "CREDENTIAL_CANARY" not in str(exc.value)


def test_enrollment_is_deterministic_and_does_not_mutate(enrollment):
    original = deepcopy(enrollment)
    assert render_enrollment(enrollment) == render_enrollment(enrollment)
    assert enrollment == original
    ns = validate_enrollment(enrollment)["namespace"]
    assert ns.startswith("saw-research-") and len(ns) <= 63
    enrollment["spec"]["credentials"].reverse()
    assert render_enrollment(enrollment) == render_enrollment(original)


@pytest.mark.parametrize("field", ["subject", "issuer"])
def test_different_identity_gets_separate_namespace(enrollment, field):
    first = validate_enrollment(enrollment)["namespace"]
    enrollment["spec"]["owner"][field] += "-other"
    assert validate_enrollment(enrollment)["namespace"] != first


def test_saw_id_isolated_and_username_rename_does_not_change_vault_path(enrollment):
    first = validate_enrollment(enrollment)["namespace"]
    first_paths = set(render_enrollment(enrollment, "vault")["policy"]["path"])
    enrollment["spec"]["owner"]["username"] = "renamed"
    assert validate_enrollment(enrollment)["namespace"] == first
    assert set(render_enrollment(enrollment, "vault")["policy"]["path"]) == first_paths
    enrollment["metadata"]["name"] = "another-saw"
    assert validate_enrollment(enrollment)["namespace"] != first


@pytest.mark.parametrize("path,value", [
    (("spec", "owner", "username"), "../bob"),
    (("spec", "owner", "username"), "Alice"),
    (("spec", "owner", "subject"), ""),
    (("spec", "owner", "issuer"), "http://identity.example.test"),
    (("spec", "owner", "issuer"), "https://user:pass@identity.example.test"),
    (("spec", "vault", "prefix"), "saw/../bob"),
    (("spec", "vault", "prefix"), "/saw/users"),
    (("spec", "vault", "mount"), "secret/*"),
    (("spec", "vault", "authMount"), "../kubernetes"),
    (("spec", "vault", "server"), "https://vault.example.test?token=CANARY"),
    (("spec", "vault", "server"), "https://vault.example.test:bad"),
    (("spec", "vault", "audience"), "{{ evil }}"),
    (("spec", "vault", "caConfigMap"), ""),
    (("spec", "image", "diskSizeGi"), True),
    (("spec", "image", "diskSizeGi"), 0),
    (("spec", "image", "diskSizeGi"), "40Gi"),
    (("spec", "image", "namespace"), "../saw-images"),
    (("spec", "credentials"), []),
    (("spec", "credentials"), "nvidia"),
])
def test_invalid_enrollment_rejected(enrollment, path, value):
    target = enrollment
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        render_enrollment(enrollment)


@pytest.mark.parametrize("mutation", ["duplicate", "path", "template", "unknown", "missing", "empty-properties"])
def test_bad_credential_definitions(enrollment, mutation):
    cred = enrollment["spec"]["credentials"][0]
    if mutation == "duplicate":
        enrollment["spec"]["credentials"].append(deepcopy(cred))
    elif mutation == "path":
        cred["remoteKey"] = "../bob/nvidia"
    elif mutation == "template":
        cred["properties"]["api_key"] = "x }} {{ evil"
    elif mutation == "unknown":
        cred["api_key"] = "CANARY"
    elif mutation == "missing":
        del cred["remoteKey"]
    else:
        cred["properties"] = {}
    with pytest.raises(ValidationError) as exc:
        render_enrollment(enrollment)
    assert "CANARY" not in str(exc.value)


def test_namespace_and_source_are_separate(enrollment):
    enrollment["spec"]["image"]["namespace"] = validate_enrollment(enrollment)["namespace"]
    with pytest.raises(ValidationError):
        render_enrollment(enrollment)


def test_provider_secrets_are_namespace_local_and_single_record(enrollment):
    docs = render_enrollment(enrollment)
    ns = validate_enrollment(enrollment)["namespace"]
    assert not select(docs, "Secret")
    assert not select(docs, "ClusterSecretStore")
    assert not select(docs, "VirtualMachine")
    assert not select(docs, "Job")
    assert all(d["metadata"].get("namespace", ns) == ns for d in docs)
    for secret in select(docs, "ExternalSecret"):
        spec = secret["spec"]
        assert spec["secretStoreRef"] == {"name": "saw-user-vault", "kind": "SecretStore"}
        assert spec["target"]["template"]["mergePolicy"] == "Replace"
        assert spec["target"]["template"]["data"] == {"api_key": "{{ .api_key }}"}
        assert len(spec["dataFrom"]) == 1
        assert spec["dataFrom"][0]["extract"]["key"].startswith(
            f"saw/users/{validate_enrollment(enrollment)['identity']}/providers/")
        assert spec["target"]["deletionPolicy"] == "Retain"
    store = select(docs, "SecretStore")[0]["spec"]["provider"]["vault"]
    assert store["auth"]["kubernetes"]["role"] == ns
    assert store["auth"]["kubernetes"]["serviceAccountRef"]["audiences"] == ["vault"]
    assert "tokenSecretRef" not in store["auth"]
    policy = select(docs, "NetworkPolicy")[0]["spec"]
    assert policy == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
    assert all(not s["automountServiceAccountToken"] for s in select(docs, "ServiceAccount"))


def test_vault_policy_has_only_exact_user_reads(enrollment):
    out = render_enrollment(enrollment, "vault")
    assert set(out["policy"]["path"]) == {
        f"secret/data/saw/users/{validate_enrollment(enrollment)['identity']}/providers/nvidia",
        f"secret/data/saw/users/{validate_enrollment(enrollment)['identity']}/providers/brave"}
    assert all(v == {"capabilities": ["read"]} for v in out["policy"]["path"].values())
    assert out["role"]["bound_service_account_namespaces"] == [out["namespace"]]
    assert out["role"]["bound_service_account_names"] == ["saw-vault-reader"]
    assert out["role"]["audience"] == "vault"
    assert "*" not in json.dumps(out)


def test_clone_grants_no_source_mutation_or_secret_read(enrollment):
    docs = render_enrollment(enrollment, "clone-access")
    role, binding = docs
    assert role["metadata"]["namespace"] == "saw-images"
    assert role["rules"] == [
        {"apiGroups": ["cdi.kubevirt.io"], "resources": ["datasources"],
         "resourceNames": [enrollment["spec"]["image"]["dataSource"]], "verbs": ["get"]},
        {"apiGroups": ["cdi.kubevirt.io"], "resources": ["datavolumes/source"], "verbs": ["create"]}]
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "saw-provisioner",
                                    "namespace": validate_enrollment(enrollment)["namespace"]}]


def test_private_root_has_no_owner_reference_or_import_credentials(enrollment):
    root = render_enrollment(enrollment, "root")[0]
    assert root["kind"] == "DataVolume"
    assert root["spec"]["sourceRef"]["namespace"] == "saw-images"
    assert "source" not in root["spec"]
    assert "ownerReferences" not in root["metadata"]
    assert root["spec"]["storage"]["resources"]["requests"]["storage"] == "40Gi"


def test_image_import_identity_changes_with_digest_or_storage(golden_image):
    first = render_image(golden_image)
    assert render_image(golden_image) == first
    dv, ds = first[1:]
    assert dv["metadata"]["name"] == ds["spec"]["source"]["pvc"]["name"]
    assert dv["spec"]["source"]["registry"]["secretRef"] == "import-pull"
    assert dv["spec"]["source"]["registry"]["certConfigMap"] == "import-ca"
    golden_image["spec"]["registryURL"] = golden_image["spec"]["registryURL"].replace("a" * 64, "b" * 64)
    assert render_image(golden_image)[1]["metadata"]["name"] != dv["metadata"]["name"]
    before = render_image(golden_image)
    golden_image["spec"]["diskSizeGi"] = 80
    assert render_image(golden_image)[1]["metadata"]["name"] != before[1]["metadata"]["name"]


@pytest.mark.parametrize("url", ["docker://registry.test/image:latest", "http://registry.test/image",
                                     "docker://u:p@registry.test/image@sha256:" + "a" * 64,
                                     "docker://registry.test/image@sha256:<qualified-digest>"])
def test_import_requires_digest(golden_image, url):
    golden_image["spec"]["registryURL"] = url
    with pytest.raises(ValidationError):
        render_image(golden_image)


@pytest.mark.parametrize("part", ["tenant", "clone-access", "root", "vault"])
def test_cli_render_is_offline(enrollment, part, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "no-user-config")
    source = tmp_path / "enrollment.yaml"
    source.write_text(yaml.safe_dump(enrollment))
    def forbidden(*args, **kwargs):
        raise AssertionError("offline rendering attempted an external command")
    monkeypatch.setattr("subprocess.run", forbidden)
    result = CliRunner().invoke(main, ["blueprint", "render-tenant", "--config", str(source), "--part", part])
    assert result.exit_code == 0, result.output
    if part == "vault":
        assert "policy" in json.loads(result.output)
    else:
        assert list(yaml.safe_load_all(result.output))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["enrollment.yaml"]


def test_cli_invalid_input_has_no_partial_manifest_output(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "absent")
    source = tmp_path / "bad.yaml"
    source.write_text("credential: [CANARY")
    result = CliRunner().invoke(main, ["blueprint", "render-tenant", "--config", str(source)])
    assert result.exit_code != 0
    assert "Error: invalid YAML" in result.output
    assert "CANARY" not in result.output and "kind: Namespace" not in result.output
