from pathlib import Path
import subprocess

import pytest
import yaml


CHART = Path(__file__).resolve().parents[2] / "charts/saw-image-cache"
IMAGE = "example.test/models/cuda@sha256:" + "a" * 64


def render(*args):
    return subprocess.run(["helm", "template", "approved-images", str(CHART), *args],
                          capture_output=True, text=True)


def test_cache_is_opt_in():
    result = render()
    assert result.returncode == 0 and not result.stdout.strip()


@pytest.mark.parametrize("images", [[], ["example.test/models/cuda:latest"], [IMAGE + "BAD"]])
def test_enabled_cache_rejects_missing_or_mutable_references(images):
    args = [arg for index, image in enumerate(images)
            for arg in ("--set-string", f"images[{index}]={image}")]
    assert render("--set", "enabled=true", *args).returncode != 0


def test_cache_mounts_approved_images_without_executing_them():
    result = render("--set", "enabled=true", "--set-string", f"images[0]={IMAGE}",
                    "--set-string", f"images[1]={IMAGE}")
    assert result.returncode == 0, result.stderr
    objects = {o["kind"]: o for o in yaml.safe_load_all(result.stdout)}
    assert set(objects) == {"DaemonSet", "ServiceAccount", "NetworkPolicy"}
    pod = objects["DaemonSet"]["spec"]["template"]["spec"]
    assert not pod["automountServiceAccountToken"] and not objects["ServiceAccount"]["automountServiceAccountToken"]
    assert pod["securityContext"] == {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    assert pod["volumes"] == [{"name": "image-0", "image": {"reference": IMAGE, "pullPolicy": "IfNotPresent"}}]
    holder, = pod["containers"]
    assert holder["image"] != IMAGE and holder["command"] == ["/usr/bin/sleep", "infinity"]
    assert holder["securityContext"] == {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                         "capabilities": {"drop": ["ALL"]}}
    assert holder["volumeMounts"] == [{"name": "image-0", "mountPath": "/images/0", "readOnly": True}]
    policy = objects["NetworkPolicy"]["spec"]
    assert set(policy["policyTypes"]) == {"Ingress", "Egress"} and not policy.get("egress") and not policy.get("ingress")
