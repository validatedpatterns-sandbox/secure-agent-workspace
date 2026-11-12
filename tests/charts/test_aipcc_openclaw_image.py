"""The shared BOM pins AIPCC OpenClaw. Container sites add UID traversal at build time.

It replaced openclaw-openshell, an image of our own built on it. What that
image added is now covered elsewhere:
- nsenter and nft (OpenShell's supervisor): in the AIPCC image since 2026.9.6.
- OpenClaw under /opt/openclaw, where the sandbox could not read it: the
  sandbox policy allows /opt/openclaw (read only), not all of /opt.
- USER sandbox:sandbox, HOME/OPENCLAW_HOME=/sandbox, SQLITE_TMPDIR/TMPDIR and
  /sandbox/.openclaw/state (owned by sandbox, mode 700): made by the AIPCC
  image build. Its node is /usr/bin/node-26, which the provider profiles'
  /usr/bin/node-* covers.
- The @openclaw/openshell-sandbox plugin is not in it; nothing here uses it.
"""
import shutil
from pathlib import Path

from helm_cache import run_helm

import pytest

import yaml

ROOT = Path(__file__).resolve().parents[2]
AIPCC = "quay.io/aipcc/base-images/agentic/openclaw@sha256:"


def openclaw_sandboxes():
    for path in sorted((ROOT / "charts" / "saw-bom" / "profiles").glob("*/*/sandbox.yaml")):
        for sb in yaml.safe_load(path.read_text())["spec"]["sandboxes"]:
            if sb.get("type") == "openclaw":
                yield path, sb


@pytest.mark.ci_external
def test_openclaw_sandboxes_use_the_aipcc_image():
    found = list(openclaw_sandboxes())
    assert found
    for path, sb in found:
        if path.relative_to(ROOT / "charts/saw-bom/profiles").parts[0] == "audited-openclaw":
            assert sb["image"] == "ghcr.io/openclaw/openclaw@sha256:0a5ff5e682e62afa19149df126aa50063bf65ef885b5c94713ce32dc0eb12e15"
        else:
            assert sb["image"].startswith(AIPCC), f"{path}: {sb['image']}"


@pytest.mark.ci_external
def test_the_policy_lets_the_sandbox_read_openclaw_under_opt():
    policy = yaml.safe_load((ROOT / "charts" / "governance-policy" / "policy.yaml").read_text())
    fs = policy["filesystem_policy"]
    assert "/opt/openclaw" in fs["read_only"]
    assert "/opt" not in fs["read_only"] + fs["read_write"], "only OpenClaw's directory, not all of /opt"
    assert not any(p.startswith("/opt") for p in fs["read_write"])


@pytest.mark.ci_external
def test_no_image_of_our_own_is_built():
    assert not (ROOT / "image-builder-charts" / "helm" / "openclaw-openshell-image").exists()
    assert "openclaw-openshell" not in (ROOT / "Makefile-quickstart").read_text()


@pytest.mark.parametrize("trigger", [True, False])
def test_container_notebook_builder_preserves_image_user_and_contents(trigger):
    helm = shutil.which("helm")
    if not helm:
        pytest.skip("helm is not installed")
    image = next(sb["image"] for path, sb in openclaw_sandboxes()
                 if path.parent.name == "default" and path.parent.parent.name == "data-science"
                 and sb["name"] == "notebook")
    options = [] if trigger else ["--set", "configChangeTrigger=false",
                                   "--set-string", "buildArchitecture=amd64"]
    out = run_helm([helm, "template", "test", str(ROOT / "image-builder-charts/helm/openshift-home-access"),
                    "--set-string", "images[0].name=notebook", "--set-string", "images[0].from="+image,
                    "--set-string", "images[0].imageUser=sandbox:sandbox", *options],
                   capture_output=True, text=True, check=True)
    build = next(d["spec"] for d in yaml.safe_load_all(out.stdout) if d and d["kind"] == "BuildConfig")
    assert build["source"]["dockerfile"].splitlines() == [
        "FROM "+image, "USER 0", "RUN test -d /sandbox && chmod o+x /sandbox", "USER sandbox:sandbox"]
    assert build["triggers"] == ([{"type": "ConfigChange"}] if trigger else [])
    assert build.get("nodeSelector") == (None if trigger else {"kubernetes.io/arch": "amd64"})
