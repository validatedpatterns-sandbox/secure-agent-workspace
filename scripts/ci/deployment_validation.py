#!/usr/bin/env python3
"""Render charts and verify the dependencies used by a deployment."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
OWN_IMAGES = {
    "nemoclaw-sandbox",
    "nemoclaw-cli",
    "openshell-gateway",
    "openshell-gateway-docker",
    "governance-interceptor",
    "saw-credential-proxy",
}
SCHEMA_LOCATIONS = (
    str(ROOT / "scripts/ci/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"),
    "default",
    "https://raw.githubusercontent.com/melmorabity/openshift-json-schemas/"
    "main/v4.18-standalone-strict/{{.ResourceKind}}.json",
    "https://raw.githubusercontent.com/datreeio/CRDs-catalog/"
    "main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json",
)
IMAGE_KEY = re.compile(r"(^image$|image$|^baseImage$|^builderImage$|^runtimeImage$)")
SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class Reference:
    kind: str
    value: str
    source: str
    path: str


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checked: dict[str, int] = {}

    def error(self, source: str, path: str, message: str) -> None:
        self.errors.append(f"{source}:{path}: {message}")

    def count(self, name: str) -> None:
        self.checked[name] = self.checked.get(name, 0) + 1


def read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a YAML map")
    return value


def chart_args(chart: Path, mode="proxy") -> list[str]:
    name = chart.name
    if name == "openshell-saw":
        if mode == "direct":
            return ["-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                    "--set", "sandboxName=ciowner", "--set", "credentialProxy.enabled=false"]
        return ["-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                "--set", "sandboxName=ciowner"]
    if name == "saw-users":
        return ["-f", str(ROOT / "tests/fixtures/deployment-validation-users.yaml")]
    if name == "openshell-keycloak":
        return ["-f", str(ROOT / "tests/fixtures/deployment-validation-keycloak.yaml")]
    if name == "nemoclaw-imagestream":
        return ["--set-string", "build.targetArch=amd64",
                "--set-string", "source.discoveryImage="
                "image-registry.openshift-image-registry.svc:5000/"
                "openshell-agents/nemoclaw-discovery-runtime@sha256:" + "0" * 64]
    if name == "openshell-gateway-image":
        return ["--set", "goldenImage.enabled=false"]
    return []


def charts() -> list[Path]:
    return sorted((*ROOT.glob("charts/*/Chart.yaml"),
                   *ROOT.glob("image-builder-charts/helm/*/Chart.yaml")))


def render_charts(result: Validation, output_dir: Path) -> None:
    variants = [(path, mode) for path in charts()
                for mode in (["proxy", "direct"] if path.parent.name == "openshell-saw" else ["proxy"])]
    for chart_file, mode in variants:
        chart = chart_file.parent
        label = chart.relative_to(ROOT).as_posix()
        args = chart_args(chart, mode)
        if mode == "direct":
            label += "-direct"
        for command in (
            ["helm", "lint", str(chart), *args],
            ["helm", "template", chart.name, str(chart), "--debug", *args],
        ):
            run = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                 timeout=90, check=False)
            if run.returncode:
                result.error(label, "helm", run.stderr.strip() or run.stdout.strip())
                break
            if command[1] == "template":
                path = output_dir / (label.replace("/", "_") + ".yaml")
                path.write_text(run.stdout, encoding="utf-8")
                documents = list(yaml.safe_load_all(run.stdout))
                if not any(isinstance(item, dict) and item.get("kind") for item in documents):
                    result.error(label, "helm template", "no Kubernetes resources rendered")
                result.count("charts")


def validate_schemas(result: Validation, output_dir: Path) -> None:
    rendered = sorted(output_dir.glob("*.yaml"))
    if not rendered:
        result.error("charts", "schema", "no rendered resources to validate")
        return
    command = ["kubeconform", "-strict", "-summary", "-output", "json",
               "-kubernetes-version", "1.30.0"]
    for location in SCHEMA_LOCATIONS:
        command.extend(("-schema-location", location))
    run = subprocess.run([*command, *map(str, rendered)], cwd=ROOT, text=True,
                         capture_output=True, timeout=300, check=False)
    try:
        report = json.loads(run.stdout)
    except json.JSONDecodeError:
        result.error("charts", "schema", run.stderr.strip() or "invalid kubeconform output")
        return
    summary = report.get("summary") or {}
    for item in report.get("resources") or []:
        if item.get("status") != "VALID":
            filename = Path(item.get("filename") or "unknown").name
            kind = item.get("kind") or "resource"
            result.error(filename, kind, item.get("msg") or item.get("status") or "schema error")
    if run.returncode and not (report.get("resources") or []):
        result.error("charts", "schema", run.stderr.strip() or "kubeconform failed")
    if summary.get("skipped", 0):
        result.error("charts", "schema", f"{summary['skipped']} resources were skipped")
    if summary.get("valid", 0) == 0:
        result.error("charts", "schema", "no resources passed schema validation")
    result.checked["schema_resources"] = summary.get("valid", 0)


def walk_values(value: Any, source: str, prefix: str = "") -> list[Reference]:
    found: list[Reference] = []
    if isinstance(value, dict):
        git = value.get("git")
        if isinstance(git, dict) and git.get("uri") and git.get("ref"):
            found.append(Reference("git", f"{git['uri']}#{git['ref']}", source,
                                   f"{prefix}.git.ref".strip(".")))
        for key, item in value.items():
            path = f"{prefix}.{key}".strip(".")
            if isinstance(item, str) and item:
                if IMAGE_KEY.search(key) and not key.lower().endswith("imagestreamtag"):
                    if item not in {"base", "scratch", "debian-runtime"}:
                        found.append(Reference("image", item, source, path))
                elif key == "pipIndexUrl":
                    found.append(Reference("index", item, source, path))
            elif isinstance(item, (dict, list)):
                found.extend(walk_values(item, source, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(walk_values(item, source, f"{prefix}[{index}]"))
    return found


def is_own_image(image: str) -> bool:
    if image.startswith(("image-registry.openshift-image-registry.svc", "localhost/")):
        return True
    if image.startswith("ghcr.io/validatedpatterns-sandbox/"):
        name = image.split("/", 2)[-1].split("@", 1)[0].split(":", 1)[0]
        return name in OWN_IMAGES
    return False


def collect_references(output_dir: Path | None = None) -> list[Reference]:
    paths = [ROOT / "values-global.yaml", ROOT / "values-prod.yaml",
             ROOT / "charts/openshell-saw/values.yaml",
             ROOT / "tests/fixtures/deployment-validation-users.yaml"]
    paths.extend(ROOT.glob("charts/*/values.yaml"))
    paths.extend(ROOT.glob("image-builder-charts/helm/*/values.yaml"))
    paths.extend(ROOT.glob("charts/saw-bom/profiles/**/*.yaml"))
    found: list[Reference] = []
    for path in sorted(set(paths)):
        source = path.relative_to(ROOT).as_posix()
        values = read_yaml(path)
        if source == "charts/governance-interceptor/values.yaml":
            engine = read_yaml(ROOT / "values-global.yaml")["global"]["governance"]["engine"]
            if engine != "apf":
                values.pop("apf", None)
        found.extend(walk_values(values, source))
    if output_dir is not None:
        for path in output_dir.glob("image-builder-charts_helm_*.yaml"):
            chart = path.stem.removeprefix("image-builder-charts_helm_")
            for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                if not isinstance(document, dict) or document.get("kind") != "BuildConfig":
                    continue
                name = document["metadata"]["name"]
                template = ("discovery-build.yaml" if name == "nemoclaw-discovery-runtime"
                            else "buildconfig.yaml")
                source = f"image-builder-charts/helm/{chart}/templates/{template}"
                spec = document["spec"]
                dockerfile = spec.get("source", {}).get("dockerfile", "")
                build_args = {item["name"]: str(item.get("value", ""))
                              for item in spec.get("strategy", {}).get("dockerStrategy", {})
                              .get("buildArgs", [])}
                for number, line in enumerate(dockerfile.splitlines(), 1):
                    match = re.match(r"^\s*FROM\s+(\S+)", line, re.IGNORECASE)
                    if not match:
                        continue
                    image = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
                                   lambda part: build_args.get(part.group(1), part.group(0)),
                                   match.group(1))
                    if image not in {"scratch", "debian-runtime"}:
                        found.append(Reference("image", image, source,
                                               f"BuildConfig.{name}.dockerfile.line {number}"))
    return found


def check_bom(result: Validation) -> None:
    saw = read_yaml(ROOT / "charts/openshell-saw/values.yaml")
    components = saw["bom"]["spec"]["openshell"]
    versions = {name: components[name]["version"]
                for name in ("cli", "gateway", "supervisor", "sandbox")}
    if len(set(versions.values())) != 1:
        result.error("charts/openshell-saw/values.yaml", "bom.installer.openshell",
                     f"component versions differ: {versions}")
    expected = next(iter(versions.values()))
    gateway = read_yaml(ROOT / "image-builder-charts/helm/openshell-gateway-image/values.yaml")
    for key, component in (("gatewayImage", "gateway"), ("supervisorImage", "supervisor")):
        image = gateway["openshell"][key]
        if not image.endswith(f":v{expected}"):
            result.error("image-builder-charts/helm/openshell-gateway-image/values.yaml",
                         f"openshell.{key}", f"{image} does not match BOM {component} {expected}")
    interceptor = read_yaml(ROOT / "image-builder-charts/helm/governance-interceptor-image/values.yaml")
    api_version = expected.split("-", 1)[0]
    if interceptor["source"]["git"]["ref"].lstrip("v") != api_version:
        result.error("image-builder-charts/helm/governance-interceptor-image/values.yaml",
                     "source.git.ref", f"does not match BOM API version {api_version}")
    result.count("bom")


def retry_call(action, label: str) -> None:
    last: Exception | None = None
    for attempt in range(3):
        try:
            action()
            return
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            last = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"{label}: {last}")


def check_url(url: str) -> None:
    if not url.startswith("https://"):
        raise RuntimeError("index or package URL must use HTTPS")
    request = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "saw-deployment-validation/1"})
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status < 200 or response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}")


def check_reference(ref: Reference) -> None:
    if ref.kind == "image":
        if ref.value.startswith("registry.redhat.io/"):
            def inspect_catalog() -> None:
                image = ref.value.removeprefix("registry.redhat.io/")
                if "@" in image or ":" not in image:
                    raise RuntimeError("Red Hat catalog check needs a tagged image")
                repository, tag = image.rsplit(":", 1)
                url = ("https://catalog.redhat.com/api/containers/v1/repositories/"
                       "registry/registry.access.redhat.com/repository/"
                       + urllib.parse.quote(repository, safe="/") + "/tag/"
                       + urllib.parse.quote(tag, safe=""))
                request = urllib.request.Request(url, headers={
                    "User-Agent": "saw-deployment-validation/1"})
                with urllib.request.urlopen(request, timeout=20) as response:
                    payload = json.load(response)
                if not payload.get("data"):
                    raise RuntimeError("Red Hat catalog has no image for this tag")
            retry_call(inspect_catalog, "Red Hat catalog lookup failed")
            return
        image = ref.value
        if "@" in image:
            name, digest = image.rsplit("@", 1)
            if ":" in name.rsplit("/", 1)[-1]:
                name = name.rsplit(":", 1)[0]
            image = f"{name}@{digest}"
        command = ["skopeo", "inspect", "--raw", f"docker://{image}"]
        def inspect() -> None:
            run = subprocess.run(command, capture_output=True, timeout=45, check=False)
            if run.returncode:
                raise RuntimeError(run.stderr.decode(errors="replace").strip()[:300])
        retry_call(inspect, "registry lookup failed")
    elif ref.kind == "git":
        uri, revision = ref.value.rsplit("#", 1)
        def inspect_git() -> None:
            if SHA.fullmatch(revision):
                with tempfile.TemporaryDirectory() as directory:
                    run = subprocess.run(["git", "-C", directory, "init", "-q"],
                                         capture_output=True, timeout=15, check=False)
                    if run.returncode:
                        raise RuntimeError("git init failed")
                    command = ["git", "-C", directory, "fetch", "--depth=1", uri, revision]
                    run = subprocess.run(command, capture_output=True, timeout=45, check=False)
                    if run.returncode:
                        raise RuntimeError(run.stderr.decode(errors="replace").strip()[:300])
            else:
                run = subprocess.run(["git", "ls-remote", "--exit-code", uri,
                                      f"refs/heads/{revision}", f"refs/tags/{revision}",
                                      f"refs/tags/{revision}^{{}}"],
                                     capture_output=True, timeout=45, check=False)
                if run.returncode or not run.stdout:
                    raise RuntimeError(run.stderr.decode(errors="replace").strip()[:300]
                                       or "ref was not found")
        retry_call(inspect_git, "upstream Git lookup failed")
    else:
        retry_call(lambda: check_url(ref.value), "package index lookup failed")


def package_references() -> list[Reference]:
    refs: list[Reference] = []
    for path in ROOT.glob("image-builder-charts/helm/**/package-lock.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        source = path.relative_to(ROOT).as_posix()
        for name, package in (data.get("packages") or {}).items():
            if not name or not isinstance(package, dict):
                continue
            resolved = package.get("resolved")
            if isinstance(resolved, str) and resolved.startswith("https://"):
                refs.append(Reference("package", resolved, source, f"packages.{name}.resolved"))
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    local = set((project.get("tool", {}).get("uv", {}).get("sources") or {}).keys())
    declarations = [("pyproject.toml", item)
                    for item in (project.get("project", {}).get("dependencies") or [])]
    for group in (project.get("dependency-groups") or {}).values():
        declarations.extend(("pyproject.toml", item) for item in group)
    requirements = ROOT / "tests/requirements.txt"
    declarations.extend(("tests/requirements.txt", line.split("#", 1)[0].strip())
                        for line in requirements.read_text(encoding="utf-8").splitlines())
    for source, item in declarations:
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?((?:==|>=|~=|<=|>|<).*)?$", item)
        if not match or match.group(1).lower() in local:
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        refs.append(Reference("package", f"https://pypi.org/simple/{name}/",
                              source, item))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    for package in lock.get("package", []):
        registry = package.get("source", {}).get("registry", "")
        if not registry:
            continue
        name = package["name"]
        version = package["version"]
        if registry.rstrip("/") == "https://pypi.org/simple":
            url = f"https://pypi.org/pypi/{name}/{version}/json"
        else:
            url = registry.rstrip("/") + f"/{name}/{version}/"
        refs.append(Reference("package", url, "uv.lock", f"package.{name}@{version}"))
    return refs


def check_dependencies(result: Validation, output_dir: Path | None = None) -> None:
    refs = collect_references(output_dir) + package_references()
    unique: dict[tuple[str, str], list[Reference]] = {}
    for ref in refs:
        if ref.kind == "image" and is_own_image(ref.value):
            result.count("repository_images")
            continue
        unique.setdefault((ref.kind, ref.value), []).append(ref)
    def worker(entry: tuple[str, str]) -> tuple[tuple[str, str], str | None]:
        ref = unique[entry][0]
        try:
            check_reference(ref)
            return entry, None
        except Exception as exc:
            return entry, str(exc)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for entry, error in pool.map(worker, unique):
            if error:
                for ref in unique[entry]:
                    result.error(ref.source, ref.path, f"{ref.kind} {ref.value}: {error}")
            else:
                result.count("redhat_catalog_tag" if entry[0] == "image" and
                             entry[1].startswith("registry.redhat.io/") else entry[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path("deployment-validation.json"))
    args = parser.parse_args()
    result = Validation()
    try:
        with tempfile.TemporaryDirectory(prefix="saw-chart-render-") as directory:
            render_charts(result, Path(directory))
            validate_schemas(result, Path(directory))
            check_dependencies(result, Path(directory))
        check_bom(result)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        result.error("deployment-validation", "runtime", str(exc))
    report = {"checked": result.checked, "errors": result.errors}
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for error in result.errors:
        print(f"ERROR {error}", file=sys.stderr)
    print(f"Deployment validation: {len(result.errors)} errors; checks: "
          + ", ".join(f"{key}={value}" for key, value in sorted(result.checked.items())))
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
