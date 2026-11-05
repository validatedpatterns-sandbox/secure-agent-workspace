"""Credential proxy release pins, using local git history and a fake registry."""

import importlib.util
import io
import json
import subprocess
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("credential_proxy_pin", ROOT / "scripts/credential-proxy-pin.py")
pin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pin)
DIGEST = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64


def index(digest=DIGEST, architectures=("amd64", "arm64")):
    return digest, {"mediaType": pin.INDEX_TYPES[0], "manifests": [
        {"platform": {"os": "linux", "architecture": arch}} for arch in architectures]}


@pytest.fixture
def repo(tmp_path, monkeypatch):
    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True,
                              capture_output=True, text=True).stdout.strip()

    git("init", "-b", "main")
    git("config", "user.name", "Pin test")
    git("config", "user.email", "pin@example.test")
    source = tmp_path / "credential-proxy/proxy.go"
    source.parent.mkdir()
    source.write_text("source v1\n")
    values = tmp_path / "charts/openshell-saw/values.yaml"
    values.parent.mkdir(parents=True)
    original = (ROOT / "charts/openshell-saw/values.yaml").read_bytes().decode()
    values.write_bytes(original.encode())
    git("add", ".")
    git("commit", "-m", "Initial source")
    commit = git("rev-parse", "HEAD")
    text = pin.PIN.sub(f"  # credential-proxy source: {commit}\n  image: {pin.REPO}@{DIGEST}", original)
    values.write_bytes(text.encode())
    git("add", ".")
    git("commit", "-m", "Pin initial source")
    tags = {"sha-" + commit: index()}
    calls = []

    def manifest(ref):
        calls.append(ref)
        return tags.get(ref)

    def change_source():
        source.write_text(source.read_text() + "new source\n")
        git("add", ".")
        git("commit", "-m", "Change proxy source")
        return git("rev-parse", "HEAD")

    monkeypatch.setattr(pin, "ROOT", tmp_path)
    monkeypatch.setattr(pin, "VALUES", values)
    monkeypatch.setattr(pin, "manifest", manifest)
    return SimpleNamespace(git=git, values=values, text=text, commit=commit,
                           tags=tags, calls=calls, change_source=change_source)


def test_consistent_pin_passes(repo, capsys):
    assert pin.main(["check", "--base-ref", "main"]) == 0
    assert "OK:" in capsys.readouterr().out
    assert repo.calls == ["sha-" + repo.commit]


@pytest.mark.parametrize("old,new", [
    (pin.REPO, "quay.io/example/proxy"),
    ("@" + DIGEST, ":latest"),
    ("# credential-proxy source:", "# source:"),
])
def test_invalid_pin_fails(repo, capsys, old, new):
    repo.values.write_text(repo.text.replace(old, new))
    assert pin.main(["check"]) == 1
    assert "make credential-proxy-pin" in capsys.readouterr().err
    assert not repo.calls


def test_unknown_source_commit_explains_full_history_requirement(repo, capsys):
    repo.values.write_text(repo.text.replace(repo.commit, "f" * 40))
    assert pin.main(["check"]) == 1
    assert "shallow checkout" in capsys.readouterr().err
    assert not repo.calls


@pytest.mark.parametrize("publication,message", [
    (index(NEW_DIGEST), "does not match"),
    (index(architectures=("amd64",)), "linux/amd64 and linux/arm64"),
    ((DIGEST, {"mediaType": "application/vnd.oci.image.manifest.v1+json"}), "multi-architecture index"),
    (None, "not published"),
])
def test_bad_publication_fails(repo, capsys, publication, message):
    repo.tags["sha-" + repo.commit] = publication
    assert pin.main(["check"]) == 1
    error = capsys.readouterr().err
    assert message in error
    assert "make credential-proxy-pin" in error


def test_pr_with_published_base_source_requires_new_pin(repo, capsys):
    latest = repo.change_source()
    repo.tags["sha-" + latest] = index(NEW_DIGEST)
    repo.git("checkout", "-b", "topic")
    assert pin.main(["check", "--base-ref", "main"]) == 1
    assert f"stale pin: credential-proxy/ changed in {latest}" in capsys.readouterr().err


def test_pr_changing_proxy_source_warns_until_merged(repo, capsys):
    repo.git("checkout", "-b", "topic")
    repo.change_source()
    assert pin.main(["check", "--base-ref", "main"]) == 0
    assert "::warning::credential-proxy/ changes in this PR; after merge" in capsys.readouterr().out


def test_stale_unpublished_source_warns(repo, capsys):
    latest = repo.change_source()
    repo.git("checkout", "-b", "topic")
    assert pin.main(["check", "--base-ref", "main"]) == 0
    assert f"::warning::credential-proxy/ changed in {latest}" in capsys.readouterr().out
    assert "sha-" + latest in repo.calls


def test_push_with_stale_pin_warns_even_when_new_source_is_published(repo, capsys):
    latest = repo.change_source()
    repo.tags["sha-" + latest] = index(NEW_DIGEST)
    assert pin.main(["check"]) == 0
    assert "::warning::" in capsys.readouterr().out


@pytest.mark.parametrize("stale", [False, True])
def test_offline_check_never_contacts_registry(repo, capsys, stale):
    if stale:
        repo.change_source()
    assert pin.main(["check", "--offline", "--base-ref", "main"]) == 0
    assert not repo.calls
    assert ("::warning::" if stale else "OK:") in capsys.readouterr().out


@pytest.mark.parametrize("selection", ["default", "ref", "commit"])
def test_bump_changes_only_source_and_image_lines(repo, capsys, selection):
    latest = repo.change_source()
    repo.tags["sha-" + latest] = index(NEW_DIGEST)
    repo.git("update-ref", "refs/remotes/origin/main", latest)
    # Include quoted YAML and CRLF outside the pin to catch newline normalization.
    before = repo.values.read_bytes().replace(b"replicas: 1\n", b"replicas: 1\r\n")
    before = before.replace(f"image: {pin.REPO}@{DIGEST}".encode(),
                            f'image: "{pin.REPO}@{DIGEST}"'.encode())
    repo.values.write_bytes(before)
    args = {"default": [], "ref": ["--ref", "main"], "commit": ["--commit", latest]}[selection]
    assert pin.main(["bump", *args]) == 0
    expected = before.replace(repo.commit.encode(), latest.encode()).replace(
        f'image: "{pin.REPO}@{DIGEST}"'.encode(), f"image: {pin.REPO}@{NEW_DIGEST}".encode())
    assert repo.values.read_bytes() == expected
    assert len([1 for old, new in zip(before.splitlines(), expected.splitlines()) if old != new]) == 2
    output = capsys.readouterr().out
    assert DIGEST in output and NEW_DIGEST in output
    assert pin.main(["check", "--base-ref", "main"]) == 0


def test_bump_missing_tag_leaves_values_unchanged(repo, capsys):
    latest = repo.change_source()
    before = repo.values.read_bytes()
    assert pin.main(["bump", "--commit", latest]) == 1
    assert "wait for the main build or pass --commit" in capsys.readouterr().err
    assert repo.values.read_bytes() == before


@pytest.mark.parametrize("status", [404, 403, 503])
def test_registry_http_errors_retry_only_server_failures(monkeypatch, status):
    calls = []

    def fail(request, timeout):
        calls.append(timeout)
        raise urllib.error.HTTPError(request.full_url, status, "error", {}, None)

    monkeypatch.setattr(pin.urllib.request, "urlopen", fail)
    monkeypatch.setattr(pin.time, "sleep", lambda _: None)
    if status == 404:
        assert pin.request_json("https://ghcr.io/test") is None
    else:
        with pytest.raises(pin.PinError):
            pin.request_json("https://ghcr.io/test")
    assert calls == [20] * (4 if status == 503 else 1)


def test_registry_retries_network_error_and_parses_json(monkeypatch):
    calls = []

    def respond(request, timeout):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError("temporary error")
        response = io.BytesIO(json.dumps({"token": "anonymous"}).encode())
        response.headers = {}
        return response

    monkeypatch.setattr(pin.urllib.request, "urlopen", respond)
    monkeypatch.setattr(pin.time, "sleep", lambda _: None)
    assert pin.request_json("https://ghcr.io/token")[1] == {"token": "anonymous"}
    assert len(calls) == 2
