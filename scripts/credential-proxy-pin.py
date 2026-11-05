#!/usr/bin/env python3
"""Check or update the chart's published multi-architecture credential proxy pin."""

import argparse
import http.client
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = "ghcr.io/validatedpatterns-sandbox/saw-credential-proxy"
VALUES = ROOT / "charts/openshell-saw/values.yaml"
SOURCE = "credential-proxy/"
PIN = re.compile(r'^  # credential-proxy source: ([0-9a-f]{40})\n  image: "?(\S+?)"?$', re.MULTILINE)
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
UPDATE_HINT = "run make credential-proxy-pin and commit charts/openshell-saw/values.yaml"


class PinError(Exception):
    pass


def git(*args, allow_difference=False):
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if result.returncode and not (allow_difference and result.returncode == 1):
        raise PinError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def parse_pin():
    # Reading bytes avoids normalizing line endings anywhere outside the pin.
    text = VALUES.read_bytes().decode("utf-8")
    matches = list(PIN.finditer(text))
    if len(matches) != 1:
        raise PinError("expected one adjacent '# credential-proxy source: <40 hex>' and 'image:' pair; "
                       + UPDATE_HINT)
    match = matches[0]
    if not re.fullmatch(re.escape(REPO) + r"@sha256:[0-9a-f]{64}", match[2]):
        raise PinError(f"credentialProxy.image must be {REPO}@sha256:<64 hex>; {UPDATE_HINT}")
    return text, match


def require_commit(commit):
    try:
        git("cat-file", "-e", f"{commit}^{{commit}}")
    except PinError as exc:
        raise PinError(f"source commit {commit} is unavailable; a shallow checkout may lack it. "
                       "Fetch full history (actions/checkout fetch-depth: 0).") from exc


def request_json(url, headers=None):
    """All network I/O: anonymous GET, 20s timeout, at most three retries."""
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.headers, json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code < 500:
                raise PinError(f"registry request failed: HTTP {exc.code} for {url}") from exc
            error = exc
        except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
            error = exc
        if attempt < 3:
            time.sleep(2 ** attempt)
    raise PinError(f"registry request failed after three retries for {url}: {error}")


def manifest(ref):
    token_response = request_json(
        "https://ghcr.io/token?scope=repository:validatedpatterns-sandbox/saw-credential-proxy:pull")
    if token_response is None or not token_response[1].get("token"):
        raise PinError("GHCR did not return an anonymous pull token")
    response = request_json(
        f"https://ghcr.io/v2/validatedpatterns-sandbox/saw-credential-proxy/manifests/{ref}",
        {"Authorization": "Bearer " + token_response[1]["token"], "Accept": ", ".join(INDEX_TYPES)})
    if response is None:
        return None
    headers, body = response
    return headers.get("Docker-Content-Digest", ""), body


def published_index(commit):
    result = manifest("sha-" + commit)
    if result is None:
        raise PinError(f"sha-{commit} is not published; wait for the main build or pass --commit. "
                       + UPDATE_HINT)
    digest, body = result
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise PinError("registry index has no valid Docker-Content-Digest; " + UPDATE_HINT)
    if body.get("mediaType") not in INDEX_TYPES:
        raise PinError(f"sha-{commit} must be a multi-architecture index; {UPDATE_HINT}")
    platforms = {(entry.get("platform", {}).get("os"), entry.get("platform", {}).get("architecture"))
                 for entry in body.get("manifests", [])}
    if not {("linux", "amd64"), ("linux", "arm64")} <= platforms:
        raise PinError(f"sha-{commit} index must contain linux/amd64 and linux/arm64; {UPDATE_HINT}")
    return digest


def source_commit(ref):
    commit = git("log", "-1", "--first-parent", "--format=%H", ref, "--", SOURCE).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PinError(f"no {SOURCE} source commit found at {ref}; fetch full history")
    return commit


def source_changed(*refs):
    return git("diff", "--quiet", *refs, "--", SOURCE, allow_difference=True).returncode == 1


def check(base_ref=None, offline=False):
    _, pin = parse_pin()
    commit, image = pin[1], pin[2]
    require_commit(commit)
    if not offline and published_index(commit) != image.split("@", 1)[1]:
        raise PinError("pinned digest does not match the published source tag; " + UPDATE_HINT)
    if not source_changed(commit, "HEAD"):
        print(f"OK: credential proxy pin matches {commit}" + (" (offline)" if offline else ""))
        return 0
    if base_ref and source_changed(f"{base_ref}...HEAD"):
        print("::warning::credential-proxy/ changes in this PR; after merge, wait for the Credential "
              "proxy workflow on main, then run make credential-proxy-pin in a follow-up PR")
        return 0
    latest = source_commit(base_ref or "HEAD")
    if offline:
        print(f"::warning::credential-proxy/ changed in {latest}; publication cannot be checked offline; "
              + UPDATE_HINT)
    elif base_ref and manifest("sha-" + latest) is not None:
        raise PinError(f"stale pin: credential-proxy/ changed in {latest}; {UPDATE_HINT}")
    else:
        print(f"::warning::credential-proxy/ changed in {latest}; after the main build is published, "
              + UPDATE_HINT)
    return 0


def bump(commit=None, ref="origin/main"):
    text, pin = parse_pin()
    commit = git("rev-parse", "--verify", f"{commit}^{{commit}}").stdout.strip() if commit else source_commit(ref)
    require_commit(commit)
    digest = published_index(commit)
    replacement = f"  # credential-proxy source: {commit}\n  image: {REPO}@{digest}"
    VALUES.write_bytes((text[:pin.start()] + replacement + text[pin.end():]).encode("utf-8"))
    print(f"Credential proxy pin: {pin[2].split('@', 1)[1]} -> {digest} (source {commit})")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check_parser = commands.add_parser("check", help="Verify publication and source freshness")
    check_parser.add_argument("--base-ref", help="PR base ref with full history, e.g. origin/main")
    check_parser.add_argument("--offline", action="store_true", help="Skip all registry requests")
    bump_parser = commands.add_parser("bump", help="Pin the published main build")
    bump_parser.add_argument("--commit", help="Published build's source commit")
    bump_parser.add_argument("--ref", default="origin/main", help="Main ref to inspect (default: origin/main)")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            return check(args.base_ref, args.offline)
        return bump(args.commit, args.ref)
    except (PinError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
