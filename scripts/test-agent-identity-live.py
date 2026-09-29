#!/usr/bin/env python3
"""Live compatibility gate. Exit 2 means blocked, never full acceptance success.

This runner currently covers infrastructure and binary compatibility probes.
Unimplemented VM scenarios are reported explicitly; an audit dependency does
not block unrelated VM implementation or testing.
No existing VM is mutated. Temporary version-probe pods are always cleaned up.
"""
import argparse
import datetime
import json
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parents[1]
NS = "zero-trust-workload-identity-manager"
SCENARIOS = (
    "automatic-provisioning", "identity-correctness", "isolation",
    "client-credentials", "token-exchange", "rotation", "negative-grants",
    "normal-restart", "state-loss-recovery", "bootstrap-failure",
    "infrastructure-outage", "lifecycle-cleanup", "scheduling",
    "disabled-mode-live", "audit", "network-policy", "trust-domain-drift-live",
)


def command(args, stdin=None):
    return subprocess.run(args, input=stdin, capture_output=True, text=True,
                          check=True, timeout=360).stdout


def ready(resource):
    return any(c["type"] == "Ready" and c["status"] == "True"
               for c in resource.get("status", {}).get("conditions", []))


def blocked_cases(transport):
    transports = ("tcp", "vsock") if transport == "both" else (transport,)
    return [{"name": f"{t}/{case}", "status": "blocked",
             "detail": ("Pinned OpenShell lacks correlated injected identity audit claims"
                        if case == "audit" else "Scenario automation not implemented yet")}
            for t in transports for case in SCENARIOS]


def run(args):
    run_id = "identity-" + uuid.uuid4().hex[:10]
    namespace = args.namespace_prefix + "-" + run_id
    if len(namespace) > 63 or not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", namespace):
        raise ValueError("namespace-prefix must produce a DNS label of at most 63 characters")
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    report = {"runId": run_id, "context": args.context,
              "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "commit": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
              "dirty": bool(command(["git", "-C", str(ROOT), "status", "--porcelain"]).strip()),
              "stage": "compatibility-gate", "acceptanceComplete": False, "checks": []}
    oc = ["oc", "--context", args.context, "--request-timeout=30s"]
    created = False

    def get(kind, name=None, ns=None):
        return json.loads(command(oc + ["get", kind] + ([name] if name else [])
                                  + (["-n", ns] if ns else []) + ["-o", "json"]))

    def check(name, action):
        try:
            detail = action()
            report["checks"].append({"name": name, "status": "pass", "detail": detail})
        except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
            # Deliberately omit arbitrary command stdout/stderr from artifacts.
            report["checks"].append({"name": name, "status": "fail",
                                     "detail": str(error)[:1000]})

    def check_ready(kind):
        obj = get(kind, "cluster")
        assert ready(obj), f"{kind}/cluster is not Ready"
        return "Ready"

    def discovery():
        server = get("spireserver", "cluster")
        issuer = server["spec"]["jwtIssuer"]
        origin = urlparse(issuer)
        assert origin.scheme == "https" and not origin.username and not origin.password
        # curl uses the workstation certificate trust store; never disable TLS validation.
        doc = json.loads(command(["curl", "--fail", "--silent", "--show-error",
                                  "--max-time", "30", issuer + "/.well-known/openid-configuration"]))
        assert doc["issuer"] == issuer, "Discovery issuer mismatch"
        keys_url = urlparse(doc["jwks_uri"])
        assert keys_url.scheme == "https" and keys_url.netloc == origin.netloc, "Unexpected JWKS origin"
        keys = json.loads(command(["curl", "--fail", "--silent", "--show-error",
                                   "--max-time", "30", doc["jwks_uri"]]))
        assert keys.get("keys"), "Empty JWKS"
        return {"issuer": issuer, "keyCount": len(keys["keys"])}

    def probe(component, image, binary):
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": component, "namespace": namespace,
                            "labels": {"saw.redhat.com/identity-test-run": run_id}},
               "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": component, "image": image,
                                        "command": [binary, "--version"],
                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                            "capabilities": {"drop": ["ALL"]}},
                                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                      "limits": {"cpu": "1", "memory": "256Mi"}}}]}}
        command(oc + ["create", "-f", "-"], json.dumps(pod))
        command(oc + ["wait", "-n", namespace, "pod/" + component,
                      "--for=jsonpath={.status.phase}=Succeeded", "--timeout=180s"])
        output = command(oc + ["logs", "-n", namespace, component]).strip()
        assert "0.0.116" in output, "Unexpected pinned binary version"
        return {"image": image, "version": output}

    try:
        report["server"] = command(oc + ["whoami", "--show-server"]).strip()
        report["clusterVersion"] = get("clusterversion", "version")["status"]["desired"]["version"]
        for kind in ("spireserver", "spireagent", "spiffecsidriver",
                     "spireoidcdiscoveryprovider", "zerotrustworkloadidentitymanager"):
            check(kind, lambda kind=kind: check_ready(kind))
        check("https-discovery-jwks", discovery)
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace,
              "labels": {"saw.redhat.com/identity-test-run": run_id}}}
        command(oc + ["create", "-f", "-"], json.dumps(ns))
        created = True
        bom = yaml.safe_load((ROOT / "charts/openshell-saw/values.yaml").read_text())["bom"]
        for comp, binary in (("gateway", "/usr/local/bin/openshell-gateway"),
                             ("cli", "/usr/local/bin/openshell"),
                             ("supervisor", "/openshell-sandbox")):
            image = bom["spec"]["openshell"][comp]["image"]
            check("binary/" + comp, lambda comp=comp, image=image, binary=binary: probe(comp, image, binary))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["checks"].append({"name": "preflight", "status": "fail", "detail": str(error)[:1000]})
    finally:
        if created:
            def cleanup():
                ns = get("namespace", namespace)
                assert ns["metadata"]["labels"].get("saw.redhat.com/identity-test-run") == run_id
                command(oc + ["delete", "namespace", namespace, "--wait=true", "--timeout=120s"])
                return "Run-owned namespace deleted"
            check("cleanup", cleanup)
        report["checks"].extend(blocked_cases(args.transport))
        report["status"] = "fail" if any(c["status"] == "fail" for c in report["checks"]) else "blocked"
        path = args.artifact_dir / (run_id + ".json")
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{report['status'].upper()}: {path}")
    return 1 if report["status"] == "fail" else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace-prefix", required=True)
    parser.add_argument("--transport", required=True, choices=("tcp", "vsock", "both"))
    parser.add_argument("--artifact-dir", required=True, type=Path)
    args = parser.parse_args()
    if not args.context.strip() or not args.namespace_prefix.strip():
        parser.error("--context and --namespace-prefix must not be empty")
    raise SystemExit(run(args))
