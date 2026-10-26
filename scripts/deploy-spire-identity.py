#!/usr/bin/env python3
"""Deploy the shared SPIRE stack in two stages; never adopt existing resources."""
import argparse
import json
import subprocess
import time
from pathlib import Path

NS = "zero-trust-workload-identity-manager"
RELEASE = "saw-spire"
CSV = "zero-trust-workload-identity-manager.v1.1.1"
ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=660).stdout


def deploy(context, values, operator_only=False):
    oc = ["oc", "--context", context, "--request-timeout=30s"]
    helm = ["helm", "--kube-context", context]
    releases = json.loads(run(*helm, "list", "-n", NS, "-a", "-o", "json"))
    existing = any(r["name"] == RELEASE for r in releases)
    if not existing:
        # An existing operator/CR must be managed by its owner, not this helper.
        subs = json.loads(run(*oc, "get", "subscription", "-A", "-o", "json"))
        if any(s["spec"]["name"] == "openshift-zero-trust-workload-identity-manager"
               for s in subs["items"]):
            raise RuntimeError("Existing ZTWIM subscription: use its owning deployment")
        crds = json.loads(run(*oc, "get", "crd", "-o", "json"))
        names = {c["metadata"]["name"] for c in crds["items"]}
        for resource in ("spireservers", "spireagents", "spiffecsidrivers",
                         "spireoidcdiscoveryproviders", "zerotrustworkloadidentitymanagers"):
            name = resource + ".operator.openshift.io"
            if name in names and json.loads(run(*oc, "get", name, "-o", "json"))["items"]:
                raise RuntimeError(f"Existing {resource}: refusing ownership takeover")
        run(*helm, "upgrade", "--install", RELEASE, str(ROOT / "charts/spire-identity"),
            "-n", NS, "--create-namespace", "-f", str(values),
            "--set", "spiffe.enabled=true,operands.enabled=false",
            "--wait", "--timeout", "5m")

    # Approve only the pinned operator's plan, never a general pending upgrade.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        sub = json.loads(run(*oc, "get", "subscription",
                             "openshift-zero-trust-workload-identity-manager",
                             "-n", NS, "-o", "json"))
        plan = sub.get("status", {}).get("installPlanRef", {}).get("name")
        if plan:
            ip = json.loads(run(*oc, "get", "installplan", plan, "-n", NS, "-o", "json"))
            if not ip["spec"].get("approved"):
                if ip["spec"].get("clusterServiceVersionNames") != [CSV]:
                    raise RuntimeError("InstallPlan differs from the pinned ZTWIM version")
                run(*oc, "patch", "installplan", plan, "-n", NS, "--type=merge",
                    "-p", '{"spec":{"approved":true}}')
            break
        time.sleep(5)
    else:
        raise RuntimeError("Timed out waiting for ZTWIM InstallPlan")
    run(*oc, "wait", "--for=jsonpath={.status.phase}=Succeeded", "csv/" + CSV,
        "-n", NS, "--timeout=300s")
    if operator_only:
        print("Operator ready; operands can now be created by the Pattern application.")
        return
    run(*helm, "upgrade", RELEASE, str(ROOT / "charts/spire-identity"), "-n", NS,
        "-f", str(values), "--set", "spiffe.enabled=true,operands.enabled=true",
        "--wait", "--timeout", "10m")
    for resource in ("spireserver", "spireagent", "spiffecsidriver",
                     "spireoidcdiscoveryprovider", "zerotrustworkloadidentitymanager"):
        run(*oc, "wait", "--for=condition=Ready", resource + "/cluster", "--timeout=300s")
    print("Shared SPIRE infrastructure ready; VM identity acceptance remains gated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--operator-only", action="store_true")
    args = parser.parse_args()
    if not args.context.strip():
        parser.error("--context must explicitly identify the target cluster")
    try:
        deploy(args.context, args.values.resolve(strict=True), args.operator_only)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        # No secrets are accepted by this helper; show Helm diagnostics on failure.
        print(getattr(error, "stderr", None) or str(error))
        raise SystemExit(1)
