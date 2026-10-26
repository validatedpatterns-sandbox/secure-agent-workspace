#!/usr/bin/env python3
"""Render the portable Pattern SAW example with site-specific values."""

import argparse
import json
import re
from pathlib import Path
from string import Template


ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "examples/agent-identity/pattern-saw-applications.yaml.tpl"
DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
LABEL_VALUE = re.compile(r"[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?\Z")


def checked(value: str, name: str, pattern: re.Pattern[str], limit: int) -> str:
    if len(value) > limit or not pattern.fullmatch(value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def checked_dns(value: str, name: str) -> str:
    if len(value) > 253 or any(
        not label or len(label) > 63 or not DNS_LABEL.fullmatch(label)
        for label in value.split(".")
    ):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saw-name", required=True)
    parser.add_argument("--saw-namespace", required=True)
    parser.add_argument("--gitops-namespace", default="vp-gitops")
    parser.add_argument("--git-repo-url", required=True)
    parser.add_argument("--git-revision", required=True)
    parser.add_argument("--trust-domain", required=True)
    parser.add_argument("--test-run-id", required=True)
    parser.add_argument(
        "--spire-server-address",
        default="spire-server.zero-trust-workload-identity-manager.svc.cluster.local",
    )
    parser.add_argument(
        "--demo-host", default="identity-demo.saw-identity-demo.svc.cluster.local"
    )
    parser.add_argument("--output", type=Path, help="write to a file instead of stdout")
    args = parser.parse_args()

    try:
        values = {
            "SAW_NAME": checked(args.saw_name, "SAW name", DNS_LABEL, 59),
            "SAW_NAMESPACE": checked(args.saw_namespace, "SAW namespace", DNS_LABEL, 63),
            "GITOPS_NAMESPACE": checked(args.gitops_namespace, "GitOps namespace", DNS_LABEL, 63),
            "TRUST_DOMAIN": checked_dns(args.trust_domain, "trust domain"),
            "TEST_RUN_ID": checked(args.test_run_id, "test run ID", LABEL_VALUE, 63),
            "SPIRE_SERVER_ADDRESS": checked_dns(
                args.spire_server_address, "SPIRE server address"
            ),
            "DEMO_HOST": checked_dns(args.demo_host, "demo host"),
        }
    except ValueError as error:
        parser.error(str(error))
    for name, value in (
        ("Git repository URL", args.git_repo_url),
        ("Git revision", args.git_revision),
    ):
        if not value or any(char.isspace() for char in value):
            parser.error(f"{name} must be nonempty and contain no whitespace")
    values["GIT_REPO_URL"] = args.git_repo_url
    values["GIT_REVISION"] = args.git_revision
    values["SAW_BOM_NAME"] = f"{args.saw_name}-bom"
    values["DEMO_AUDIENCE"] = f"http://{args.demo_host}:8080"
    values["DEMO_TOKEN_ENDPOINT"] = f"{values['DEMO_AUDIENCE']}/token"

    # JSON strings are also valid YAML scalars, including inside Helm values.
    rendered = Template(TEMPLATE.read_text()).substitute(
        {key: json.dumps(value) for key, value in values.items()}
    )
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
