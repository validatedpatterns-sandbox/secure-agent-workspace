#!/usr/bin/env python3
"""Create an explicitly scoped token-exchange provider from laptop credentials."""
import argparse
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("gateway", "workspace", "provider", "profile"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--credential", default="subject_token")
    parser.add_argument("--token-stdin", action="store_true",
                        help="Read a subject token acquired on this laptop from stdin; otherwise use gateway OIDC login")
    args = parser.parse_args()
    if any(not value.strip() for value in (args.gateway, args.workspace, args.provider, args.profile)):
        parser.error("gateway, workspace, provider and profile must be explicit and nonempty")
    cmd = ["openshell", "--gateway", args.gateway, "provider", "create",
           "--workspace", args.workspace, "--name", args.provider,
           "--type", args.profile, "--credential", args.credential]
    env = os.environ.copy()
    if args.token_stdin:
        token = sys.stdin.read(65537).strip()
        if not token or len(token) > 65536 or "\n" in token:
            parser.error("stdin must contain one subject token")
        env[args.credential] = token
    else:
        cmd.append("--from-oidc-token")
    # CLI error output can come from a remote issuer. Do not echo it or retain it.
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode:
        print("Provider creation failed; verify authenticated gateway access and the approved token-exchange profile.", file=sys.stderr)
        return result.returncode
    print(f"Created provider {args.provider} in {args.gateway}/{args.workspace}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
