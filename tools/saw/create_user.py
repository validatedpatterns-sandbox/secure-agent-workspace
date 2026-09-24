#!/usr/bin/env python3
"""Create a starter admin-owned SAW user enrollment file."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("config/users"))
    parser.add_argument("--username", required=True)
    parser.add_argument("--profiles", required=True,
                        help="comma-separated profile names")
    args = parser.parse_args()

    if len(args.username) > 63 or not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", args.username):
        parser.error("username must be a Kubernetes-compatible lowercase name")
    profiles = [item.strip() for item in args.profiles.split(",") if item.strip()]
    if (not profiles or len(profiles) != len(set(profiles)) or
            any(len(item) > 63 or not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", item)
                for item in profiles)):
        parser.error("profiles must be comma-separated Kubernetes-compatible names")

    user_dir = args.directory / args.username
    user_path = user_dir / "user.yaml"
    secret_path = user_dir / "secret.yaml"
    if user_path.exists() or secret_path.exists():
        parser.error(f"refusing to overwrite existing user directory: {user_dir}")

    profile_lines = "\n".join(f"    - {profile}" for profile in profiles)
    user_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    user_path.write_text(f'''# Admin-owned manual user enrollment. Provider credentials never belong here.
sawUser:
  name: {args.username}
  username: {args.username}
  vaultPrefix: saw/{args.username}
  # Required for external OIDC. For bundled Keycloak, set the user's immutable sub/UUID.
  subject: ""
  profiles:
{profile_lines}
  credentials: []
  guest:
    enabled: true
    cores: 4
    memoryGi: 8
    runStrategy: Halted
''')
    secret_path.write_text('''# Local-only provider configuration. Never commit this file.
providers: {}
''')
    user_path.chmod(0o600)
    secret_path.chmod(0o600)
    print(f"Created {user_path}")
    print(f"Created {secret_path}; fill provider values locally and keep it uncommitted.")


if __name__ == "__main__":
    main()
