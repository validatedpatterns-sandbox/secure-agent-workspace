#!/usr/bin/env python3
"""Delete one resource normally, preserving controller finalizers and API errors."""
import argparse
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('resource', help='resource/name')
    parser.add_argument('--namespace')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--optional-api-group', default='')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    deadline = time.monotonic() + args.timeout
    scope = ['-n', args.namespace] if args.namespace else []

    def oc(*command):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        result = subprocess.run(
            ['oc', '--request-timeout=10s', *command],
            capture_output=True, text=True, timeout=min(10, remaining))
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or 'Kubernetes request failed')
        return result.stdout.strip()

    try:
        if args.optional_api_group:
            resources = oc('api-resources', '--api-group=' + args.optional_api_group,
                           '-o', 'name').splitlines()
            if args.resource.split('/')[0] not in resources:
                return 0
        oc('delete', args.resource, *scope, '--wait=false', '--ignore-not-found=true')
        while True:
            remaining_object = oc('get', args.resource, *scope,
                                  '--ignore-not-found=true', '-o', 'name')
            if not remaining_object:
                return 0
            time.sleep(min(2, max(0, deadline - time.monotonic())))
    except (TimeoutError, subprocess.TimeoutExpired):
        print(f'Timed out deleting {args.resource}; finalizers were preserved. '
              f'Inspect with: oc describe {args.resource} {" ".join(scope)}. '
              'Resolve remaining resources/controller errors before retrying. '
              'Subsequent cleanup stopped.', file=sys.stderr)
        return 124
    except RuntimeError as error:
        print(f'Deletion of {args.resource} failed: {error}. '
              'Subsequent cleanup stopped.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
