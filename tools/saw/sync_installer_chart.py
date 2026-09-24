#!/usr/bin/env python3
"""Package the canonical installer for legacy Helm use; never edit the copy."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'installer/apply_bom.py'
TARGET = ROOT / 'charts/saw-bom/files/apply_bom.py'
HEADER = b'# GENERATED from installer/apply_bom.py; run tools/saw/sync_installer_chart.py. DO NOT EDIT.\n'


def sync(check=False):
    expected = HEADER + SOURCE.read_bytes()
    if check:
        if not TARGET.exists() or TARGET.read_bytes() != expected:
            raise SystemExit('Installer chart copy is stale; run tools/saw/sync_installer_chart.py')
    else:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    sync(parser.parse_args().check)
