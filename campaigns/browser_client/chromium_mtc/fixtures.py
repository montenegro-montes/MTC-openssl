#!/usr/bin/env python3
"""Opt-in ECDSA-P256/N=16 server.test fixtures for Chromium interoperability."""
import argparse
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from campaigns.scaling.mtc_profile_scaling.workflow import main as workflow_main


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('generate', 'validate'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--image', default='mt-tls-mtc:local')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--server-hostname', default='server.test')
    args = parser.parse_args()
    if args.action == 'validate' and args.fixtures is None:
        parser.error('validate requires --fixtures')
    if args.action == 'generate' and args.fixtures is not None:
        parser.error('generate requires new fixtures; omit --fixtures')
    command = [args.action, '--output', str(args.output), '--profile', 'ecdsa-p256',
               '--server-hostname', args.server_hostname, '--image', args.image]
    if args.action == 'generate':
        command += ['--sizes', '16']
    else:
        command += ['--fixtures', str(args.fixtures), '--tree-size', '16']
    if args.execute:
        command += ['--execute']
    workflow_main(command)


if __name__ == '__main__':
    main()
