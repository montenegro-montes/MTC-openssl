"""Opt-in matrix of isolated BoringSSL/OpenSSL MTC interoperability checks."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PROFILES = ['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'mldsa44', 'mldsa65', 'mldsa87']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--profiles', nargs='+', choices=PROFILES, default=PROFILES)
    parser.add_argument('--server-image', default='mt-tls-mtc:local')
    parser.add_argument('--client-image', default='mt-browser-boringssl:wire')
    args = parser.parse_args()
    profiles = list(dict.fromkeys(args.profiles))
    if not args.execute:
        print(f'PLAN: {len(profiles)} profiles x 2 modes x 4 cases = {len(profiles) * 8} planned TLS connections.')
        print('No Docker or TLS executed. Use --execute to run; each suite stops at its first failure.')
        return
    parent = HERE.parents[2] / 'artifacts/results'
    parent.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='browser-mtc-matrix-', dir=parent))
    print(f'Matrix evidence: {out}', flush=True)
    results = []
    summary = {'status': 'running', 'profiles': profiles, 'suites': results}
    try:
        for profile in profiles:
            for mode in ['standalone', 'landmark']:
                label = f'{profile}-{mode}'
                print(f'=== {label} ===', flush=True)
                # The child enforces per-process timeouts and owns container cleanup.
                with (out / f'{label}.log').open('w') as log:
                    result = subprocess.run([sys.executable, str(HERE / 'run-tls-smoke.py'),
                        '--execute', '--profile', profile, '--mode', mode,
                        '--server-image', args.server_image, '--client-image', args.client_image],
                        stdout=log, stderr=subprocess.STDOUT)
                text = (out / f'{label}.log').read_text()
                print(text, end='', flush=True)
                evidence = next((line[len('Evidence: '):] for line in text.splitlines()
                                 if line.startswith('Evidence: ')), None)
                passed = False
                if result.returncode == 0 and evidence:
                    report = json.loads((Path(evidence) / 'summary.json').read_text())
                    passed = report['status'] == 'passed' and len(report['cases']) == 4 and all(
                        case['passed'] for case in report['cases'])
                results.append({'profile': profile, 'mode': mode, 'passed': passed,
                                'returncode': result.returncode, 'evidence': evidence})
                (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        failures = sum(not item['passed'] for item in results)
        summary['status'] = 'failed' if failures else 'passed'
        print(f'MATRIX: {len(results) - failures} suites PASS, {failures} suites FAIL', flush=True)
        return 1 if failures else 0
    finally:
        if summary['status'] == 'running':
            summary['status'] = 'interrupted'
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
