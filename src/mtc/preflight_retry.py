"""Preflight for direct and bounded-retry MTC authentication.

Uses supplied immutable fixtures; no fixture generation or readiness connections.
"""

import argparse
import json
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile

from retry import events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', required=True)
    parser.add_argument('--trust', type=Path, required=True)
    parser.add_argument('--cert', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--initial-id', required=True)
    parser.add_argument(
        '--expect',
        choices=['happy', 'retry'],
        default='retry',
        help='expected transaction shape: direct authentication or one bounded retry',
    )
    parser.add_argument('--port', type=int, default=19443)

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error('invalid port')

    expected_connections = 1 if args.expect == 'happy' else 2

    with tempfile.TemporaryFile(mode='w+') as errors:
        server = subprocess.Popen(
            [
                args.peer,
                'server',
                '127.0.0.1',
                str(args.port),
                str(args.trust),
                'landmark',
                str(args.cert),
                str(args.key),
                str(expected_connections),
            ],
            stdout=subprocess.PIPE,
            stderr=errors,
            text=True,
        )

        try:
            with selectors.DefaultSelector() as selector:
                selector.register(server.stdout, selectors.EVENT_READ)

                if (
                    not selector.select(timeout=10)
                    or server.stdout.readline().strip() != 'MTC_RETRY_READY'
                ):
                    errors.seek(0)
                    reasons = events(errors.read(), 'MTC_RETRY_ERROR ')
                    raise AssertionError(
                        'server readiness failed: ' + json.dumps(reasons)
                    )

            client = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name('retry.py')),
                    '--peer',
                    args.peer,
                    '--host',
                    '127.0.0.1',
                    '--port',
                    str(args.port),
                    '--hostname',
                    args.hostname,
                    '--trust',
                    str(args.trust),
                    '--initial-id',
                    args.initial_id,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            output, _ = server.communicate(timeout=10)

            report = json.loads(client.stdout)
            native = events(output, 'MTC_RETRY_RESULT ')

            errors.seek(0)
            selected = events(errors.read(), 'MTC_RETRY_SERVER ')

            assert client.returncode == server.returncode == 0

            if args.expect == 'retry':
                assert report['final_result'] == 'PASS'
                assert report['retry_count'] == 1
                assert report['attempt_count'] == 2
                assert report['attempt_1_result'] == 'FAIL'
                assert report['attempt_2_result'] == 'PASS'

                assert len(native) == len(selected) == 2
                assert [r['request_satisfied'] for r in selected] == [False, True]
                assert [r['result'] for r in native] == ['FAIL', 'PASS']

                assert native[0]['connection_id'] != native[1]['connection_id']

                for index, record in enumerate(native, 1):
                    assert (
                        record['connection_id']
                        == report[f'attempt_{index}_connection_id']
                    )
                    assert record['session_reused'] is False

                print(json.dumps(report, indent=2))
                print(
                    'PASS: one bounded retry transaction, '
                    'two distinct authenticated-state connections'
                )

            else:
                assert report['final_result'] == 'PASS'
                assert report['retry_count'] == 0
                assert report['attempt_count'] == 1
                assert report['attempt_1_result'] == 'PASS'
                assert report['attempt_2_result'] is None

                assert len(native) == len(selected) == 1
                assert selected[0]['request_satisfied'] is True
                assert native[0]['result'] == 'PASS'
                assert (
                    native[0]['connection_id']
                    == report['attempt_1_connection_id']
                )
                assert native[0]['session_reused'] is False

                print(json.dumps(report, indent=2))
                print('PASS: direct authenticated transaction, no retry')

        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

            server.stdout.close()


if __name__ == '__main__':
    main()