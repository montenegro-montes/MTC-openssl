"""Opt-in per-observation capture coordination; packet parsing belongs to Stage 1."""
import argparse
import contextlib
import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

EXTRACTOR = Path('/opt/handshake-capture/analyze.py')
METRICS = ('tcp_connect_wall_ms', 'tls_from_pcap_wall_ms', 'connection_handshake_wall_ms',
           'connection_handshake_packets', 'connection_handshake_frame_bytes',
           'connection_handshake_ip_bytes', 'connection_handshake_tcp_payload_bytes',
           'connection_handshake_retransmission_frames')


def save(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def wait_for(predicate, seconds=8):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.05)
    raise TimeoutError('capture coordination timed out')


@contextlib.contextmanager
def observation(out, scenario, round_number, order, warm, port):
    """Control delays surround, never enter, the original process/handshake timer."""
    if warm or os.environ.get('MEASUREMENT_PCAP') != '1':
        yield None
        return
    directory = out / 'pcap' / f'sample-{round_number:04d}-{scenario}'
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity = dict(campaign_id=os.environ['MEASUREMENT_CAMPAIGN_ID'],
                    round_id=round_number+1, round=round_number, scenario=scenario,
                    order_in_round=order+1, is_warmup=0,
                    openssl_samples='../../samples.csv',
                    openssl_log=f'../../logs/sample-{round_number:04d}-{scenario}.log')
    save(directory/'observation.json', identity)
    save(directory/'connections.json', [dict(scenario=scenario, server_port=port)])
    save(directory/'request.json', dict(server_port=port))
    ready = False
    try:
        try:
            wait_for(lambda: (directory/'ready.json').exists() or (directory/'capture-status.json').exists())
            ready = (directory/'ready.json').exists() and not (directory/'capture-status.json').exists()
            if not ready:
                raise RuntimeError('tcpdump did not become ready')
        except Exception as error:
            save(directory/'client-capture-error.json', dict(error=str(error)))
        try:
            yield directory/'tls.keys' if ready else None
        except BaseException as error:
            save(directory/'tls-status.json', dict(status='TLS_MEASUREMENT_FAILURE', error=str(error)))
            raise
        else:
            save(directory/'tls-status.json', dict(status='SUCCESS'))
    finally:
        (directory/'stop').touch()
        try:
            wait_for(lambda: (directory/'capture-status.json').exists(), 8)
        except TimeoutError as error:
            save(directory/'client-capture-error.json', dict(error=str(error)))


def capture_one(directory):
    """One sequential tcpdump process; explicit readiness and bounded clean stop."""
    process = None
    try:
        if (directory/'stop').exists():
            raise RuntimeError('capture request cancelled before startup')
        port = int(json.loads((directory/'request.json').read_text())['server_port'])
        if not 1 <= port <= 65535:
            raise ValueError('invalid server port')
        with (directory/'tcpdump.log').open('w') as log:
            process = subprocess.Popen(['tcpdump', '-i', 'eth0', '-s', '0', '-U',
                                        '-w', str(directory/'handshakes.pcap'),
                                        'tcp', 'port', str(port)],
                                       stdout=subprocess.DEVNULL, stderr=log,
                                       env={**os.environ, 'LC_ALL':'C'})
            def listening():
                if process.poll() is not None:
                    raise RuntimeError('tcpdump exited before readiness')
                if (directory/'stop').exists():
                    raise RuntimeError('capture startup cancelled')
                return 'listening on eth0' in (directory/'tcpdump.log').read_text()
            wait_for(listening)
            save(directory/'ready.json', dict(status='LISTENING'))
            wait_for(lambda: (directory/'stop').exists() or process.poll() is not None, 60)
            if process.poll() is not None:
                raise RuntimeError('tcpdump exited before requested shutdown')
            # Let kernel/libpcap buffers reach tcpdump before SIGINT flushes output.
            time.sleep(1.2)
            process.send_signal(signal.SIGINT)
            if process.wait(timeout=5) != 0:
                raise RuntimeError('tcpdump did not terminate cleanly')
        pcap = directory/'handshakes.pcap'
        if not pcap.is_file() or pcap.stat().st_size <= 24:
            raise RuntimeError('PCAP missing or contains no packet records')
        # Readability only, not a second metric parser; Stage 1 analyzes later.
        result = subprocess.run(['tcpdump','-n','-r',str(pcap),'-c','1'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode or not result.stdout.strip():
            raise RuntimeError('PCAP is unreadable or empty')
        save(directory/'capture-status.json', dict(status='SUCCESS', pcap_bytes=pcap.stat().st_size,
             pcap_sha256=hashlib.sha256(pcap.read_bytes()).hexdigest()))
    except Exception as error:
        save(directory/'capture-status.json', dict(status='CAPTURE_FAILURE', error=str(error)))
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


def serve(root):
    root.mkdir(parents=True, exist_ok=True)
    while True:
        for request in sorted(root.glob('*/request.json')):
            if not (request.parent/'capture-status.json').exists():
                capture_one(request.parent)
        time.sleep(.05)


def analyze(campaign):
    samples = campaign/'samples.csv'
    with samples.open() if samples.exists() else contextlib.nullcontext([]) as handle:
        rows = list(csv.DictReader(handle)) if samples.exists() else []
    results = []
    for directory in sorted((campaign/'pcap').glob('sample-*')):
        identity = json.loads((directory/'observation.json').read_text())
        result = dict(**identity, artifact_directory=str(directory.relative_to(campaign)),
                      metrics=None, capture_status='CAPTURE_FAILURE', analysis_status='NOT_EXECUTED',
                      tls_status='TLS_MEASUREMENT_FAILURE')
        matches = [r for r in rows if r['campaign_id']==identity['campaign_id']
                   and int(r['round_id'])==identity['round_id'] and r['scenario']==identity['scenario']
                   and int(r['is_warmup'])==0]
        if len(matches)==1:
            result.update(tls_status='SUCCESS', client_random=matches[0]['client_random'])
        try:
            if (directory/'client-capture-error.json').exists():
                raise RuntimeError(json.loads((directory/'client-capture-error.json').read_text())['error'])
            status=json.loads((directory/'capture-status.json').read_text())
            if status['status']!='SUCCESS':
                raise RuntimeError(status.get('error','capture failed'))
            result.update(capture_status='SUCCESS', pcap_sha256=status['pcap_sha256'])
            if len(matches)!=1:
                raise RuntimeError('no unique successful OpenSSL observation')
            keylog=directory/'tls.keys'
            # Check correlation without copying any secrets into reports.
            random=matches[0]['client_random'].lower()
            entries=[line.split() for line in keylog.read_text().splitlines() if line and not line.startswith('#')]
            if not entries or any(len(e)!=3 or e[1].lower()!=random for e in entries):
                raise RuntimeError('missing or mismatched observation key log')
            proc=subprocess.run([sys.executable,str(EXTRACTOR),str(directory)],
                                text=True,capture_output=True,timeout=60)
            (directory/'analysis.log').write_text(proc.stdout+proc.stderr)
            if proc.returncode:
                raise RuntimeError('Stage-1 extractor failed; see analysis.log')
            summary=json.loads((directory/'summary.json').read_text())
            if len(summary['scenarios'])!=1 or summary['scenarios'][0]['scenario']!=identity['scenario']:
                raise RuntimeError('extractor observation mismatch')
            metrics=summary['scenarios'][0]
            if any(metrics.get(k) is None for k in METRICS):
                raise RuntimeError('extractor omitted required metrics')
            result.update(metrics=metrics, analysis_status='SUCCESS')
        except Exception as error:
            result['error']=str(error)
            if result['capture_status']=='SUCCESS': result['analysis_status']='ANALYSIS_FAILURE'
        save(directory/'derived.json',result)
        results.append(result)
    (campaign/'pcap-metrics.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in results))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['serve','analyze'])
    parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    (serve if args.action=='serve' else analyze)(args.directory)


if __name__=='__main__': main()
