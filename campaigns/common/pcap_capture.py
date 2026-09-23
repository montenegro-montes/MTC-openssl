"""Shared opt-in PCAP capture core; packet parsing belongs to Stage 1."""
import argparse
import contextlib
import csv
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import time

EXTRACTOR = Path('/opt/pcap-core/pcap_analyze.py')
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
            # Failure-aware wrappers may return normally after recording a failed attempt.
            if not (directory/'tls-status.json').exists():
                save(directory/'tls-status.json', dict(status='SUCCESS'))
    finally:
        (directory/'stop').touch()
        try:
            wait_for(lambda: (directory/'capture-status.json').exists(),
                     float(os.environ.get('MEASUREMENT_PCAP_FINALIZATION_SECONDS','8')))
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
        captured=re.search(r'(\d+) packets captured', (directory/'tcpdump.log').read_text())
        if not captured or int(captured.group(1))==0:
            raise RuntimeError('tcpdump did not record captured packets')
        pcap = directory/'handshakes.pcap'
        if not pcap.is_file() or pcap.stat().st_size <= 24:
            raise RuntimeError('PCAP missing or contains no packet records')
        # Readability only, not a second metric parser; Stage 1 analyzes later.
        result = subprocess.run(['tcpdump','-n','-r',str(pcap),'-c','1'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode or not result.stdout.strip():
            raise RuntimeError('PCAP is unreadable or empty')
        save(directory/'capture-status.json', dict(status='SUCCESS', captured_packets=int(captured.group(1)), pcap_bytes=pcap.stat().st_size,
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


def analyze(campaign, allow_failed=False):
    samples = campaign/'samples.csv'
    with samples.open() if samples.exists() else contextlib.nullcontext([]) as handle:
        rows = list(csv.DictReader(handle)) if samples.exists() else []
    failed_rows = []
    if allow_failed and (campaign/'failures.csv').exists():
        with (campaign/'failures.csv').open() as handle:
            failed_rows = list(csv.DictReader(handle))
    results = []
    for directory in sorted((campaign/'pcap').glob('sample-*')):
        identity = json.loads((directory/'observation.json').read_text())
        result = dict(**identity, artifact_directory=str(directory.relative_to(campaign)),
                      metrics=None, capture_status='CAPTURE_FAILURE', analysis_status='NOT_EXECUTED',
                      tls_status='TLS_OUTCOME_UNAVAILABLE' if allow_failed else 'TLS_MEASUREMENT_FAILURE')
        matches = [r for r in rows if r['campaign_id']==identity['campaign_id']
                   and int(r['round_id'])==identity['round_id'] and r['scenario']==identity['scenario']
                   and int(r['is_warmup'])==0]
        failures = [r for r in failed_rows if r['campaign_id']==identity['campaign_id']
                    and int(r['round_id'])==identity['round_id'] and r['scenario']==identity['scenario']
                    and int(r['is_warmup'])==0]
        associated = matches + failures
        failed = len(failures)==1 and not matches
        if len(associated)==1:
            result.update(tls_status='TLS_MEASUREMENT_FAILURE' if failed else 'SUCCESS',
                          client_random=associated[0].get('client_random'),
                          association_confidence='client_random' if associated[0].get('client_random') else 'observation_tuple_only')
        try:
            if (directory/'client-capture-error.json').exists():
                raise RuntimeError(json.loads((directory/'client-capture-error.json').read_text())['error'])
            status=json.loads((directory/'capture-status.json').read_text())
            if status['status']!='SUCCESS':
                raise RuntimeError(status.get('error','capture failed'))
            pcap = directory/'handshakes.pcap'
            actual_hash = hashlib.sha256(pcap.read_bytes()).hexdigest()
            if status.get('pcap_sha256') != actual_hash:
                raise RuntimeError('PCAP hash does not match capture status')
            result.update(capture_status='SUCCESS', pcap_sha256=actual_hash)
            if len(associated)!=1 or (failed and not allow_failed):
                raise RuntimeError('no unique OpenSSL observation')
            if 'order_in_round' in associated[0] and int(associated[0]['order_in_round'])!=identity['order_in_round']:
                raise RuntimeError('observation order mismatch')
            keylog=directory/'tls.keys'
            # Check correlation without copying any secrets into reports.
            random=(associated[0].get('client_random') or '').lower()
            entries=[line.split() for line in keylog.read_text().splitlines() if line and not line.startswith('#')] if keylog.exists() else []
            if any(len(e)!=3 for e in entries) or (random and any(e[1].lower()!=random for e in entries)):
                raise RuntimeError('mismatched observation key log')
            if not failed and (not random or not entries):
                raise RuntimeError('missing or mismatched observation key log')
            if not random and len({e[1].lower() for e in entries})>1:
                raise RuntimeError('ambiguous failed observation key log')
            command=[sys.executable,str(EXTRACTOR),str(directory)]
            random_stream = (os.environ.get('MEASUREMENT_PCAP_CLIENT_RANDOM_STREAM') == '1'
                             and (not failed or bool(random)))
            if random_stream:
                if not re.fullmatch(r'[0-9a-f]{64}', random):
                    raise RuntimeError('missing or malformed native client_random')
                command += ['--client-random', random]
            if failed: command.append('--allow-incomplete')
            proc=subprocess.run(command,text=True,capture_output=True,timeout=60)
            (directory/'analysis.log').write_text(proc.stdout+proc.stderr)
            if proc.returncode:
                raise RuntimeError('Stage-1 extractor failed; see analysis.log')
            summary=json.loads((directory/'summary.json').read_text())
            if len(summary['scenarios'])!=1 or summary['scenarios'][0]['scenario']!=identity['scenario']:
                raise RuntimeError('extractor observation mismatch')
            if summary.get('pcap_sha256') != actual_hash:
                raise RuntimeError('PCAP hash does not match extractor output')
            metrics=summary['scenarios'][0]
            if random_stream and (metrics.get('client_random') != random
                                  or not isinstance(metrics.get('tcp_stream'), int)):
                raise RuntimeError('extractor client_random/stream association mismatch')
            partial = metrics.get('pcap_analysis_status')=='PARTIAL'
            if partial and not failed:
                raise RuntimeError('successful TLS observation has incomplete PCAP boundaries')
            if not partial and any(metrics.get(k) is None for k in METRICS):
                raise RuntimeError('extractor omitted required metrics')
            result.update(metrics=metrics, analysis_status='PARTIAL' if partial else 'SUCCESS')
        except Exception as error:
            result['error']=str(error)
            if result['capture_status']=='SUCCESS': result['analysis_status']='ANALYSIS_FAILURE'
        save(directory/'derived.json',result)
        results.append(result)
    (campaign/'pcap-metrics.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in results))


# Shared core: drain 1.2s + SIGINT close 5s + readability probe 5s.
FINALIZATION_SECONDS = 12
ANALYSIS_SECONDS_PER_OBSERVATION = 60
STARTUP_MARGIN_SECONDS = 8


def save_status(directory, status, error):
    (directory/'pcap-analysis-status.json').write_text(json.dumps({
        'status':status,'metrics':None,'error':str(error)})+'\n')


@contextlib.contextmanager
def capture_session(compose, directory, env, enabled, observation_count, allow_failed=False):
    if not enabled:
        yield
        return
    start_error = None
    try:
        with (directory/'capture-start.log').open('w') as log:
            subprocess.run(compose+['--profile','pcap','up','-d','--no-deps',
                           '--force-recreate','capture'], env=env,stdout=log,
                           stderr=subprocess.STDOUT,check=True)
    except (OSError,subprocess.SubprocessError) as error:
        start_error=error
        save_status(directory,'CAPTURE_FAILURE',error)
    try:
        yield
    finally:
        try:
            # A failed driver can leave a request pending; request an explicit
            # tcpdump stop and allow the core to flush before analyzing/teardown.
            requests=list((directory/'pcap').glob('sample-*/request.json'))
            for request in requests:
                (request.parent/'stop').touch()
            if start_error is None:
                deadline=time.monotonic()+FINALIZATION_SECONDS
                while any(not (r.parent/'capture-status.json').exists() for r in requests):
                    if time.monotonic()>=deadline:
                        raise TimeoutError('capture finalization did not complete before analysis')
                    time.sleep(.05)
            with (directory/'pcap-analysis.log').open('w') as log:
                subprocess.run(compose+['--profile','pcap','run','--rm','--no-deps',
                               'capture','python3','/opt/pcap-core/pcap_capture.py',
                               'analyze',env['MEASUREMENT_RUN_ROOT']+'/'+env['MEASUREMENT_CAMPAIGN_ID']]+(['--allow-failed'] if allow_failed else []),
                               env=env,stdout=log,stderr=subprocess.STDOUT,check=True,
                               timeout=STARTUP_MARGIN_SECONDS+ANALYSIS_SECONDS_PER_OBSERVATION*max(1,observation_count))
        except (OSError,subprocess.SubprocessError,TimeoutError) as error:
            save_status(directory,'ANALYSIS_FAILURE',error)
        finally:
            # Namespace is retained by the runner until after this context exits.
            try:
                subprocess.run(compose+['--profile','pcap','stop','capture'],env=env,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
            except OSError as error:
                save_status(directory,'CAPTURE_FAILURE',error)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['serve','analyze'])
    parser.add_argument('directory',type=Path)
    parser.add_argument('--allow-failed',action='store_true')
    args=parser.parse_args()
    if args.action=='serve': serve(args.directory)
    else: analyze(args.directory,allow_failed=args.allow_failed)


if __name__=='__main__': main()
