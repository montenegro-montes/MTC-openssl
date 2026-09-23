"""Failure-aware wrapper around the frozen controlled measurement driver; metric definitions unchanged."""
import csv,json,os,subprocess,sys
from pathlib import Path

MEASUREMENT_DIR='/opt/measurement'
if MEASUREMENT_DIR not in sys.path:
    sys.path.insert(0,MEASUREMENT_DIR)

failures=[]
def write_failure(scenario,round_number,order,warm,result):
    reason='timeout' if result.returncode==124 else ('tls_error' if result.returncode else 'measurement_error')
    row={'experiment':'packet-loss-only','loss_target_percent':os.environ['LOSS_TARGET_PERCENT'],'campaign_id':os.environ['MEASUREMENT_CAMPAIGN_ID'],'round_id':round_number+1,'seed':int(os.environ['MEASUREMENT_SEED']),'scenario':scenario,'order_in_round':order+1,'is_warmup':int(warm),'success':0,'failure_reason':reason,'timeout':int(reason=='timeout'),'TLS_error':result.stderr[-2000:] if reason=='tls_error' else '','returncode':result.returncode}
    failures.append(row);out=Path(os.environ['MEASUREMENT_RUN_ROOT'])/os.environ['MEASUREMENT_CAMPAIGN_ID']
    with (out/'failures.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(row));w.writeheader();w.writerows(failures)
    if not warm and os.environ.get('MEASUREMENT_PCAP')=='1':
        # Keep the original failure CSV schema; diagnostics belong to PCAP sidecars.
        directory=out/'pcap'/f'sample-{round_number:04d}-{scenario}'
        if directory.is_dir():
            from pcap_capture import save
            save(directory/'tls-status.json',dict(status='TLS_MEASUREMENT_FAILURE',
                 failure_reason=reason,returncode=result.returncode))
            metrics={k:None for k in ('tcp_connect_wall_ms_native','handshake_wall_ms',
                                     'connection_establishment_wall_ms_native')}
            parse_errors=[]
            def records(prefix):
                values=[]
                for line in result.stderr.splitlines():
                    if line.startswith(prefix+' '):
                        try:
                            value=json.loads(line.split(' ',1)[1])
                            if not isinstance(value,dict): raise ValueError('diagnostic is not an object')
                            values.append(value)
                        except ValueError:
                            parse_errors.append(prefix+' diagnostic incomplete or malformed')
                return values
            diagnostics=records('NATIVE_CONNECTION_METRICS')
            if len(diagnostics)==1:
                metrics.update({k:diagnostics[0].get(k) for k in metrics if k!='handshake_wall_ms'})
            completed=records('PROFILE_METRICS')
            if len(completed)==1:
                metrics.update({k:completed[0].get(k) for k in metrics})
            save(directory/'native-timing.json',dict(campaign_id=row['campaign_id'],round_id=row['round_id'],
                 scenario=scenario,is_warmup=0,tls_status='TLS_MEASUREMENT_FAILURE',
                 diagnostic_errors=parse_errors,**metrics))
def loss_run(args,request):
    try:return subprocess.run(args,input=request,text=True,capture_output=True,timeout=float(os.environ.get('HANDSHAKE_TIMEOUT_SECONDS','30')))
    except subprocess.TimeoutExpired as error:
        # TimeoutExpired may carry bytes even when subprocess.run uses text=True.
        def text(value): return value.decode(errors='replace') if isinstance(value,bytes) else (value or '')
        return subprocess.CompletedProcess(args,124,text(error.stdout),text(error.stderr)+'\nLOSS_TIMEOUT')

source=Path('/opt/measurement/measure.py').read_text()
needle="source=Path('/opt/mtc/benchmark.py').read_text()"
if source.count(needle)!=1:raise RuntimeError('Frozen controlled measurement driver drift')
original_run="result=subprocess.run(client_args(scenario,a.host,4433+ALL_SCENARIOS.index(scenario)),input='GET / HTTP/1.0\\r\\n\\r\\n',text=True,capture_output=True,timeout=20)"
run_replacement="result=loss_run(client_args(scenario,a.host,4433+ALL_SCENARIOS.index(scenario)),'GET / HTTP/1.0\\r\\n\\r\\n')"
failure="if result.returncode or len(values)!=1 or 'HTTP/1.0 200' not in log:raise RuntimeError('Handshake failed: '+scenario)"
failure_replacement="if result.returncode or len(values)!=1 or 'HTTP/1.0 200' not in log:\n        write_failure(scenario,round_number,order,warm,result);return"
injection=f"""source=Path('/opt/mtc/benchmark.py').read_text()
original_run={original_run!r}
replacement={run_replacement!r}
if source.count(original_run)!=1:raise RuntimeError('Frozen benchmark subprocess drift')
source=source.replace(original_run,replacement)
failure={failure!r}
replacement={failure_replacement!r}
if source.count(failure)!=1:raise RuntimeError('Frozen benchmark failure branch drift')
source=source.replace(failure,replacement)"""
source=source.replace(needle,injection)
exec(compile(source,'failure-aware-frozen-measurement-driver','exec'))
