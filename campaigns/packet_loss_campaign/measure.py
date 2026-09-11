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
def loss_run(args,request):
    try:return subprocess.run(args,input=request,text=True,capture_output=True,timeout=float(os.environ.get('HANDSHAKE_TIMEOUT_SECONDS','30')))
    except subprocess.TimeoutExpired as error:return subprocess.CompletedProcess(args,124,error.stdout or '',(error.stderr or '')+'\nLOSS_TIMEOUT')

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
