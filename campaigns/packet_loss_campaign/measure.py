"""Failure-aware wrapper around the frozen paper driver; metric definitions unchanged."""
import csv,json,os,subprocess,sys
from pathlib import Path

PAPER_DIR='/opt/paper'
if PAPER_DIR not in sys.path:
    sys.path.insert(0,PAPER_DIR)

failures=[]
def write_failure(scenario,round_number,order,warm,result):
    reason='timeout' if result.returncode==124 else ('tls_error' if result.returncode else 'measurement_error')
    row={'experiment':'packet-loss-only','loss_target_percent':os.environ['LOSS_TARGET_PERCENT'],'campaign_id':os.environ['PAPER_CAMPAIGN_ID'],'round_id':round_number+1,'seed':int(os.environ['PAPER_SEED']),'scenario':scenario,'order_in_round':order+1,'is_warmup':int(warm),'success':0,'failure_reason':reason,'timeout':int(reason=='timeout'),'TLS_error':result.stderr[-2000:] if reason=='tls_error' else '','returncode':result.returncode}
    failures.append(row);out=Path(os.environ['PAPER_RUN_ROOT'])/os.environ['PAPER_CAMPAIGN_ID']
    with (out/'failures.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(row));w.writeheader();w.writerows(failures)
def loss_run(args,request):
    try:return subprocess.run(args,input=request,text=True,capture_output=True,timeout=float(os.environ.get('HANDSHAKE_TIMEOUT_SECONDS','30')))
    except subprocess.TimeoutExpired as error:return subprocess.CompletedProcess(args,124,error.stdout or '',(error.stderr or '')+'\nLOSS_TIMEOUT')

source=Path('/opt/paper/measure.py').read_text()
needle="source=Path('/opt/mtc/benchmark.py').read_text()"
if source.count(needle)!=1:raise RuntimeError('Frozen paper driver drift')
injection="""source=Path('/opt/mtc/benchmark.py').read_text()
original_run=\"result=subprocess.run(client_args(scenario,a.host,4433+ALL_SCENARIOS.index(scenario)),input='GET / HTTP/1.0\\r\\n\\r\\n',text=True,capture_output=True,timeout=20)\"
replacement=\"result=loss_run(client_args(scenario,a.host,4433+ALL_SCENARIOS.index(scenario)),'GET / HTTP/1.0\\r\\n\\r\\n')\"
if source.count(original_run)!=1:raise RuntimeError('Frozen benchmark subprocess drift')
source=source.replace(original_run,replacement)
failure=\"if result.returncode or len(values)!=1 or 'HTTP/1.0 200' not in log:raise RuntimeError('Handshake failed: '+scenario)\"
replacement=\"if result.returncode or len(values)!=1 or 'HTTP/1.0 200' not in log:\\n        write_failure(scenario,round_number,order,warm,result);return\"
if source.count(failure)!=1:raise RuntimeError('Frozen benchmark failure branch drift')
source=source.replace(failure,replacement)"""
source=source.replace(needle,injection)
exec(compile(source,'failure-aware-frozen-paper-driver','exec'))
