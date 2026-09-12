import datetime
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from scenarios import SCENARIOS,server_args
if '--health' in sys.argv:
    raise SystemExit(0 if Path('/tmp/profile-ready').is_file() else 1)
base=Path('/work/results');base.mkdir(parents=True,exist_ok=True)
directory=Path(tempfile.mkdtemp(prefix='profile-server-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-',dir=base))
(directory/'metadata.json').write_text(json.dumps({'detail':os.environ.get('PROFILE_DETAIL','0'),
    'profile_sha256':Path('/opt/openssl-profile/PROFILE_SHA256').read_text().strip()},indent=2))
processes=[];streams=[]
def stop(*args):raise SystemExit(0)
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
try:
    for index,scenario in enumerate(SCENARIOS):
        stream=(directory/(scenario+'.log')).open('w');streams.append(stream)
        env=os.environ.copy();env['PROFILE_METRICS_DIR']=str(directory)
        processes.append(subprocess.Popen(server_args(scenario,4433+index),stdout=stream,stderr=stream,env=env))
    for index,process in enumerate(processes):
        for _ in range(100):
            if process.poll() is not None:raise RuntimeError('Server failed: '+SCENARIOS[index])
            try:
                with socket.create_connection(('127.0.0.1',4433+index),timeout=.1):break
            except OSError:time.sleep(.025)
        else:raise RuntimeError('Readiness timeout')
    Path('/tmp/profile-ready').write_text(str(directory))
    print(directory,flush=True)
    while True:
        for process in processes:
            if process.poll() is not None:raise RuntimeError('Server process exited')
        time.sleep(.5)
finally:
    for process in processes:
        if process.poll() is None:process.terminate()
    for process in processes:
        try:process.wait(timeout=3)
        except subprocess.TimeoutExpired:process.kill();process.wait()
    for stream in streams:stream.close()
