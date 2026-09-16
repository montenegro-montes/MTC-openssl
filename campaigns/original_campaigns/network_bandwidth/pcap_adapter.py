"""Thin bandwidth lifecycle adapter; capture/extraction belong to the shared core."""
import contextlib
import json
from pathlib import Path
import subprocess
import time

# Shared core: drain 1.2s + SIGINT close 5s + readability probe 5s.
FINALIZATION_SECONDS = 12
ANALYSIS_SECONDS_PER_OBSERVATION = 60
STARTUP_MARGIN_SECONDS = 8


def save_status(directory, status, error):
    (directory/'pcap-analysis-status.json').write_text(json.dumps({
        'status':status,'metrics':None,'error':str(error)})+'\n')


@contextlib.contextmanager
def capture_session(compose, directory, env, enabled, observation_count):
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
                               'analyze',env['MEASUREMENT_RUN_ROOT']+'/'+env['MEASUREMENT_CAMPAIGN_ID']],
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
