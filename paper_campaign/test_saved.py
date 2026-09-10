"""Execute each saved security suite against the measurement executable."""
import sys,importlib.util
from pathlib import Path
import scenarios
suite=sys.argv[1]
if suite=='mtc':
    # The saved MTC suite imports its mutations module and prepare helper.
    sys.path.insert(1,'/opt/mtc')
    source=Path('/opt/mtc/test_tls.py').read_text()
elif suite=='compact':
    sys.path.insert(1,'/opt/compact')
    source=Path('/opt/compact/test_tls.py').read_text()
    scenarios.SCENARIOS=scenarios.previous.previous.previous.SCENARIOS
    source=source.replace('LAB_METRICS ','PROFILE_METRICS ')
elif suite=='profile':
    sys.path.insert(1,'/opt/compact')
    scenarios.SCENARIOS=scenarios.previous.previous.SCENARIOS
    source=Path('/opt/profiling/test_tls.py').read_text()
else:raise SystemExit('unknown suite')
exec(compile(source,'saved-'+suite+'-suite-on-paper-binary','exec'))
