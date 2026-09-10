"""Keep previous endpoint telemetry definitions; isolate output and readiness."""
from pathlib import Path
source=Path('/opt/profiling/serve.py').read_text()
source=source.replace('from scenarios import SCENARIOS,server_args','from scenarios import ALL_SCENARIOS as SCENARIOS,server_args')
source=source.replace('/tmp/profile-ready','/tmp/mtc-ready').replace("prefix='profile-server-'","prefix='mtc-server-'")
exec(compile(source,'mtc-server','exec'))
