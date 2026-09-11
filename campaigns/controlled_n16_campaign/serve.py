"""Endpoint telemetry stays within its campaign directory."""
import os
from pathlib import Path
source=Path('/opt/profiling/serve.py').read_text()
source=source.replace("base=Path('/work/results');base.mkdir(parents=True,exist_ok=True)","base=Path(os.environ['MEASUREMENT_RUN_ROOT'])/os.environ['MEASUREMENT_CAMPAIGN_ID'];base.mkdir(parents=True,exist_ok=True)")
source=source.replace('/tmp/profile-ready','/tmp/measurement-ready')
source=source.replace("prefix='profile-server-'","prefix='server-'")
exec(compile(source,'measurement-server','exec'))
