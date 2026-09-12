"""Separate PROFILE_DETAIL=1 collection using the existing native timers only."""
from pathlib import Path
import sys
sys.path.insert(0,'/opt/measurement')
source=Path('/opt/measurement/measure.py').read_text()
needle="source=Path('/opt/mtc/benchmark.py').read_text()"
assert source.count(needle)==1
source=source.replace(needle,needle+"\nassert source.count(\"or x['detail'] or\")==1\nsource=source.replace(\"or x['detail'] or\",\"or x['detail']!=1 or\")\nsource=source.replace(\"'detail':0\",\"'detail':1\")")
exec(compile(source,'separate-detail-campaign','exec'))
