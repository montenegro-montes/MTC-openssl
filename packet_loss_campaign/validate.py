"""Validate required output structure after manual execution."""
import csv,json,sys
from pathlib import Path
root=Path(sys.argv[1]);status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and len(status['campaigns'])==30
assert sum(c['measured_attempts'] for c in status['campaigns'])==5400
assert sum(c['warmup_attempts'] for c in status['campaigns'])==900
required=['all-samples.csv','all-warmups.csv','failures.csv','campaign-summary.csv','scenario-summary.csv','paired-comparisons.csv','bootstrap-comparisons.csv','network-validation.csv','retransmissions.csv','outliers.csv','metadata.json','environment.json','tests.log','report.md']
assert all((root/name).is_file() for name in required)
print('PASS output layout, 30 campaigns, 5400 measured attempts, 900 warmup attempts')
