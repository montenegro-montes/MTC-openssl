import json,sys
from pathlib import Path
root=Path(sys.argv[1]);status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and len(status['campaigns'])==20;assert sum(x['measured_attempts'] for x in status['campaigns'])==3600;assert sum(x['warmup_attempts'] for x in status['campaigns'])==600
for name in ['all-samples.csv','all-warmups.csv','failures.csv','campaign-summary.csv','scenario-summary.csv','paired-comparisons.csv','paired-table.csv','main-table.csv','network-telemetry.csv','campaign-tcp-counters.csv','metadata.json','report.md']:assert (root/name).is_file(),name
print('PASS: 20 campaigns, 3600 measured attempts, 600 warmups')
