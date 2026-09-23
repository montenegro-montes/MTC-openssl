"""Record a later completed experiment commit in ignored metadata and report."""
import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();root=a.root
commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();metadata=json.loads((root/'metadata.json').read_text())
if metadata.get('status')!='complete':raise SystemExit('Audit incomplete')
metadata['git_commit_after_experiment']=commit;(root/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
report=root/'report.md';text=report.read_text();report.write_text(text.replace('Experiment commit: PENDING_COMMIT','Experiment commit: `'+commit+'`'))
print(commit)
