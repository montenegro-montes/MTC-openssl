"""Record the completed experiment commit in ignored result metadata/report."""
import argparse,json,subprocess
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
subject=subprocess.check_output(['git','log','-1','--format=%s'],text=True).strip()
if subject!='experiment: add controlled bandwidth-limited TLS measurements':
    raise SystemExit('HEAD is not the expected completed bandwidth experiment commit')
metadata=json.loads((root/'metadata.json').read_text())
if metadata.get('status')!='complete':raise SystemExit('Audit is not complete')
metadata['git_commit_after_experiment']=commit
(root/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
report=root/'report.md';text=report.read_text()
if 'Experiment commit: PENDING_COMMIT' not in text:raise SystemExit('Report placeholder missing')
report.write_text(text.replace('Experiment commit: PENDING_COMMIT','Experiment commit: `'+commit+'`'))
print(commit)
