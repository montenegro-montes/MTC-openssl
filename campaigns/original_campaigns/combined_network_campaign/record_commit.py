import json,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]);commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();metadata=json.loads((root/'metadata.json').read_text());
if metadata.get('status')!='complete':raise SystemExit('audit incomplete')
metadata['git_commit_after_experiment']=commit;(root/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n');report=root/'report.md';report.write_text(report.read_text().replace('Experiment commit: PENDING_COMMIT','Experiment commit: `'+commit+'`'));print(commit)
