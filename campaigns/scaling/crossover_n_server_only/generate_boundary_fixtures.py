#!/usr/bin/env python3
"""Generate only N-1/N MTC fixtures selected by the analytical crossover."""
import argparse, csv, json, shutil, sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'src/mtc'))
from prepare import prepare

def selected(path):
    with path.open(newline='') as f: rows=list(csv.DictReader(f))
    result={}
    for row in rows:
        if row.get('status')!='CROSSED': continue
        n=int(row['crossover_N'])
        if row.get('x509_depth') == '2' and 1 < n <= 256: result.setdefault(row['algorithm'],set()).update((n-1,n))
    return {k:sorted(v) for k,v in result.items()}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('output exists')
    targets=selected(a.analysis/'crossover_extended.csv')
    if not targets:raise SystemExit('no auditable D=2 crossover at 2 <= N <= 256')
    a.output.mkdir(parents=True)
    for profile,sizes in targets.items():
        source_population=a.source/'population'/profile;population=a.output/'population'/profile;population.mkdir(parents=True)
        for i in range(max(sizes)):
            shutil.copy2(source_population/f'{i}.pem',population/f'{i}.pem')
        shutil.copy2(source_population/'0.key',population/'0.key')
        seed=a.source/'batch16'/'mtc'/profile
        keys=[seed/f'cosigner-{i}.key' for i in range(2)]
        for n in sizes:
            out=a.output/f'batch{n}'/'mtc'/profile;out.parent.mkdir(parents=True,exist_ok=True)
            prepare(out,a.output/'population',profile,n,originals=[population/f'{i}.pem' for i in range(n)],signer_keys=keys,metadata={'experiment':'crossover-boundary-audit','analytical_source':str(a.analysis)})
    (a.output/'boundary-plan.json').write_text(json.dumps({'profiles':targets,'source':str(a.source),'analysis':str(a.analysis)},indent=2)+'\n')
    print(a.output)
if __name__=='__main__':main()
