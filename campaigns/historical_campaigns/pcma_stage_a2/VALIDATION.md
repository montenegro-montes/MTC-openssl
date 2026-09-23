# Preparation validation — 2026-09-11

Only lightweight local checks were executed. No scientific Stage A.2 results
were generated. All new maintained files are under `campaigns/historical_campaigns/pcma_stage_a2/`.
Existing Stage-A source, fixture and result files were not edited.

Exact validation commands (run from the repository root):

```sh
./campaigns/historical_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --diagnostic
./campaigns/historical_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --help
./campaigns/historical_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --check-config
./campaigns/historical_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh
sh -n campaigns/historical_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh
git diff --check
git status --short
git diff --name-only -- campaigns/historical_campaigns/pcma compact integration artifacts
```

Exact syntax/configuration parsing check:

```sh
python3 - <<'PY'
import ast
import json
from pathlib import Path
root = Path('campaigns/historical_campaigns/pcma_stage_a2')
for p in sorted(root.glob('*.py')):
    ast.parse(p.read_text(), filename=str(p))
    print('syntax OK:', p)
for p in sorted((root/'configs').glob('*.json')):
    json.loads(p.read_text())
    print('JSON OK:', p)
PY
```

The diagnostic was rerun during implementation after changes. Its first pass
found a mistaken negative test: the coordinate submode was a valid canonical
winner for empty hybrid state. The test was corrected to supply a losing range
submode. Subsequent passes succeeded. Final suite: **13 tests, all passing**.

Coverage includes all 64 possible semantic states of an N=4 non-root universe;
empty, single, multiple and maximum N=1024 coordinates (no N=1024 Merkle tree
or workload simulation); exact original PCA1 sizes; canonical hybrid tie breaks;
truncation at every byte boundary; wrong roots/tree sizes; invalid dimensions;
unknown version/mode; duplicate entries; malformed integers, ranges, bitmaps and
padding; missing/corrupt local hashes; four handcrafted accesses on N=4/8 with
both policies and small budgets; seed offsets and matrix arithmetic.

A source-equivalence test calls the original Stage-A simulation function with
a mocked N=4 handcrafted fixture and only four accesses, for each policy. It
never reads production fixtures or launches the Stage-A command/campaign.
Baseline advertisement, proof reuse, cache counts and net saving agree.

Audit negative tests use two handwritten accounting rows in an automatically
deleted temporary directory. They detect omissions, duplicates, seed/leaf/cache
inconsistency, changed proof signatures and broken net equations. The same tiny
fixture tests summary/Pareto generation and CSV/LaTeX table plumbing. Decision
logic tests use in-memory synthetic witnesses only. These values are not
experimental findings and were not preserved as scientific outputs.

No-argument CLI prints help. Configuration parsing reports 144 trajectories,
720 format configurations and 720,000 expected observations. Output refusal
is tested before fixture access. No tracked differences were reported under
`campaigns/historical_campaigns/pcma`, `compact`, `integration`, or `artifacts` during final checks.
Git does not track all generated artifacts; preservation of ignored results
also follows from making no writes to those paths during this task.

Deliberately **not executed**:

- `--single`, `--full`, any 1000-access campaign or full result audit;
- any Stage-A campaign, Stage B, TLS, Docker or network experiment;
- CLI analysis/table/plot/GO commands against scientific results;
- plotting, dependency installation, or a large benchmark.

Campaign runtime, full-scale resource consumption, external historical pairing,
real-data plots and publication layout remain unvalidated until manual execution.
No GO/NO-GO conclusion has been drawn for Stage A.2.

Additional check of the 11 new maintained files (needed because ordinary
`git diff --check` does not include untracked files):

```sh
python3 - <<'PY'
from pathlib import Path
root=Path('campaigns/historical_campaigns/pcma_stage_a2')
files=sorted(p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
for p in files:
    for i,line in enumerate(p.read_text().splitlines(),1):
        if line.rstrip()!=line:
            raise SystemExit(f'trailing whitespace: {p}:{i}')
print(f'PASS whitespace check: {len(files)} new maintained files')
PY
```
