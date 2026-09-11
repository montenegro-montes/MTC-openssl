"""Prepare or manually execute the isolated PCMA Stage A.2 laboratory."""
import argparse
import datetime
import json
from pathlib import Path
import sys
import uuid

from analysis import aggregate, decision, plots, summarize, tables
from audit import audit
from formats import MODES, SCHEMES
from lab import DEFAULT, config_read, configurations, execute, json_write


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    for name in ('diagnostic','single','full','analyze','plots','tables','go-no-go','audit','check-config'):
        modes.add_argument('--'+name, action='store_true')
    p.add_argument('--config',type=Path,default=DEFAULT)
    p.add_argument('--fixtures',type=Path,help='existing Stage-A fixtures.json; never regenerates fixtures')
    p.add_argument('--output',type=Path,help='NEW output directory; defaults to a unique artifacts/results/pcma-stage-a2-* directory')
    p.add_argument('--results',type=Path,help='existing A.2 result directory for read-only analysis')
    p.add_argument('--stage-a-results',type=Path,help='existing Stage-A matrix for strict paired comparison')
    p.add_argument('--tree-size',type=int,choices=[16,64,256,1024],default=1024)
    p.add_argument('--workload',choices=['uniform','zipf','clustered'],default='clustered')
    p.add_argument('--policy','--cache-policy',choices=['lru','upper-level'],default='lru')
    p.add_argument('--cache-kb',type=int,choices=[0,1,2,4,8,16],default=1)
    p.add_argument('--advertisement',choices=list(SCHEMES)+['trimmed-bitmap','all'],default='all')
    p.add_argument('--seed',type=int,help='base seed for full; literal workload seed for single')
    p.add_argument('--accesses',type=int)
    a = p.parse_args(argv)
    selected = next((name for name in ('diagnostic','single','full','analyze','plots','tables','go_no_go','audit','check_config') if getattr(a,name)),None)
    if selected is None:
        p.print_help()
        return
    if a.diagnostic:
        import unittest
        from test_stage_a2 import FormatTests, LaboratoryTests
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (FormatTests,LaboratoryTests))
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
            raise SystemExit(1)
        return
    c = config_read(a.config)
    if a.seed is not None:
        c['base_seed']=a.seed
    if a.accesses is not None:
        if a.accesses < 1:
            p.error('--accesses must be positive')
        c['accesses']=a.accesses
    if a.check_config:
        print(json.dumps(dict(configuration=c, base_configurations=len(configurations(c)),
                              scheme_configurations=len(configurations(c))*len(c['schemes']),
                              observations=len(configurations(c))*len(c['schemes'])*c['accesses']),indent=2))
        return
    if a.full or a.single:
        if a.fixtures is None:
            p.error('--fixtures is required for manual execution')
        if a.results:
            p.error('--results is for analysis only')
        if a.full and a.advertisement != 'all':
            p.error('custom full schemes must be selected in --config')
    elif a.results is None:
        p.error('--results is required')
    if a.audit:
        print(json.dumps(audit(a.results),indent=2)); return
    if a.go_no_go:
        audit(a.results)
        manifest=json.loads((a.results/'manifest.json').read_text())
        value=decision(summarize(a.results),manifest['configuration'])
        print(json.dumps(value,indent=2))
        if a.output:
            a.output.mkdir(parents=True,exist_ok=False)
            json_write(a.output/'go-no-go.json',value)
        return
    output=a.output or Path('artifacts/results')/('pcma-stage-a2-'+selected+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
    if output.exists():
        p.error('output exists; choose a new directory')
    if a.full or a.single:
        c['execution']='full' if a.full else 'single'
        configs=configurations(c)
        if a.single:
            c.update(tree_sizes=[a.tree_size], workloads=[a.workload], policies=[a.policy], budgets_kb=[a.cache_kb])
            c['schemes']=c['schemes'] if a.advertisement=='all' else [a.advertisement]
            configs=[dict(tree_size=a.tree_size,workload=a.workload,cache_policy=a.policy,
                          cache_budget_bytes=a.cache_kb*1024,seed=c['base_seed'])]
        execute(output,a.fixtures.resolve(),c,configs)
        aggregate(output,output/'analysis',a.stage_a_results)
    elif a.analyze:
        aggregate(a.results,output,a.stage_a_results)
    elif a.plots:
        plots(a.results,output)
    elif a.tables:
        tables(a.results,output,a.stage_a_results)
    print(output)


if __name__=='__main__':
    try:
        main()
    except (ValueError, FileExistsError, FileNotFoundError, KeyError) as e:
        raise SystemExit(str(e))
