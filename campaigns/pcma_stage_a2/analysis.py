"""Aggregation, predefined decision criteria, publication tables and seven plots."""
import csv
import json
import statistics
from collections import defaultdict

from audit import audit, compare_stage_a
from lab import IDENTITY, csv_write, digest, json_write

GROUP = IDENTITY + ('advertisement_scheme',)


def summarize(directory):
    fields = ('advertisement_bytes', 'net_authentication_bytes', 'net_bytes_saved',
              'net_saving_percentage', 'cache_bytes', 'gross_proof_bytes_saved',
              'partial_proof_bytes', 'normal_proof_bytes')
    groups = {}
    with (directory/'observations.csv').open(newline='') as f:
        for row in csv.DictReader(f):
            key = tuple(row[k] for k in GROUP)
            sums, saved = groups.setdefault(key, ({field: 0.0 for field in fields}, []))
            for field in fields:
                sums[field] += float(row[field])
            saved.append(float(row['net_bytes_saved']))
    result = []
    for key, (sums, saved) in groups.items():
        r = dict(zip(GROUP, key))
        r['observations'] = len(saved)
        for field in fields:
            r['mean_'+field] = sums[field]/len(saved)
        r.update(median_net_bytes_saved=statistics.median(saved), maximum_net_bytes_saved=max(saved),
                 beneficial_authentication_percentage=100*sum(x > 0 for x in saved)/len(saved),
                 mean_benefit=r['mean_net_bytes_saved'] > 0)
        result.append(r)
    return result


def pareto(summary):
    result = []
    for r in summary:
        peers = [p for p in summary if (p['tree_size'], p['workload']) == (r['tree_size'], r['workload'])]
        x, y = r['mean_cache_bytes'], r['mean_net_authentication_bytes']
        dominated = any(p['mean_cache_bytes'] <= x and p['mean_net_authentication_bytes'] <= y and
                        (p['mean_cache_bytes'] < x or p['mean_net_authentication_bytes'] < y) for p in peers)
        result.append(dict(r, pareto_optimal=not dominated))
    return result


def decision(summary, c):
    compact = [r for r in summary if r['advertisement_scheme'] != 'baseline']
    witnesses = {}
    for n in ('256', '1024'):
        for w in ('uniform', 'zipf', 'clustered'):
            choices = [r for r in compact if r['tree_size'] == n and r['workload'] == w and r['mean_net_bytes_saved'] > 0]
            witnesses[n+'/'+w] = max(choices, key=lambda r: r['mean_net_bytes_saved']) if choices else None
    baseline = {tuple(r[k] for k in IDENTITY): r for r in summary if r['advertisement_scheme'] == 'baseline'}
    improvements = []
    threshold = c['material_advertisement_reduction_percent']
    for r in compact:
        b = baseline.get(tuple(r[k] for k in IDENTITY))
        if b:
            reduction = 100*(b['mean_advertisement_bytes']-r['mean_advertisement_bytes'])/b['mean_advertisement_bytes']
            if reduction >= threshold and r['mean_net_bytes_saved'] > b['mean_net_bytes_saved']:
                improvements.append(dict(r, advertisement_reduction_percentage=reduction))
    criteria = {
        '1_positive_mean_N256_N1024_all_workloads': all(witnesses.values()),
        '2_benefit_includes_advertisement': any(r['mean_net_bytes_saved'] > 0 for r in compact),
        '3_material_improvement_over_PCA1': bool(improvements),
        '4_not_exclusively_clustered': any(r['workload'] != 'clustered' and r['mean_net_bytes_saved'] > 0 for r in compact),
        '5_no_raw_cached_hash_advertisement': bool(compact),
    }
    strong = [r for r in compact if r['tree_size'] == '1024' and int(r['cache_budget_bytes']) <= 4096 and r['mean_net_saving_percentage'] >= 15]
    complete = (c.get('execution') == 'full' and set(c['tree_sizes']) == {16,64,256,1024}
                and set(c['workloads']) == {'uniform','zipf','clustered'}
                and set(c['policies']) == {'lru','upper-level'} and set(c['budgets_kb']) == {0,1,2,4,8,16}
                and set(c['schemes']) >= {'baseline','coordinates','bitmap','ranges','hybrid'})
    return dict(outcome=('GO' if all(criteria.values()) else 'NO-GO') if complete else 'INCOMPLETE_SCOPE',
                criteria=criteria, strong_go=len({r['workload'] for r in strong}) >= 2 if complete else None,
                material_threshold_percent=threshold, witnesses=witnesses, material_witnesses=improvements,
                strong_witnesses=strong, comparison='paired PCA1 replay within A.2; external Stage-A pairing separate',
                interpretation='Criterion 1 allows different compact schemes/budgets per N/workload; criterion 3 requires >= threshold mean advertisement reduction and improved mean net saving.',
                executes_stage_b=False)


def aggregate(directory, output, stage_a=None):
    report = audit(directory)
    summary = summarize(directory)
    manifest = json.loads((directory/'manifest.json').read_text())
    comparison = compare_stage_a(directory, stage_a) if stage_a else None
    output.mkdir(parents=True, exist_ok=False)
    csv_write(output/'summary.csv', summary)
    csv_write(output/'pareto.csv', pareto(summary))
    if comparison:
        csv_write(output/'stage_a_comparison.csv', comparison)
    json_write(output/'analysis.json', dict(audit=report, decision=decision(summary, manifest['configuration']),
               external_stage_a_paired=stage_a is not None,
               stage_a_manifest_sha256=digest(stage_a/'manifest.json') if stage_a else None,
               output_sha256={p.name: digest(p) for p in output.glob('*.csv')}))
    return output


def tables(directory, output, stage_a=None):
    audit(directory)
    summary = summarize(directory)
    comparison = compare_stage_a(directory, stage_a) if stage_a else None
    output.mkdir(parents=True, exist_ok=False)
    grouped = defaultdict(list)
    for row in summary:
        grouped[(row['tree_size'], row['workload'])].append(row)
    best = [max(rows, key=lambda r: (r['mean_net_bytes_saved'], -int(r['cache_budget_bytes']), r['advertisement_scheme'])) for rows in grouped.values()]
    # Full table preserves mean/median/maximum and beneficial percentages for every cell.
    csv_write(output/'all_configurations.csv', summary)
    csv_write(output/'best_scheme_and_budget.csv', best)
    if comparison:
        csv_write(output/'stage_a_reduction.csv', comparison)
    def latex(rows, fields):
        def esc(v):
            return str(v).replace('_', r'\_').replace('%', r'\%')
        lines = [r'\begin{tabular}{'+'l'*len(fields)+'}', ' & '.join(map(esc, fields))+r' \\ \hline']
        for r in rows:
            lines.append(' & '.join(esc(f'{r[k]:.3f}' if isinstance(r[k], float) else r[k]) for k in fields)+r' \\')
        return '\n'.join(lines+[r'\end{tabular}', ''])
    fields = ['tree_size','workload','advertisement_scheme','cache_policy','cache_budget_bytes',
              'maximum_net_bytes_saved','mean_net_bytes_saved','median_net_bytes_saved','beneficial_authentication_percentage']
    for name, rows in [('best_scheme_and_budget', best), ('all_configurations', summary)]:
        with (output/(name+'.tex')).open('x') as f:
            f.write(latex(rows, fields))
    if comparison:
        with (output/'stage_a_reduction.tex').open('x') as f:
            f.write(latex(comparison, list(GROUP)+['advertisement_reduction_percentage','improvement']))
    json_write(output/'manifest.json', dict(source_sha256=digest(directory/'observations.csv'),
                                          output_sha256={p.name:digest(p) for p in output.iterdir()}))


def plots(directory, output):
    audit(directory)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    summary = summarize(directory)
    output.mkdir(parents=True, exist_ok=False)
    def save(fig, name):
        fig.tight_layout()
        fig.savefig(output/(name+'.png'), dpi=160)
        fig.savefig(output/(name+'.pdf'))
        plt.close(fig)
    def panel(rows, x, y, group_fields, name):
        grouped = defaultdict(list)
        for r in rows:
            grouped[tuple(r[k] for k in group_fields)].append(r)
        for group, points in grouped.items():
            fig, ax = plt.subplots(figsize=(8,5))
            for scheme in sorted({r['advertisement_scheme'] for r in points}):
                series = sorted([r for r in points if r['advertisement_scheme']==scheme], key=lambda r:float(r[x]))
                ax.plot([float(r[x]) for r in series], [float(r[y]) for r in series], marker='.', label=scheme)
            ax.set(xlabel=x, ylabel=y, title=' / '.join(map(str,group)))
            ax.axhline(0, color='grey', linewidth=.5)
            ax.legend(fontsize='small')
            save(fig, name+'_'+'_'.join(map(str,group)))
    for name, y in [('01_net_vs_budget','mean_net_bytes_saved'), ('02_advertisement_vs_budget','mean_advertisement_bytes'),
                    ('04_beneficial_vs_budget','beneficial_authentication_percentage')]:
        panel(summary,'cache_budget_bytes',y,('tree_size','workload','cache_policy'),name)
    panel(summary,'tree_size','mean_net_saving_percentage',('workload','cache_policy','cache_budget_bytes'),'03_percent_vs_N')
    for n,w in sorted({(r['tree_size'],r['workload']) for r in summary}):
        points=[r for r in pareto(summary) if r['tree_size']==n and r['workload']==w]
        fig,ax=plt.subplots(figsize=(8,5))
        for scheme in sorted({r['advertisement_scheme'] for r in points}):
            ps=[r for r in points if r['advertisement_scheme']==scheme]
            ax.scatter([r['mean_cache_bytes'] for r in ps],[r['mean_net_authentication_bytes'] for r in ps],label=scheme)
        frontier=sorted([r for r in points if r['pareto_optimal']],key=lambda r:r['mean_cache_bytes'])
        ax.plot([r['mean_cache_bytes'] for r in frontier],[r['mean_net_authentication_bytes'] for r in frontier],color='black',label='Pareto frontier')
        ax.set(xlabel='mean client storage (bytes)',ylabel='mean net authentication bytes',title=f'N={n} / {w}')
        ax.legend(fontsize='small');save(fig,f'05_pareto_{n}_{w}')
    baseline={tuple(r[k] for k in IDENTITY):r for r in summary if r['advertisement_scheme']=='baseline'}
    fig,ax=plt.subplots(figsize=(7,5))
    for key,b in baseline.items():
        peers=[r for r in summary if tuple(r[k] for k in IDENTITY)==key and r['advertisement_scheme']!='baseline']
        if peers:
            ax.scatter(b['mean_advertisement_bytes'],min(r['mean_advertisement_bytes'] for r in peers),s=12)
    ax.set(xlabel='PCA1 mean advertisement bytes',ylabel='best compact mean advertisement bytes')
    save(fig,'06_baseline_vs_best')
    # One panel per base configuration: avoid mixing incompatible cache budgets.
    with (directory/'observations.csv').open(newline='') as f:
        panel(({k: r[k] for k in IDENTITY+('advertisement_scheme','access_t','net_bytes_saved')} for r in csv.DictReader(f)), 'access_t','net_bytes_saved',IDENTITY,'07_progression')
    json_write(output/'manifest.json',dict(source_sha256=digest(directory/'observations.csv'),output_sha256={p.name:digest(p) for p in output.iterdir()}))
