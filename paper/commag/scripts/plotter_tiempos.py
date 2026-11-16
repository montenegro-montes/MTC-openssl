#!/usr/bin/env python3
"""3D server-authentication plots from authentication_statistics.csv.

python3 plotter_tiempos.py authentication_statistics.csv --figure auth
python3 plotter_tiempos.py authentication_statistics.csv --figure merkle --unit us
python3 plotter_tiempos.py authentication_statistics.csv --figure all --statistic median

Requires matplotlib. All configuration and labels below are editable.
"""
import argparse
import csv
import json
from decimal import Decimal
from pathlib import Path

# Appearance: same palette and camera convention as the earlier size plotter.
FIGSIZE = (12, 8)
FONT_SIZE = 12
ELEVATION = 20
AZIMUTH = -120
DEFAULT_STATISTIC = 'mean'
DEFAULT_UNIT = 'ms'
DEFAULT_FORMATS = ['png', 'pdf']
DPI = 200
SECURITY_LEVELS = {
    '1': ['ecdsa-p256', 'mldsa44', 'slhdsa128s'],
    '3': ['ecdsa-p384', 'mldsa65', 'slhdsa192s'],
    '5': ['ecdsa-p521', 'mldsa87', 'slhdsa256s'],
}
CLIENTS = ['s_client', 'chromium']
CASES = ['x509', 'landmark', 'standalone']
CASE_LABELS = {'x509': 'X.509', 'landmark': 'MTC\nLandmark', 'standalone': 'MTC\nStandalone'}
STATISTICS = ['mean', 'median', 'stddev', 'min', 'q1', 'q3', 'iqr', 'p05', 'p95', 'max']
FIGURES = ['auth', 'credential', 'credential-detail', 'mtc', 'merkle', 'auth-detail']
AUTH = 'auth_total_ns'
CRED = 'credential_validation_total_ns'
CV = 'certificate_verify_crypto_ns'
X509 = 'x509_signatures_ns'
MTC = 'mtc_total_ns'
MERKLE = 'merkle_total_ns'
LEAF = 'merkle_leaf_hash_ns'
PATH = 'merkle_path_ns'
TRUST = 'landmark_trust_ns'
SIG = 'standalone_signatures_ns'
CRED_R = 'credential_residual_ns'
MTC_R = 'mtc_residual_ns'
MERKLE_R = 'merkle_residual_ns'
LABELS = {
    AUTH: 'Measured authentication', CRED: 'Credential validation',
    CV: 'CertificateVerify', X509: 'X.509 signatures', MTC: 'MTC verification',
    MERKLE: 'Merkle verification', LEAF: 'Leaf construction / hash',
    PATH: 'Merkle path', TRUST: 'Landmark trust', SIG: 'Standalone signatures',
    CRED_R: 'Credential residual', MTC_R: 'Internal MTC residual',
    MERKLE_R: 'Internal Merkle residual',
}
COLORS = {
    AUTH: '#4C566A', CV: '#0173B2', CRED: '#DE8F05', X509: '#0173B2',
    MTC: '#029E73', MERKLE: '#0173B2', LEAF: '#56B4E9', PATH: '#0173B2',
    TRUST: '#CC78BC', SIG: '#CC78BC', CRED_R: '#949494',
    MTC_R: '#CA9161', MERKLE_R: '#029E73',
}


def components(figure, case):
    """Return an inclusive height and mutually exclusive stack segments."""
    binding = TRUST if case == 'landmark' else SIG
    if figure == 'auth':
        return AUTH, [CV, CRED]
    if figure == 'credential':
        return CRED, [X509 if case == 'x509' else MTC, CRED_R]
    if figure in {'credential-detail', 'auth-detail'}:
        inner = [X509, CRED_R] if case == 'x509' else [LEAF, PATH, MERKLE_R, binding, MTC_R, CRED_R]
        return (AUTH, [CV, *inner]) if figure == 'auth-detail' else (CRED, inner)
    if figure == 'mtc':
        return MTC, [MERKLE, binding, MTC_R]
    if figure == 'merkle':
        return MERKLE, [LEAF, PATH, MERKLE_R]
    raise ValueError('Unknown figure: '+figure)


def load_statistics(path):
    with path.open(newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        required = {'client', 'profile', 'credential_type', 'mtc_verification_mode',
                    'metric', 'unit', 'phase', 'n_valid', 'n_observations', 'n_missing', *STATISTICS}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('Missing columns: '+str(sorted(required-set(reader.fieldnames or []))))
        data = {}
        for row in reader:
            if row['phase'] != 'measured':
                continue
            if row['unit'] != 'ns':
                raise ValueError('The input statistics must be in ns')
            case = 'x509' if row['credential_type'] == 'x509' else row['mtc_verification_mode']
            if row['client'] not in CLIENTS or case not in CASES:
                raise ValueError('Unknown client or credential mode')
            if row['profile'] not in {p for ps in SECURITY_LEVELS.values() for p in ps}:
                raise ValueError('Add the unknown signature profile to SECURITY_LEVELS: '+row['profile'])
            key = (row['client'], row['profile'], case, row['metric'])
            if key in data:
                raise ValueError('Multiple configurations have the same public labels. Select a single configuration before plotting: '+str(key))
            data[key] = row
    if not data:
        raise ValueError('No measured statistics found')
    return data


def cell(data, client, profile, case, metric, statistic):
    key = (client, profile, case, metric)
    if key not in data:
        raise ValueError('Missing metric '+metric+'. Regenerate statistics with the updated prepare_authentication.py')
    row = data[key]
    if int(row['n_valid']) == 0 or row[statistic] == '':
        raise ValueError('No valid '+statistic+' for '+str(key))
    val = Decimal(row[statistic])
    if not val.is_finite() or val < 0:
        raise ValueError('Invalid or negative plotted value: '+str(key))
    return val, row


def make_cells(data, client, profiles, figure, args):
    cells = []
    cases = CASES if figure not in {'mtc', 'merkle'} else ['landmark', 'standalone']
    for profile in profiles:
        for case in cases:
            if not any(k[:3] == (client, profile, case) for k in data):
                continue
            total_metric, segments = components(figure, case)
            total, total_row = cell(data, client, profile, case, total_metric, args.statistic)
            parts = []
            for metric in segments if args.layout != 'total' else []:
                value, row = cell(data, client, profile, case, metric, args.statistic)
                if args.layout == 'stacked':
                    if (row['n_valid'], row['n_observations']) != (total_row['n_valid'], total_row['n_observations']) or int(row['n_missing']) != 0 or int(total_row['n_missing']) != 0:
                        raise ValueError('Stacked means require complete components over the same included observations')
                parts.append((metric, value))
            if args.layout == 'stacked':
                # Two-decimal ns CSV rounding can cause <= .005 ns per term.
                tolerance = Decimal('.005')*(len(parts)+1)+Decimal('.000001')
                if abs(sum(v for _, v in parts)-total) > tolerance:
                    raise ValueError('Stack components do not match the measured parent mean: '+str((client, profile, case, figure)))
            cells.append(dict(profile=profile, case=case, total_metric=total_metric,
                              total=total, parts=parts, n=int(total_row['n_valid'])))
    return cases, cells


def plot_one(data, client, level, figure, args):
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from mpl_toolkits.mplot3d import proj3d
    profiles = [p for p in SECURITY_LEVELS[level] if any(k[:2] == (client, p) for k in data)]
    if not profiles:
        return []
    cases, cells = make_cells(data, client, profiles, figure, args)
    if not cells:
        return []
    fig = plt.figure(figsize=tuple(args.figsize))
    ax = fig.add_subplot(111, projection='3d')
    divisor = {'ns': Decimal(1), 'us': Decimal(1000), 'ms': Decimal(1000000)}[args.unit]
    unit_label = 'µs' if args.unit == 'us' else args.unit
    maximum = float(max([c['total'] for c in cells]+[v for c in cells for _, v in c['parts']])/divisor)
    maximum = maximum if maximum else 1.0
    shown = []
    audit = []
    value_labels = []
    for c in cells:
        x, y = cases.index(c['case'])*1.4, profiles.index(c['profile'])*1.1
        total = float(c['total']/divisor)
        if args.layout == 'stacked':
            bottom = 0
            for metric, value in c['parts']:
                height = float(value/divisor)
                ax.bar3d(x, y, bottom, .4, .4, height, color=COLORS[metric], shade=True)
                bottom += height
                if metric not in shown:
                    shown.append(metric)
            label_x, label_y = x+.2, y+.2
        elif args.layout == 'total':
            metric = c['total_metric']
            ax.bar3d(x, y, 0, .4, .4, total, color=COLORS[metric], shade=True)
            if metric not in shown:
                shown.append(metric)
            label_x, label_y = x+.2, y+.2
        else:
            bars = [(c['total_metric'], c['total']), *c['parts']]
            width = .85/len(bars)
            for i, (metric, value) in enumerate(bars):
                ax.bar3d(x, y+i*width, 0, .4, width*.82, float(value/divisor), color=COLORS[metric], shade=True)
                if metric not in shown:
                    shown.append(metric)
            label_x, label_y = x+.2, y+width*.4
        if args.values:
            value_labels.append((label_x, label_y, total, f'{total:.{args.decimals}f}'))
        audit.append({'client':client,'level':level,'figure':figure,'profile':c['profile'],
                      'mode':c['case'],'statistic':args.statistic,'layout':args.layout,
                      'total_metric':c['total_metric'],'total_ns':str(c['total']),
                      'components_ns':{m:str(v) for m,v in c['parts']},'n_valid':c['n']})
    ax.set_xticks([i*1.4+.2 for i in range(len(cases))], [CASE_LABELS[c] for c in cases])
    ax.set_yticks([i*1.1+.2 for i in range(len(profiles))], profiles)
    ax.tick_params(axis='x', labelsize=11, pad=6)
    ax.tick_params(axis='y', labelsize=11, pad=10)
    ax.tick_params(axis='z', labelsize=10, pad=5)
    ax.set_zlim(0, maximum*1.18)
    ax.view_init(elev=args.elev, azim=args.azim)
    # Draw labels above the 3D layer so front faces cannot hide their text.
    for x, y, z, label in value_labels:
        px, py, _ = proj3d.proj_transform(x, y, z+maximum*.025, ax.get_proj())
        ax.annotate(label, (px, py), xytext=(0, 6), textcoords='offset points',
                    ha='center', va='bottom', fontsize=9, zorder=10000,
                    bbox=dict(facecolor='white', edgecolor='none', alpha=.7, pad=.2))
    fig.text(.08,.5,'Time ('+unit_label+')',rotation=90,va='center',fontsize=13)
    titles = {'auth':'Measured client authentication', 'credential':'Credential validation',
              'credential-detail':'Credential validation: detailed breakdown',
              'mtc':'Internal MTC verification', 'merkle':'Merkle verification',
              'auth-detail':'Measured client authentication: detailed breakdown'}
    fig.suptitle(f'{client} · Security level {level}\n{titles[figure]} ({args.statistic})',fontsize=15,y=.98)
    fig.legend(handles=[Patch(color=COLORS[m],label=LABELS[m]) for m in shown],
               loc='upper center',bbox_to_anchor=(.51,.9),ncol=min(3,len(shown)),fontsize=10,frameon=False)
    note = ('Stacked means of exclusive intervals; total labels use the measured parent mean.'
            if args.layout == 'stacked' else
            'Separate interval statistics; bars are not added. Labels show the measured parent.'
            if args.layout == 'components' else 'Single measured interval per bar; no component statistics are added.')
    ns = sorted({c['n'] for c in cells})
    fig.text(.12,.025,note+'\nn='+('/'.join(map(str,ns)))+' per group; no outlier filtering.',fontsize=9)
    fig.subplots_adjust(left=.17,right=.91,bottom=.14,top=.8)
    target = args.out_dir/client
    target.mkdir(parents=True,exist_ok=True)
    stem = f'{figure}_{args.statistic}_{args.layout}_level_{level}_{args.unit}'
    for ext in args.formats:
        fig.savefig(target/(stem+'.'+ext),dpi=args.dpi,bbox_inches='tight',pad_inches=.18)
    plt.close(fig)
    return audit


def main():
    p = argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('statistics_csv',type=Path)
    p.add_argument('--figure',choices=[*FIGURES,'all'],default='auth')
    p.add_argument('--statistic',choices=STATISTICS,default=DEFAULT_STATISTIC)
    p.add_argument('--layout',choices=['auto','stacked','components','total'],default='auto',
                   help='auto: stacked means; separate bars for other statistics')
    p.add_argument('--client',choices=[*CLIENTS,'both'],default='both')
    p.add_argument('--level',choices=['1','3','5','all'],default='all')
    p.add_argument('--unit',choices=['ms','us','ns'],default=DEFAULT_UNIT)
    p.add_argument('--formats',nargs='+',choices=['png','pdf','svg'],default=DEFAULT_FORMATS)
    p.add_argument('--out-dir',type=Path,default=Path('graphs_times'))
    p.add_argument('--figsize',nargs=2,type=float,default=FIGSIZE,metavar=('WIDTH','HEIGHT'))
    p.add_argument('--elev',type=float,default=ELEVATION)
    p.add_argument('--azim',type=float,default=AZIMUTH)
    p.add_argument('--dpi',type=int,default=DPI)
    p.add_argument('--decimals',type=int,default=3)
    p.add_argument('--no-values',dest='values',action='store_false')
    args = p.parse_args()
    if args.layout == 'auto':
        args.layout = 'stacked' if args.statistic == 'mean' else 'components'
    if args.layout == 'stacked' and args.statistic != 'mean':
        p.error('Only means are additive. Use --layout components or --layout total for other statistics.')
    if args.decimals < 0 or args.dpi <= 0 or any(v <= 0 for v in args.figsize):
        p.error('Invalid decimal count, DPI, or figure dimensions')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':FONT_SIZE,'font.family':'DejaVu Sans','axes.grid':True})
    data = load_statistics(args.statistics_csv)
    clients = CLIENTS if args.client == 'both' else [args.client]
    levels = list(SECURITY_LEVELS) if args.level == 'all' else [args.level]
    figures = FIGURES if args.figure == 'all' else [args.figure]
    audit = []
    for client in clients:
        for figure in figures:
            for level in levels:
                audit.extend(plot_one(data,client,level,figure,args))
    if not audit:
        raise ValueError('No figures match the requested selection')
    args.out_dir.mkdir(parents=True,exist_ok=True)
    manifest = f'plot_values_{args.figure}_{args.statistic}_{args.layout}_{args.client}_{args.level}_{args.unit}.json'
    (args.out_dir/manifest).write_text(json.dumps(audit,indent=2)+'\n')
    print(f'Created {len({(r["client"],r["figure"],r["level"]) for r in audit})} figures; values exported to {manifest}')


if __name__ == '__main__':
    main()
