"""Prepare and inspect an isolated experiment; execution always needs --execute."""
import argparse
import json
import shutil
from pathlib import Path
from .common import (REPO, protocol, cases, schedule, source_inventory, fixture_inventory,
                     save, sha, load, require, image_id, git_metadata, frozen)


def freeze(fixtures, image, output):
    fixtures, output = fixtures.resolve(), output.resolve()
    require(output.is_relative_to(REPO / 'artifacts/results'), 'Use artifacts/results/...')
    require(not output.exists(), 'Output exists; no overwrite or resume')
    require(fixtures.is_relative_to(REPO / 'artifacts/network-authentication'), 'Use new isolated fixtures')
    require(load(fixtures / 'preparation-status.json')['passed'] is True, 'Fixture preparation incomplete')
    spec = protocol()
    provenance = load(fixtures / 'provenance.json')
    require(provenance['image_id'] == image_id(image), 'Use the same image for preparation and measurement')
    sources = source_inventory()
    require(provenance['source_sha256'] == sources, 'Sources changed since fixture preparation; use a fresh preparation')
    for profile, sizes in spec['profiles'].items():
        for role in ['server', 'client']:
            base = fixtures / profile / role
            for name in ['ca.pem', 'leaf-0000.pem', 'leaf-0000.key']:
                require((base / name).is_file(), 'Missing fixture ' + str(base / name))
            for n in sizes:
                m = load(base / f'mtc-n{n}/manifest.json')
                require(m['profile'] == profile and m['tree_size'] == n and m['role'] == role, 'Fixture identity mismatch')
                require(m['baseline_leaf_sha256'] == sha(base / 'leaf-0000.pem'), 'MTC and X.509 source leaf differ')
                for name in ['landmark-0000.pem', 'trust.bin']:
                    require((base / f'mtc-n{n}' / name).is_file(), 'Missing MTC material')
    output.mkdir(parents=True)
    m = {'protocol': spec, 'image_id': image, 'fixtures': str(fixtures), 'git': git_metadata(),
         'source_sha256': sources, 'fixture_sha256': fixture_inventory(fixtures),
         'cases': cases(spec), 'tls_executed': False}
    for name in sources:
        dest = output / 'source' / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, dest)
    save(output / 'manifest.json', m)
    (output / 'manifest.sha256').write_text(sha(output / 'manifest.json') + '\n')
    print(json.dumps({'root': str(output), 'cases': len(m['cases']), 'frozen': True}, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('plan')
    f = sub.add_parser('freeze'); f.add_argument('--fixtures', type=Path, required=True)
    f.add_argument('--image', required=True); f.add_argument('--output', type=Path, required=True)
    for command in ['preflight', 'smoke', 'full', 'audit', 'analyze']:
        a = sub.add_parser(command); a.add_argument('root', type=Path)
        if command in ['preflight', 'smoke', 'full']:
            a.add_argument('--execute', action='store_true')
        if command == 'analyze':
            a.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    if a.command == 'plan':
        spec = protocol()
        n = len(cases(spec)); blocks = len(spec['conditions']) * spec['campaign_repetitions']
        print(json.dumps({'protocol': spec, 'cases': cases(spec), 'full_campaign_blocks': blocks,
                          'measured_attempts': blocks * n * spec['measured_rounds'],
                          'warmup_attempts': blocks * n * spec['warmup_rounds'],
                          'tls_executed': False}, indent=2))
    elif a.command == 'freeze':
        freeze(a.fixtures, a.image, a.output)
    elif a.command in ['preflight', 'smoke', 'full']:
        m = frozen(a.root)
        if not a.execute:
            blocks = schedule(m['protocol'], a.command)
            print(json.dumps({'stage': a.command, 'execute': False, 'blocks': len(blocks),
                              'attempts': sum(len(r['cases']) for b in blocks for r in b['rounds']),
                              'negative_mutual_controls': sum(c['authentication']=='mutual' for c in m['cases']) if a.command=='preflight' else 0}, indent=2))
        else:
            from .runner import execute
            execute(a.root.resolve(), a.command, m)
    elif a.command == 'audit':
        from .audit import audit
        print(json.dumps(audit(a.root.resolve()), indent=2))
    else:
        from .analyze import analyze
        analyze(a.root.resolve(), a.output.resolve())


if __name__ == '__main__':
    main()
