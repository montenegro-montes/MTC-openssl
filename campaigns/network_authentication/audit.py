"""Read-only offline audit. Does not call Docker or regenerate evidence."""
from .common import load, frozen, schedule, require, sha, fixture_inventory, verify_inventory
from .metrics import parse_metrics, validate


def audit(root):
    manifest = frozen(root)
    seen = set()
    stages = {}
    for stage in ['preflight', 'smoke', 'full']:
        directory = root / stage
        status = load(directory / 'status.json')
        require(status['passed'] is True and status['state'] == 'complete', 'Stage not complete: ' + stage)
        require(status['manifest_sha256'] == sha(root / 'manifest.json'), 'Stage manifest mismatch')
        inventory = load(directory / 'integrity.json')
        verify_inventory(directory, inventory)
        actual = fixture_inventory(directory); actual.pop('integrity.json')
        require(actual == inventory, 'Stage inventory changed')
        success = failure = measured = warmups = 0
        for block in schedule(manifest['protocol'], stage):
            out = directory / block['id']
            require(load(out / 'network-validation.json')['passed'], 'Network validation failed')
            rows = [__import__('json').loads(line) for line in (out / 'observations.jsonl').read_text().splitlines()]
            expected = [(rnd, order, case) for rnd in block['rounds'] for order, case in enumerate(rnd['cases'], 1)]
            require(len(rows) == len(expected), 'Missing/extra attempts in ' + block['id'])
            for row, (rnd, order, case) in zip(rows, expected):
                require(row['case'] == case and row['phase'] == rnd['phase'] and row['round'] == rnd['round']
                        and row['order'] == order and row['campaign'] == block['id']
                        and row['condition'] == block['condition']['name']
                        and row['repetition'] == block['repetition'], 'Order or pairing mismatch')
                measured += row['phase'] == 'measured'; warmups += row['phase'] == 'warmup'
                raw = out / 'raw' / row['raw_stem']
                cl = raw.with_suffix('.client.log').read_text(); sl = raw.with_suffix('.server.log').read_text()
                if row['success'] == 1:
                    client = parse_metrics(cl); server = load(raw.with_suffix('.server-metrics.json'))
                    parsed = validate(case, cl, sl, client, server)
                    require(all(row[k] == value for k, value in parsed.items()), 'Observation differs from raw endpoint metrics')
                    require(row['client_random'] not in seen, 'Duplicate client_random across stages/rounds')
                    seen.add(row['client_random']); success += 1
                else:
                    require(stage == 'full' and block['condition']['loss_percent'] > 0,
                            'Unexpected failed positive gate')
                    require(row['failure_kind'] in ['timeout', 'tls-error'], 'Integrity or infrastructure failure')
                    failure += 1
            if stage == 'preflight':
                controls = load(out / 'negative-controls.json')
                expected_negative = [c for c in manifest['cases'] if c['authentication'] == 'mutual']
                require([r['case'] for r in controls] == expected_negative, 'Negative control coverage mismatch')
                for index, row in enumerate(controls):
                    text = (out / 'raw' / f'negative-{index:02d}.server.log').read_text()
                    require(row['expected_rejection'] is True and
                            ('peer did not return a certificate' in text or 'certificate required' in text.lower())
                            and 'SSL_accept:SSLv3/TLS read finished' not in text,
                            'Missing-client rejection not evidenced')
        stages[stage] = {'measured_attempts': measured, 'warmup_attempts': warmups,
                         'successful_including_warmups': success, 'failed_including_warmups': failure}
    return {'passed': True, 'manifest_sha256': sha(root / 'manifest.json'), 'stages': stages,
            'scope': 'Offline internal consistency; not independent replication or full draft compliance'}
