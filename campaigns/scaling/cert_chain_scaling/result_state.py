"""Read-only validation of completed cells, including legacy measurement rows."""
import csv
import hashlib
import json
import math
from pathlib import Path
from config import PROFILES

METRICS=('handshake_wall_ms','client_cpu_ms','server_cpu_ms','authentication_processing_wall_ms',
         'authentication_processing_cpu_ms','certificate_message_bytes','certificate_verify_message_bytes',
         'tls_bio_read_bytes','tls_bio_written_bytes')


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def cell_name(profile,depth,campaign):return f'{profile}-d{depth}-c{campaign}'


def validate_complete(directory, profile, depth, campaign, manifest, fixture_hash):
    """A directory or CSV alone never establishes successful completion."""
    directory=Path(directory);data=directory/'data';errors=[]
    if not directory.exists():return 'MISSING',[]
    try:
        status=json.loads((data/'validation.json').read_text())
        if status.get('passed') is not True:raise ValueError('validation status is not passed')
        expected={'observations.csv':(manifest['repetitions'],0),'warmups.csv':(manifest['warmups'],1)}
        if status.get('measured_handshakes')!=manifest['repetitions'] or status.get('warmup_handshakes')!=manifest['warmups']:
            errors.append('validation counts differ from frozen run')
        used=set()
        for filename,(count,warm) in expected.items():
            with (data/filename).open() as f:rows=list(csv.DictReader(f))
            if len(rows)!=count:errors.append(filename+': wrong row count')
            rounds=[]
            for r in rows:
                rounds.append(int(r['round']))
                expected_seed=manifest['seed']+campaign+depth*100+list(PROFILES).index(profile)*1000
                if int(r['seed'])!=expected_seed:errors.append('seed differs from frozen run')
                if r['success']!='1' or int(r['is_warmup'])!=warm:errors.append('unsuccessful or misclassified row')
                if r['campaign']!=cell_name(profile,depth,campaign) or r['scenario']!=f'{profile}-d{depth}':errors.append('cell identity mismatch')
                if int(r.get('certificate_depth') or r['chain_depth'])!=depth:errors.append('depth mismatch')
                if r['fixture_hash']!=fixture_hash or r['image_id']!=manifest['image_id']:errors.append('fixture/image provenance mismatch')
                accepted_commits={manifest['git_commit'],*manifest.get('accepted_source_commits',[])}
                if r['git_commit'] not in accepted_commits:errors.append('source commit mismatch')
                if 'profile' in r:
                    config=manifest.get('configured_profiles',PROFILES)[profile]
                    if r['profile']!=profile or r['family']!=config['family'] or int(r['security_level'])!=config['level']:
                        errors.append('profile metadata mismatch')
                    if r.get('TLS_signature_supported') not in ('True','true','1'):errors.append('missing TLS support declaration')
                for name in METRICS:
                    number=float(r[name])
                    if not math.isfinite(number) or number<0:errors.append('invalid metric '+name)
                key=r['client_random']
                if len(key)!=64 or any(c not in '0123456789abcdefABCDEF' for c in key) or key in used:
                    errors.append('invalid/duplicate client random');continue
                used.add(key)
                log=data/'logs'/f'{"warmup" if warm else "sample"}-{int(r["round"]):04d}.log'
                if not log.is_file() or 'Verify return code: 0 (ok)' not in log.read_text():errors.append('missing authenticated client log')
                server=json.loads((data/'server-metrics'/(key+'.json')).read_text())
                if server['reused'] or int(server['certificate_message_bytes'])!=int(r['certificate_message_bytes']):errors.append('server invariant mismatch')
            if sorted(rounds)!=list(range(1,count+1)):errors.append(filename+': missing or duplicate rounds')
    except (OSError,ValueError,KeyError,TypeError) as error:errors.append(str(error))
    return ('INVALID_INCOMPLETE' if errors else 'COMPLETE'),sorted(set(errors))


def validate_fixture(directory, profile, depth):
    path=directory/'manifest.json';meta=json.loads(path.read_text())
    if meta['profile']!=profile or meta['depth_including_root']!=depth:raise ValueError('Fixture identity mismatch: '+str(directory))
    for name,value in meta['files_sha256'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe fixture manifest path')
        if digest(directory/relative)!=value:raise ValueError('Fixture hash mismatch: '+str(directory/relative))
    return digest(path)
