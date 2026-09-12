"""Exact capability matching; standardized SLH-DSA is never mapped to SPHINCS+."""
import csv
import re
from config import PROFILES

STANDARD = {'mldsa44':'ML-DSA-44','mldsa65':'ML-DSA-65','mldsa87':'ML-DSA-87',
            'slhdsa128s':'SLH-DSA-SHA2-128s','slhdsa192s':'SLH-DSA-SHA2-192s',
            'slhdsa256s':'SLH-DSA-SHA2-256s'}
ECDSA_TLS = {'P-256':'ecdsa_secp256r1_sha256', 'P-384':'ecdsa_secp384r1_sha384',
             'P-521':'ecdsa_secp521r1_sha512'}


def tokens(text):
    return {re.sub(r'[-_]', '', x).lower() for x in re.findall(r'[A-Za-z][A-Za-z0-9_-]*', text)}


def support_table(signature, tls, key_algorithms='', profiles=None):
    profiles = profiles or PROFILES
    signatures, schemes, keys = map(tokens, (signature, tls, key_algorithms))
    result = []
    for name, p in profiles.items():
        algorithm = STANDARD.get(name, p.get('standard_name',p['algorithm']))
        aliases = tokens(p['algorithm']) | tokens(algorithm)
        if p['family'] == 'ECDSA':
            sig = 'ecdsa' in signatures
            tls_ok = next(iter(tokens(ECDSA_TLS[p['curve']]))) in schemes
            key_ok = bool({'ec','id-ecpublickey','idecpublickey'} & keys)
        else:
            sig, tls_ok, key_ok = bool(aliases & signatures), bool(aliases & schemes), bool(aliases & keys)
        result.append({'profile':name,'family':p['family'],'algorithm':algorithm,
                       'implementation_algorithm':p['algorithm'],'security_level':p['level'],
                       'signature_supported':sig,'keygen_supported':key_ok if key_algorithms else None,
                       'x509_sign_supported':None,'x509_verify_supported':None,
                       'tls_signature_supported':tls_ok,'static_experiment_enabled':sig,
                       'tls_experiment_enabled':sig and tls_ok,
                       'reason':('TLS scheme advertised by tested image' if tls_ok else
                                 'SKIPPED_UNSUPPORTED_TLS: no matching TLS signature scheme advertised'),
                       'x509_evidence':'not tested by capability listing; use fixture validation'})
    return result


def write_support(path, rows):
    with path.open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)


def load_support(environment):
    if 'tls_signature_algorithms' not in environment or 'signature_algorithms' not in environment:
        raise ValueError('Environment lacks separate cryptographic/TLS capability evidence; inspect image again')
    return support_table(environment['signature_algorithms'], environment['tls_signature_algorithms'],
                         environment.get('key_algorithms',''), environment.get('configured_profiles'))


def fixture_evidence(rows, fixtures, openssl=None, image_id=None):
    """Only generated, hash-valid manifests establish X.509 support evidence."""
    import json
    from result_state import validate_fixture
    result=[dict(r) for r in rows]
    for row in result:
        manifests=sorted(fixtures.glob(row['profile']+'/depth-*/manifest.json'))
        validated=[]
        for path in manifests:
            meta=json.loads(path.read_text())
            if openssl is None or meta.get('openssl')!=openssl or not image_id or meta.get('image_id')!=image_id:continue
            validate_fixture(path.parent,row['profile'],meta['depth_including_root'])
            if not meta.get('certificate_checks') or not all(v.get('key_matches_certificate') for v in meta['certificate_checks'].values()):
                continue
            wanted=tokens(row['algorithm']) | tokens(row['implementation_algorithm'])
            if row['family']=='ECDSA':wanted={x for v in meta['certificate_checks'].values() for x in tokens(' '.join(v.get('signature_algorithms',[]))) if x.startswith('ecdsa')}
            observed=[tokens(' '.join(v.get('signature_algorithms',[]))) for v in meta['certificate_checks'].values()]
            if not wanted or not all(wanted & v for v in observed):continue
            validated.append(str(path))
        if validated:
            row.update(keygen_supported=True,x509_sign_supported=True,x509_verify_supported=True,
                       x509_evidence='Hash-valid fixture_builder manifests written after standalone verify: '+'; '.join(validated))
    return result
