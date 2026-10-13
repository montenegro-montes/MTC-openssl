"""MTC signature profiles; historical classic/pq retain their original meaning."""
DRAFT = 'draft-ietf-plants-merkle-tree-certs-07'
TREE_HASH = 'SHA-256'
TREE_SIZES = (1, 4, 16, 64, 256, 1024)

# profile, family, standard name, implementation name, signature OID,
# curve, digest, level, CA, cosigner
_ROWS = (
    ('ecdsa-p256','ECDSA','ECDSA P-256','EC','1.2.840.10045.4.3.2','P-256','sha256',1,101,201),
    ('ecdsa-p384','ECDSA','ECDSA P-384','EC','1.2.840.10045.4.3.3','P-384','sha384',3,102,202),
    ('ecdsa-p521','ECDSA','ECDSA P-521','EC','1.2.840.10045.4.3.4','P-521','sha512',5,103,203),
    ('mldsa44','ML-DSA','ML-DSA-44','mldsa44','2.16.840.1.101.3.4.3.17',None,None,1,111,211),
    ('mldsa65','ML-DSA','ML-DSA-65','mldsa65','2.16.840.1.101.3.4.3.18',None,None,3,112,212),
    ('mldsa87','ML-DSA','ML-DSA-87','mldsa87','2.16.840.1.101.3.4.3.19',None,None,5,113,213),
    ('slhdsa128s','SLH-DSA','SLH-DSA-SHA2-128s','slhdsasha2128s','2.16.840.1.101.3.4.3.20',None,None,1,121,221),
    ('slhdsa192s','SLH-DSA','SLH-DSA-SHA2-192s','slhdsasha2192s','2.16.840.1.101.3.4.3.22',None,None,3,122,222),
    ('slhdsa256s','SLH-DSA','SLH-DSA-SHA2-256s','slhdsasha2256s','2.16.840.1.101.3.4.3.24',None,None,5,123,223),
)
SIGNATURE_PROFILES = {
    name:dict(profile=name,family=family,standard_name=standard,
              implementation_algorithm=implementation,
              signature_algorithm_oid=signature_oid,curve=curve,digest=digest,
              security_level=level,ca_id=f'32473.{ca}',cosigner_ids=(f'32473.{ca}',f'32473.{cosigner}'))
    for name,family,standard,implementation,signature_oid,curve,digest,level,ca,cosigner in _ROWS
}
LEGACY_PROFILE_MAP = {'ecdsa-p256':'classic','mldsa65':'pq'}
LEGACY_PROFILES = {
    'classic':dict(SIGNATURE_PROFILES['ecdsa-p256'],profile='classic',ca_id='32473.1',cosigner_ids=('32473.1','32473.3')),
    'pq':dict(SIGNATURE_PROFILES['mldsa65'],profile='pq',ca_id='32473.2',cosigner_ids=('32473.2','32473.4')),
}


def crypto_profile(name):
    if name in LEGACY_PROFILES:return LEGACY_PROFILES[name]
    if name in SIGNATURE_PROFILES:return SIGNATURE_PROFILES[name]
    raise ValueError('Unknown MTC crypto profile: '+name)
