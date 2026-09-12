"""Paper-1 signer profiles; historical classic/pq retain their original meaning."""
DRAFT = 'draft-ietf-plants-merkle-tree-certs-05'
TREE_HASH = 'SHA-256'
TREE_SIZES = (1, 4, 16, 64, 256, 1024)

# profile, family, standard name, implementation name, curve, digest, level, CA, cosigner
_ROWS = (
    ('ecdsa-p256','ECDSA','ECDSA P-256','EC','P-256','sha256',1,101,201),
    ('ecdsa-p384','ECDSA','ECDSA P-384','EC','P-384','sha384',3,102,202),
    ('ecdsa-p521','ECDSA','ECDSA P-521','EC','P-521','sha512',5,103,203),
    ('mldsa44','ML-DSA','ML-DSA-44','mldsa44',None,None,1,111,211),
    ('mldsa65','ML-DSA','ML-DSA-65','mldsa65',None,None,3,112,212),
    ('mldsa87','ML-DSA','ML-DSA-87','mldsa87',None,None,5,113,213),
    ('slhdsa128s','SLH-DSA','SLH-DSA-SHA2-128s','slhdsasha2128s',None,None,1,121,221),
    ('slhdsa192s','SLH-DSA','SLH-DSA-SHA2-192s','slhdsasha2192s',None,None,3,122,222),
    ('slhdsa256s','SLH-DSA','SLH-DSA-SHA2-256s','slhdsasha2256s',None,None,5,123,223),
)
PAPER1_PROFILES = {
    name:dict(profile=name,family=family,standard_name=standard,
              implementation_algorithm=implementation,curve=curve,digest=digest,
              security_level=level,ca_id=f'32473.{ca}',cosigner_ids=(f'32473.{ca}',f'32473.{cosigner}'))
    for name,family,standard,implementation,curve,digest,level,ca,cosigner in _ROWS
}
LEGACY_PROFILE_MAP = {'ecdsa-p256':'classic','mldsa65':'pq'}
LEGACY_PROFILES = {
    'classic':dict(PAPER1_PROFILES['ecdsa-p256'],profile='classic',ca_id='32473.1',cosigner_ids=('32473.1','32473.3')),
    'pq':dict(PAPER1_PROFILES['mldsa65'],profile='pq',ca_id='32473.2',cosigner_ids=('32473.2','32473.4')),
}


def crypto_profile(name):
    if name in LEGACY_PROFILES:return LEGACY_PROFILES[name]
    if name in PAPER1_PROFILES:return PAPER1_PROFILES[name]
    raise ValueError('Unknown MTC crypto profile: '+name)
