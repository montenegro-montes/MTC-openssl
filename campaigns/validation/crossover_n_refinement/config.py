MTC_CHAIN_PROFILE = 'mtc-landmark'

TLS = {'version': 'TLSv1.3', 'group': 'X25519', 'cipher': 'TLS_AES_256_GCM_SHA384', 'tickets': False, 'resumption': False, 'zero_rtt': False, 'client_authentication': False}

PROFILES = [
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
]

TREE_SIZES_BY_PROFILE = {
    "ecdsa-p256": [8],
    "ecdsa-p384": [8, 32],
    "ecdsa-p521": [32, 128],
}

TREE_SIZES = sorted({
    n
    for values in TREE_SIZES_BY_PROFILE.values()
    for n in values
})
