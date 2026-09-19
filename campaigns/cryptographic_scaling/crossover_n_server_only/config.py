"""Configuration for server-only MTC crossover-by-N experiments."""

PROFILES = [
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "slhdsa128s",
    "slhdsa192s",
    "slhdsa256s",
]

BASE_TREE_SIZES = [1, 4, 16, 64, 256, 1024]

TREE_SIZES_BY_PROFILE = {
    "ecdsa-p256": [1, 4, 8, 16, 64, 256, 1024],
    "ecdsa-p384": [1, 4, 8, 16, 32, 64, 256, 1024],
    "ecdsa-p521": [1, 4, 16, 32, 64, 128, 256, 1024],
    "mldsa44": BASE_TREE_SIZES,
    "mldsa65": BASE_TREE_SIZES,
    "mldsa87": BASE_TREE_SIZES,
    "slhdsa128s": BASE_TREE_SIZES,
    "slhdsa192s": BASE_TREE_SIZES,
    "slhdsa256s": BASE_TREE_SIZES,
}

TREE_SIZES = sorted({
    n
    for sizes in TREE_SIZES_BY_PROFILE.values()
    for n in sizes
})

X509_CHAIN_PROFILES = [
    "direct-server",
    "ca-server",
    "root-intermediate-server",
]

MTC_CHAIN_PROFILE = "mtc-landmark"

TLS = {
    "version": "TLSv1.3",
    "group": "X25519",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "tickets": False,
    "resumption": False,
    "zero_rtt": False,
    "client_authentication": False,
}
