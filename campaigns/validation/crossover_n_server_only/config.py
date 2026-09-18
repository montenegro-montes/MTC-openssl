"""Configuration for server-only MTC crossover-by-N experiments."""

PROFILES = [
    "ecdsa-p256",
    "ecdsa-p384",
    "mldsa65",
    "slhdsa128s",
]

TREE_SIZES = [1, 4, 16, 64, 256, 1024]

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
