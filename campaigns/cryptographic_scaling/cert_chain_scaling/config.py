"""Frozen design for the ideal-network certificate scaling experiment."""
PROFILES = {
    "ecdsa-p256": {
        "level": 1,
        "family": "ECDSA",
        "algorithm": "EC",
        "curve": "P-256",
        "digest": "sha256",
        "standard_name": "ECDSA P-256",
    },
    "ecdsa-p384": {
        "level": 3,
        "family": "ECDSA",
        "algorithm": "EC",
        "curve": "P-384",
        "digest": "sha384",
        "standard_name": "ECDSA P-384",
    },
    "ecdsa-p521": {
        "level": 5,
        "family": "ECDSA",
        "algorithm": "EC",
        "curve": "P-521",
        "digest": "sha512",
        "standard_name": "ECDSA P-521",
    },

    "mldsa44": {
        "level": 1,
        "family": "ML-DSA",
        "algorithm": "mldsa44",
        "standard_name": "ML-DSA-44",
    },
    "mldsa65": {
        "level": 3,
        "family": "ML-DSA",
        "algorithm": "mldsa65",
        "standard_name": "ML-DSA-65",
    },
    "mldsa87": {
        "level": 5,
        "family": "ML-DSA",
        "algorithm": "mldsa87",
        "standard_name": "ML-DSA-87",
    },

    "slhdsa128s": {
        "level": 1,
        "family": "SLH-DSA",
        "algorithm": "slhdsasha2128s",
        "standard_name": "SLH-DSA-SHA2-128s",
    },
    "slhdsa192s": {
        "level": 3,
        "family": "SLH-DSA",
        "algorithm": "slhdsasha2192s",
        "standard_name": "SLH-DSA-SHA2-192s",
    },
    "slhdsa256s": {
        "level": 5,
        "family": "SLH-DSA",
        "algorithm": "slhdsasha2256s",
        "standard_name": "SLH-DSA-SHA2-256s",
    },
}
DEPTHS = (2, 3, 4, 5)
TREE_SIZES = (1, 4, 16, 64, 256, 1024)
TLS = {"version": "TLSv1.3", "group": "X25519", "cipher": "TLS_AES_256_GCM_SHA384",
       "tickets": False, "resumption": False, "zero_rtt": False, "client_authentication": False}
IMAGE = "mt-tls-measurement:local"
MTC_PROFILE_MAP = {"ecdsa-p256": "classic", "mldsa65": "pq"}
