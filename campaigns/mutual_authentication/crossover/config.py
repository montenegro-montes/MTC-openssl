#!/usr/bin/env python3

from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

EXPERIMENT = "mutual-auth-crossover-v2"

SERVER_ONLY_FIXTURES = (
    REPO
    / "artifacts"
    / "validation"
    / "chain-depth-server-only-fixtures-full-20260918T101613Z"
)

ARTIFACT_ROOT = (
    REPO
    / "artifacts"
    / "validation"
    / "mutual-auth-crossover-v2"
)

PROFILES = {
    "ecdsa-p256": {
        "curve": "prime256v1",
        "pkey_curve": "P-256",
        "digest": "sha256",
        "mtc_id": "32473.101.1.1.1",
    },
    "ecdsa-p384": {
        "curve": "secp384r1",
        "pkey_curve": "P-384",
        "digest": "sha384",
        "mtc_id": "32473.102.1.1.1",
    },
    "ecdsa-p521": {
        "curve": "secp521r1",
        "pkey_curve": "P-521",
        "digest": "sha512",
        "mtc_id": "32473.103.1.1.1",
    },
}

CHAIN_PROFILES = (
    "direct-server",
    "ca-server",
)

CROSSOVER_MATRIX = {
    ("ecdsa-p256", "direct-server"): (1, 4, 8, 16),
    ("ecdsa-p256", "ca-server"):     (4, 8, 16, 32),

    ("ecdsa-p384", "direct-server"): (1, 4, 8, 16, 32),
    ("ecdsa-p384", "ca-server"):     (8, 16, 32, 64),

    ("ecdsa-p521", "direct-server"): (4, 16, 32, 64),
    ("ecdsa-p521", "ca-server"):     (16, 32, 64, 128),
}

SERVER_ONLY_RAW_CROSSOVER = {
    ("ecdsa-p256", "direct-server"): (4, 8),
    ("ecdsa-p256", "ca-server"):     (8, 16),
    ("ecdsa-p384", "direct-server"): (8, 16),
    ("ecdsa-p384", "ca-server"):     (16, 32),
    ("ecdsa-p521", "direct-server"): (16, 32),
    ("ecdsa-p521", "ca-server"):     (64, 128),
}

# MTC is held fixed across X.509 chain-depth comparisons.
# direct-server and ca-server describe only the X.509 baselines.
MTC_SOURCE_CHAIN_PROFILE = "ca-server"

MTC_N_VALUES = {
    "ecdsa-p256": (1, 4, 8, 16, 32),
    "ecdsa-p384": (1, 4, 8, 16, 32, 64),
    "ecdsa-p521": (4, 8, 16, 32, 64, 128),
}
