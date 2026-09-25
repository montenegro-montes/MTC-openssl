"""Server-only chain-depth sensitivity configuration.

This block is separate from mutual-auth and retry validation.
It studies X.509 vs MTC-experimental sensitivity to server certificate
chain depth under fixed TLS settings.
"""

from pathlib import Path
import os,sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src/mtc"))

from crypto_profiles import PAPER1_PROFILES, LEGACY_PROFILE_MAP

PROFILES = {
    name: dict(
        level=p["security_level"],
        family=p["family"],
        algorithm=p["implementation_algorithm"],
        standard_name=p["standard_name"],
        **({"curve": p["curve"], "digest": p["digest"]} if p["curve"] else {}),
    )
    for name, p in PAPER1_PROFILES.items()
}

CHAIN_PROFILES = {
    "direct-server": {
        "auth_family": "x509",
        "depth_including_root": 1,
        "chain_depth": 1,
        "transmitted_certificates": 1,
        "tree_size": "",
        "mtc_mode": "",
        "description": "server certificate used directly as trust anchor; no intermediates",
    },
    "ca-server": {
        "auth_family": "x509",
        "depth_including_root": 2,
        "chain_depth": 1,
        "transmitted_certificates": 1,
        "tree_size": "",
        "mtc_mode": "",
        "description": "CA -> server; root/CA trusted locally and not transmitted",
    },
    "root-intermediate-server": {
        "auth_family": "x509",
        "depth_including_root": 3,
        "chain_depth": 2,
        "transmitted_certificates": 2,
        "tree_size": "",
        "mtc_mode": "",
        "description": "root -> intermediate -> server; server transmits server + intermediate",
    },
    "mtc-landmark": {
        "auth_family": "mtc-experimental",
        "depth_including_root": "",
        "chain_depth": 1,
        "transmitted_certificates": 1,
        "tree_size": 16,
        "mtc_mode": "landmark",
        "description": "MTC experimental landmark certificate with pre-distributed trust.bin",
    },
}


X509_CHAIN_PROFILES = {
    name: data for name, data in CHAIN_PROFILES.items()
    if data["auth_family"] == "x509"
}

MTC_CHAIN_PROFILES = {
    name: data for name, data in CHAIN_PROFILES.items()
    if data["auth_family"] == "mtc-experimental"
}


TLS = {
    "version": "TLSv1.3",
    "group": os.environ.get("MTC_TLS_GROUP", "X25519"),
    "cipher": "TLS_AES_256_GCM_SHA384",
    "tickets": False,
    "resumption": False,
    "zero_rtt": False,
    "client_authentication": False,
}

TREE_SIZE = 16
IMAGE = os.environ.get("MTC_PROFILE_IMAGE", "mt-tls-mtc-profile:local")
MTC_PROFILE_MAP = {name: name for name in PAPER1_PROFILES}
LEGACY_MTC_PROFILE_MAP = dict(LEGACY_PROFILE_MAP)
