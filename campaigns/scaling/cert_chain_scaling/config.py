"""Frozen Paper-1 design, sharing the explicit signature-profile registry."""
from pathlib import Path
import os,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'src/mtc'))
from crypto_profiles import PAPER1_PROFILES, LEGACY_PROFILE_MAP

PROFILES = {
    name:dict(level=p['security_level'],family=p['family'],algorithm=p['implementation_algorithm'],
              standard_name=p['standard_name'],**({'curve':p['curve'],'digest':p['digest']} if p['curve'] else {}))
    for name,p in PAPER1_PROFILES.items()
}
DEPTHS = (2, 3, 4, 5)
TREE_SIZES = (1, 4, 16, 64, 256)
TLS = {"version": "TLSv1.3", "group": os.environ.get("MTC_TLS_GROUP", "X25519"), "cipher": "TLS_AES_256_GCM_SHA384",
       "tickets": False, "resumption": False, "zero_rtt": False, "client_authentication": False}
IMAGE = os.environ.get("MTC_PROFILE_IMAGE", "mt-tls-mtc-profile:local")
MTC_PROFILE_MAP = {name:name for name in PAPER1_PROFILES}
LEGACY_MTC_PROFILE_MAP = dict(LEGACY_PROFILE_MAP)
