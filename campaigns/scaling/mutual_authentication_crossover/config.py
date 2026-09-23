#!/usr/bin/env python3
"""Nine-profile mutual-authentication crossover configuration."""
import os
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src/mtc"))
from crypto_profiles import PAPER1_PROFILES, TREE_SIZES

EXPERIMENT = "mutual-auth-crossover"
SERVER_ONLY_FIXTURES = Path(os.environ.get(
    "MUTUAL_CROSSOVER_SERVER_FIXTURES",
    REPO / "artifacts/scaling/mutual-auth-crossover/server-x509",
))
ARTIFACT_ROOT = Path(os.environ.get(
    "MUTUAL_CROSSOVER_FIXTURES",
    REPO / "artifacts/scaling/mutual-auth-crossover/fixtures",
))
SOURCE_ROOT = Path(os.environ.get(
    "MUTUAL_CROSSOVER_SOURCE_ROOT",
    ARTIFACT_ROOT,
))

PROFILES = {
    name: {
        "family": profile["family"],
        "algorithm": profile["implementation_algorithm"],
        "pkey_curve": profile["curve"],
        "digest": profile["digest"],
        "mtc_id": f'{profile["ca_id"]}.1.1.1',
    }
    for name, profile in PAPER1_PROFILES.items()
}
CHAIN_PROFILES = ("direct-server", "ca-server")
MTC_SOURCE_CHAIN_PROFILE = "ca-server"
MTC_N_VALUES = {name: TREE_SIZES for name in PROFILES}
