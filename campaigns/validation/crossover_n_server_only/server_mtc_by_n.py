#!/usr/bin/env python3
"""Single MTC-experimental landmark TLS endpoint for crossover-by-N."""

from __future__ import annotations

import json
import os
import signal
import subprocess
from pathlib import Path

OPENSSL = "/opt/mtc/openssl.sh"

mtc_root = Path(os.environ["MTC_ROOT"])
profile = os.environ["CERT_PROFILE"]
tree_size = int(os.environ["MTC_TREE_SIZE"])
mtc_dir = mtc_root / f"batch{tree_size}" / "mtc" / profile
population_dir = mtc_root / "population" / profile
results = Path(os.environ["SERVER_METRICS"])
results.mkdir(parents=True, exist_ok=True)

meta = json.loads((mtc_dir / "manifest.json").read_text())
if meta.get("profile") != profile:
    raise SystemExit(f"profile mismatch in {mtc_dir / 'manifest.json'}")
if int(meta.get("tree_size")) != tree_size:
    raise SystemExit(f"tree_size mismatch in {mtc_dir / 'manifest.json'}")
if "landmark" not in meta.get("mtc_modes", []):
    raise SystemExit(f"landmark mode missing in {mtc_dir / 'manifest.json'}")

mtc_id = meta["ca_id"] + ".1.1.1"

args = [
    OPENSSL,
    "s_server",
    "-accept",
    "4433",
    "-cert",
    str(mtc_dir / "landmark-0000.pem"),
    "-key",
    str(population_dir / "0.key"),
    "-mtc_id",
    mtc_id,
    "-www",
    "-tls1_3",
    "-groups",
    "X25519",
    "-ciphersuites",
    "TLS_AES_256_GCM_SHA384",
    "-num_tickets",
    "0",
    "-lab_metrics",
]

env = os.environ.copy()
env["PROFILE_METRICS_DIR"] = str(results)

process = subprocess.Popen(args, env=env)


def stop(*_) -> None:
    process.terminate()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

raise SystemExit(process.wait())
