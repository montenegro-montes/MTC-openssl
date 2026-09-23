#!/usr/bin/env python3
"""Single MTC-experimental landmark TLS endpoint for chain-depth comparison."""

import json
import os
import signal
import subprocess
from pathlib import Path

OPENSSL = "/opt/mtc/openssl.sh"

mtc_root = Path(os.environ["MTC_ROOT"])
profile = os.environ["CERT_PROFILE"]
mtc_dir = mtc_root / "batch16" / "mtc" / profile
population_dir = mtc_root / "population" / profile
results = Path(os.environ["SERVER_METRICS"])
results.mkdir(parents=True, exist_ok=True)

meta = json.loads((mtc_dir / "manifest.json").read_text())
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
    os.environ.get("MTC_TLS_GROUP", "X25519"),
    "-ciphersuites",
    "TLS_AES_256_GCM_SHA384",
    "-num_tickets",
    "0",
    "-lab_metrics",
]

env = os.environ.copy()
env["PROFILE_METRICS_DIR"] = str(results)

process = subprocess.Popen(args, env=env)


def stop(*_):
    process.terminate()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

raise SystemExit(process.wait())
