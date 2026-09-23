#!/usr/bin/env python3
"""Single server-only TLS endpoint for one chain-depth fixture."""

import os
import signal
import subprocess
from pathlib import Path

OPENSSL = "/opt/measurement/openssl.sh"

fixture = Path(os.environ["CERT_FIXTURE"])
results = Path(os.environ["SERVER_METRICS"])
results.mkdir(parents=True, exist_ok=True)

args = [
    OPENSSL,
    "s_server",
    "-accept",
    "4433",
    "-cert",
    str(fixture / "server.pem"),
    "-key",
    str(fixture / "server.key"),
]

intermediates = fixture / "intermediates.pem"
if intermediates.exists() and intermediates.stat().st_size:
    args += ["-cert_chain", str(intermediates)]

args += [
    "-www",
    "-tls1_3",
    "-groups",
    os.environ.get("MTC_TLS_GROUP", "X25519"),
    "-ciphersuites",
    "TLS_AES_256_GCM_SHA384",
    "-no_ticket",
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
