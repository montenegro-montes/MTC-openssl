#!/usr/bin/env python3
"""Native/PCAP validation pq-only TLS server for Native <-> PCAP instrumentation validation."""

from __future__ import annotations

import datetime as dt
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path


PORT = 4434
OPENSSL = "/opt/measurement/openssl.sh"
FIXTURE = Path(
    "/work/cert-chain-scaling/fixtures-20260914T113933Z/"
    "mldsa65/depth-2"
)


def main() -> None:
    run_root = Path(os.environ["MEASUREMENT_RUN_ROOT"])
    campaign_id = os.environ["MEASUREMENT_CAMPAIGN_ID"]
    campaign = run_root / campaign_id
    campaign.mkdir(parents=True, exist_ok=True)

    required = [
        FIXTURE / "root.pem",
        FIXTURE / "server.pem",
        FIXTURE / "server.key",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(
            "Missing Native/PCAP validation ML-DSA-65 fixture files: " + ", ".join(missing)
        )

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = campaign / f"server-{stamp}"
    directory.mkdir()
    log_path = directory / "pq.log"

    metadata = {
        "experiment": "native-pcap-validation",
        "scenario": "pq",
        "port": PORT,
        "fixture": str(FIXTURE),
        "tls": "1.3",
        "group": "X25519",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "server_authentication_only": True,
        "tickets": False,
    }
    (directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n"
    )

    args = [
        OPENSSL,
        "s_server",
        "-accept", str(PORT),
        "-tls1_3",
        "-groups", "X25519",
        "-ciphersuites", "TLS_AES_256_GCM_SHA384",
        "-cert", str(FIXTURE / "server.pem"),
        "-key", str(FIXTURE / "server.key"),
        "-num_tickets", "0",
        "-www",
        "-quiet",
        "-lab_metrics",
    ]

    env = os.environ.copy()
    env["PROFILE_METRICS_DIR"] = str(directory)

    stream = log_path.open("w")
    process = subprocess.Popen(args, stdout=stream, stderr=stream, env=env)

    def stop(*_args: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Native/PCAP validation pq server failed during startup")
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.025)
        else:
            raise RuntimeError("Native/PCAP validation pq server readiness timeout")

        Path("/tmp/measurement-ready").write_text(str(directory))
        print(directory, flush=True)

        while True:
            if process.poll() is not None:
                raise RuntimeError("Native/PCAP validation pq server exited")
            time.sleep(0.5)
    finally:
        Path("/tmp/measurement-ready").unlink(missing_ok=True)
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        stream.close()


if __name__ == "__main__":
    main()
