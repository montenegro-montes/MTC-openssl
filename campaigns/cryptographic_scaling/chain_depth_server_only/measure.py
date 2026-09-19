#!/usr/bin/env python3
"""Measure one server-only TLS chain-depth profile."""

import argparse
import csv
import json
import os
import re
import subprocess
import time
from pathlib import Path

from config import CHAIN_PROFILES, PROFILES

OPENSSL = "/opt/measurement/openssl.sh"


def profile_metadata(profile):
    config = PROFILES[profile]
    return {
        "profile": profile,
        "family": config["family"],
        "algorithm": config.get("standard_name", config["algorithm"]),
        "implementation_algorithm": config["algorithm"],
        "security_level": config["level"],
        "TLS_signature_supported": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, required=True)
    parser.add_argument("--warmups", type=int, required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()

    if args.runs < 1 or args.warmups < 0:
        parser.error("runs >= 1 and warmups >= 0")

    fixture = Path(os.environ["CERT_FIXTURE"])
    out = Path(os.environ["CAMPAIGN_OUTPUT"])
    metrics = Path(os.environ["SERVER_METRICS"])
    profile_name = os.environ["CERT_PROFILE_NAME"]
    chain_profile = os.environ["CHAIN_PROFILE"]
    chain = CHAIN_PROFILES[chain_profile]

    out.mkdir(parents=True, exist_ok=False)
    (out / "logs").mkdir()
    (out / "server-metrics").mkdir()

    rows = []
    warmups = []

    for is_warmup, count in [(1, args.warmups), (0, args.runs)]:
        for round_id in range(1, count + 1):
            start = time.perf_counter_ns()
            result = subprocess.run(
                [
                    OPENSSL,
                    "s_client",
                    "-connect",
                    "server:4433",
                    "-servername",
                    "server",
                    "-CAfile",
                    str(fixture / "root.pem"),
                    "-verify_hostname",
                    "server",
                    "-verify_return_error",
                    "-tls1_3",
                    "-groups",
                    "X25519",
                    "-ciphersuites",
                    "TLS_AES_256_GCM_SHA384",
                    "-no_ticket",
                    "-ign_eof",
                    "-lab_metrics",
                ],
                input="GET / HTTP/1.0\r\n\r\n",
                text=True,
                capture_output=True,
                timeout=60,
            )
            process_ms = (time.perf_counter_ns() - start) / 1e6
            log = result.stdout + result.stderr
            log_name = f'{"warmup" if is_warmup else "sample"}-{round_id:04d}.log'
            (out / "logs" / log_name).write_text(log)

            found = re.findall(r"^PROFILE_METRICS (\{.*\})$", result.stderr, re.M)
            if result.returncode or len(found) != 1 or "Verify return code: 0 (ok)" not in log:
                raise RuntimeError("TLS authentication failed")
            if "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" not in log:
                raise RuntimeError("controlled TLS cipher mismatch")
            if "Shared groups: x25519" not in log:
                raise RuntimeError("controlled TLS group mismatch")

            client = json.loads(found[0])
            client_random = client["client_random"]
            server_metric_paths = list(metrics.glob(client_random + ".json"))
            if len(server_metric_paths) != 1:
                raise RuntimeError("missing server metrics")

            server = json.loads(server_metric_paths[0].read_text())
            (out / "server-metrics" / (client_random + ".json")).write_text(
                server_metric_paths[0].read_text()
            )

            if client["reused"] or server["reused"]:
                raise RuntimeError("session reuse detected")
            if client["certificate_message_bytes"] != server["certificate_message_bytes"]:
                raise RuntimeError("client/server Certificate-message mismatch")

            row = {
                "campaign": args.campaign,
                "scenario": args.scenario,
                **profile_metadata(profile_name),
                "auth_family": "x509",
                "chain_profile": chain_profile,
                "depth_including_root": chain["depth_including_root"],
                "chain_depth": chain["chain_depth"],
                "transmitted_certificates": chain["transmitted_certificates"],
                "tree_size": "",
                "mtc_profile": "",
                "round": round_id,
                "repetition": round_id,
                "is_warmup": is_warmup,
                "seed": args.seed,
                "fixture_hash": os.environ["FIXTURE_SHA256"],
                "image_id": os.environ["IMAGE_ID"],
                "git_commit": os.environ["SOURCE_COMMIT"],
                "client_random": client_random,
                "handshake_wall_ms": client["handshake_wall_ms"],
                "client_cpu_ms": client["handshake_cpu_ms"],
                "server_cpu_ms": server["handshake_cpu_ms"],
                "authentication_processing_wall_ms": client["components"]["peer_auth"]["wall_ms"],
                "authentication_processing_cpu_ms": client["components"]["peer_auth"]["cpu_ms"],
                "certificate_message_bytes": client["certificate_message_bytes"],
                "certificate_verify_message_bytes": client["certificate_verify_message_bytes"],
                "tls_bio_read_bytes": client["transport_read_bytes"],
                "tls_bio_written_bytes": client["transport_written_bytes"],
                "process_http_wall_ms": process_ms,
                "success": 1,
            }

            (warmups if is_warmup else rows).append(row)

    for filename, data in [("observations.csv", rows), ("warmups.csv", warmups)]:
        with (out / filename).open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list((data or rows)[0]))
            writer.writeheader()
            writer.writerows(data)

    (out / "validation.json").write_text(
        json.dumps(
            {
                "passed": True,
                "measured_handshakes": len(rows),
                "warmup_handshakes": len(warmups),
                "checks": [
                    "TLS 1.3",
                    "TLS_AES_256_GCM_SHA384",
                    "X25519",
                    "certificate verification",
                    "no resumed sessions",
                    "client/server Certificate-message agreement",
                    "server-only authentication",
                ],
            },
            indent=2,
        )
        + "\n"
    )

    print(out)


if __name__ == "__main__":
    main()
