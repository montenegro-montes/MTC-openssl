#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

IMAGE = "mt-tls-mtc-mutual:local"
OPENSSL = "/opt/openssl-mtc/bin/openssl"

NETWORK = "mt-mutual-metrics-probe"
SERVER_NAME = "mt-mutual-metrics-probe-server"

LD_LIBRARY_PATH = "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib"

SERVER_FIXTURE = (
    REPO
    / "artifacts/validation/"
      "chain-depth-server-only-fixtures-full-20260918T101613Z/"
      "ecdsa-p256/direct-server"
)

CLIENT_FIXTURE = (
    REPO
    / "artifacts/validation/"
      "mutual-auth-crossover-v2/"
      "client-x509/ecdsa-p256/direct-server"
)


def run(cmd, *, check=True, input_text=None):
    r = subprocess.run(
        cmd,
        cwd=REPO,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if check and r.returncode != 0:
        raise SystemExit(
            "COMMAND FAILED\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + (r.stdout or "")
            + "\nSTDERR:\n"
            + (r.stderr or "")
        )

    return r


def parse_profile_metrics(text):
    matches = re.findall(
        r"^PROFILE_METRICS (\{.*\})$",
        text,
        re.MULTILINE,
    )

    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one PROFILE_METRICS record, got {len(matches)}"
        )

    return json.loads(matches[0])


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    args = p.parse_args()

    root = args.root
    if not root.is_absolute():
        root = REPO / root

    results_root = REPO / "artifacts/results"

    if not root.is_relative_to(results_root):
        raise SystemExit("root must be under artifacts/results")

    if root.exists() and any(root.iterdir()):
        raise SystemExit(
            f"refusing to overwrite non-empty root: {root}"
        )

    root.mkdir(parents=True, exist_ok=True)

    server_metrics_dir = root / "server-metrics"
    server_metrics_dir.mkdir()

    for path in [
        SERVER_FIXTURE / "server.pem",
        SERVER_FIXTURE / "server.key",
        CLIENT_FIXTURE / "client-0000.pem",
        CLIENT_FIXTURE / "client-0000.key",
    ]:
        if not path.is_file():
            raise SystemExit(f"missing fixture: {path}")

    run(
        ["docker", "rm", "-f", SERVER_NAME],
        check=False,
    )
    run(
        ["docker", "network", "rm", NETWORK],
        check=False,
    )
    run(
        ["docker", "network", "create", NETWORK]
    )

    server_cmd = [
        "docker", "run", "-d",
        "--name", SERVER_NAME,
        "--network", NETWORK,

        "-e", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}",
        "-e", "PROFILE_METRICS_DIR=/metrics",

        "-v",
        f"{SERVER_FIXTURE.resolve()}:/server:ro",

        "-v",
        f"{CLIENT_FIXTURE.resolve()}:/client:ro",

        "-v",
        f"{server_metrics_dir.resolve()}:/metrics",

        "--entrypoint", OPENSSL,
        IMAGE,

        "s_server",
        "-accept", "4433",

        "-cert", "/server/server.pem",
        "-key", "/server/server.key",

        "-CAfile", "/client/client-0000.pem",
        "-Verify", "1",
        "-verify_return_error",

        "-tls1_3",
        "-groups", "X25519",
        "-ciphersuites", "TLS_AES_256_GCM_SHA384",

        "-num_tickets", "0",
        "-www",
        "-state",
        "-lab_metrics",
    ]

    client_cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK,

        "-e", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}",

        "-v",
        f"{SERVER_FIXTURE.resolve()}:/server:ro",

        "-v",
        f"{CLIENT_FIXTURE.resolve()}:/client:ro",

        "--entrypoint", OPENSSL,
        IMAGE,

        "s_client",
        "-connect", f"{SERVER_NAME}:4433",
        "-servername", "server",

        "-CAfile", "/server/server.pem",

        "-cert", "/client/client-0000.pem",
        "-key", "/client/client-0000.key",

        "-tls1_3",
        "-groups", "X25519",
        "-ciphersuites", "TLS_AES_256_GCM_SHA384",

        "-no_ticket",
        "-verify_return_error",
        "-state",
        "-lab_metrics",
    ]

    try:
        server = run(server_cmd)

        if not server.stdout.strip():
            raise RuntimeError("server container did not start")

        time.sleep(1)

        client = run(
            client_cmd,
            check=False,
            input_text="",
        )

        client_log = (
            (client.stdout or "")
            + (client.stderr or "")
        )

        (root / "client.log").write_text(
            client_log,
            encoding="utf-8",
        )

        server_logs = run(
            ["docker", "logs", SERVER_NAME],
            check=False,
        )

        server_log = (
            (server_logs.stdout or "")
            + (server_logs.stderr or "")
        )

        (root / "server.log").write_text(
            server_log,
            encoding="utf-8",
        )

        require(
            client.returncode == 0,
            f"s_client failed rc={client.returncode}",
        )

        require(
            "Verification: OK" in client_log,
            "client verification failed",
        )

        require(
            "Verify return code: 0 (ok)" in client_log,
            "client verify return code is not zero",
        )

        require(
            "SSL_accept:SSLv3/TLS read client certificate"
            in server_log,
            "server did not receive client Certificate",
        )

        require(
            "SSL_accept:SSLv3/TLS read certificate verify"
            in server_log,
            "server did not receive client CertificateVerify",
        )

        client_metrics = parse_profile_metrics(
            client.stderr
        )

        client_random = client_metrics["client_random"]

        server_metric_path = (
            server_metrics_dir
            / f"{client_random}.json"
        )

        for _ in range(30):
            if server_metric_path.is_file():
                break
            time.sleep(0.1)

        require(
            server_metric_path.is_file(),
            "matching server metrics file not found",
        )

        server_metrics = json.loads(
            server_metric_path.read_text()
        )

        # -----------------------------------------------------
        # Directional Certificate invariants.
        # -----------------------------------------------------

        fields = [
            "server_certificate_message_bytes",
            "client_certificate_message_bytes",
            "server_certificate_verify_message_bytes",
            "client_certificate_verify_message_bytes",
        ]

        for field in fields:
            require(
                field in client_metrics,
                f"client missing {field}",
            )

            require(
                field in server_metrics,
                f"server missing {field}",
            )

            require(
                client_metrics[field]
                == server_metrics[field],
                (
                    f"endpoint mismatch for {field}: "
                    f"{client_metrics[field]} != "
                    f"{server_metrics[field]}"
                ),
            )

        # Both mutual-auth directions must exist.
        require(
            client_metrics[
                "server_certificate_message_bytes"
            ] > 0,
            "missing server Certificate bytes",
        )

        require(
            client_metrics[
                "client_certificate_message_bytes"
            ] > 0,
            "missing client Certificate bytes",
        )

        require(
            client_metrics[
                "server_certificate_verify_message_bytes"
            ] > 0,
            "missing server CertificateVerify bytes",
        )

        require(
            client_metrics[
                "client_certificate_verify_message_bytes"
            ] > 0,
            "missing client CertificateVerify bytes",
        )

        # -----------------------------------------------------
        # Backward compatibility invariants.
        # -----------------------------------------------------

        for endpoint_name, metrics in [
            ("client", client_metrics),
            ("server", server_metrics),
        ]:
            require(
                metrics["certificate_message_bytes"]
                == metrics[
                    "server_certificate_message_bytes"
                ],
                (
                    f"{endpoint_name}: legacy Certificate "
                    "counter changed semantics"
                ),
            )

            require(
                metrics[
                    "certificate_verify_message_bytes"
                ]
                == metrics[
                    "server_certificate_verify_message_bytes"
                ],
                (
                    f"{endpoint_name}: legacy "
                    "CertificateVerify counter "
                    "changed semantics"
                ),
            )

        server_cert = client_metrics[
            "server_certificate_message_bytes"
        ]

        client_cert = client_metrics[
            "client_certificate_message_bytes"
        ]

        cert_total = server_cert + client_cert

        # Endpoint-local total handshake-message bytes.
        # Each endpoint observes the whole TLS handshake:
        # read + written.
        client_handshake_total = (
            client_metrics["handshake_read_bytes"]
            + client_metrics["handshake_written_bytes"]
        )

        server_handshake_total = (
            server_metrics["handshake_read_bytes"]
            + server_metrics["handshake_written_bytes"]
        )

        require(
            client_handshake_total
            == server_handshake_total,
            (
                "endpoint mismatch for total handshake "
                f"bytes: {client_handshake_total} != "
                f"{server_handshake_total}"
            ),
        )

        summary = {
            "result": "PASS",
            "experiment":
                "mutual-auth-directional-metrics-probe",
            "image": IMAGE,
            "profile": "ecdsa-p256",
            "auth_family": "x509-direct",
            "client_random": client_random,

            "server_certificate_message_bytes":
                server_cert,

            "client_certificate_message_bytes":
                client_cert,

            "certificate_total_bytes":
                cert_total,

            "server_certificate_verify_message_bytes":
                client_metrics[
                    "server_certificate_verify_message_bytes"
                ],

            "client_certificate_verify_message_bytes":
                client_metrics[
                    "client_certificate_verify_message_bytes"
                ],

            "handshake_total_bytes":
                client_handshake_total,

            "legacy_certificate_semantics_preserved":
                True,

            "endpoint_directional_invariants":
                True,

            "client_metrics":
                client_metrics,

            "server_metrics":
                server_metrics,
        }

        (root / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n",
            encoding="utf-8",
        )

        print()
        print("=== MUTUAL METRICS PROBE PASS ===")
        print(
            "server Certificate bytes =",
            server_cert,
        )
        print(
            "client Certificate bytes =",
            client_cert,
        )
        print(
            "Certificate total bytes  =",
            cert_total,
        )
        print(
            "handshake total bytes    =",
            client_handshake_total,
        )
        print(
            "legacy semantics         = PASS"
        )
        print(
            "endpoint invariants      = PASS"
        )
        print(root)

    finally:
        run(
            ["docker", "rm", "-f", SERVER_NAME],
            check=False,
        )

        run(
            ["docker", "network", "rm", NETWORK],
            check=False,
        )


if __name__ == "__main__":
    main()
