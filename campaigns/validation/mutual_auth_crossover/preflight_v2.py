#!/usr/bin/env python3

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from config import (
    ARTIFACT_ROOT,
    MTC_N_VALUES,
    PROFILES,
    SERVER_ONLY_FIXTURES,
)

REPO = Path(__file__).resolve().parents[3]

OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"

NETWORK = "mt-mutual-auth-crossover-v2-preflight"
SERVER_NAME = "mt-mutual-auth-crossover-v2-server"

COMMON_ENV = {
    "LD_LIBRARY_PATH":
        "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib",
}

TLS_FLAGS = [
    "-tls1_3",
    "-groups", "X25519",
    "-ciphersuites", "TLS_AES_256_GCM_SHA384",
]


def run(cmd, *, check=True):
    result = subprocess.run(
        cmd,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if check and result.returncode != 0:
        raise SystemExit(
            "COMMAND FAILED\n"
            + " ".join(map(str, cmd))
            + "\n\nSTDOUT:\n"
            + (result.stdout or "")
            + "\nSTDERR:\n"
            + (result.stderr or "")
        )

    return result


def docker_rm(name):
    run(
        ["docker", "rm", "-f", name],
        check=False,
    )


def docker_network_reset():
    run(
        ["docker", "network", "rm", NETWORK],
        check=False,
    )
    run(
        ["docker", "network", "create", NETWORK]
    )


def docker_env_args(env):
    result = []

    for key, value in env.items():
        result += ["-e", f"{key}={value}"]

    return result


def base_server_cmd(volumes):
    cmd = [
        "docker", "run", "-d",
        "--name", SERVER_NAME,
        "--network", NETWORK,
    ]

    cmd += docker_env_args(COMMON_ENV)

    for host, guest in volumes:
        cmd += [
            "-v",
            f"{host.resolve()}:{guest}:ro",
        ]

    cmd += [
        "--entrypoint", OPENSSL,
        IMAGE,
        "s_server",
    ]

    return cmd


def base_client_cmd(volumes):
    cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK,
    ]

    cmd += docker_env_args(COMMON_ENV)

    for host, guest in volumes:
        cmd += [
            "-v",
            f"{host.resolve()}:{guest}:ro",
        ]

    cmd += [
        "--entrypoint", OPENSSL,
        IMAGE,
        "s_client",
    ]

    return cmd


def assert_files(paths):
    missing = [
        path
        for path in paths
        if not path.is_file()
    ]

    if missing:
        raise SystemExit(
            f"Missing required file: {missing[0]}"
        )


def case_definitions(profile, n):
    if profile not in PROFILES:
        raise SystemExit(
            f"Unknown profile: {profile}"
        )

    if n not in MTC_N_VALUES[profile]:
        raise SystemExit(
            f"N={n} not allowed for {profile}; "
            f"expected one of {MTC_N_VALUES[profile]}"
        )

    mtc_id = PROFILES[profile]["mtc_id"]

    # ---------------------------------------------------------
    # X.509 server fixtures from the server-only experiment.
    # ---------------------------------------------------------

    server_direct = (
        SERVER_ONLY_FIXTURES
        / profile
        / "direct-server"
    )

    server_ca = (
        SERVER_ONLY_FIXTURES
        / profile
        / "ca-server"
    )

    # ---------------------------------------------------------
    # New mutual-auth client fixtures.
    # ---------------------------------------------------------

    client_direct = (
        ARTIFACT_ROOT
        / "client-x509"
        / profile
        / "direct-server"
    )

    client_ca = (
        ARTIFACT_ROOT
        / "client-x509"
        / profile
        / "ca-server"
    )

    # ---------------------------------------------------------
    # MTC fixtures.
    # ---------------------------------------------------------

    server_mtc = (
        ARTIFACT_ROOT
        / "server-mtc"
        / f"batch{n}"
        / profile
    )

    client_mtc = (
        ARTIFACT_ROOT
        / "client-mtc"
        / f"batch{n}"
        / profile
    )

    server_mtc_source = (
        ARTIFACT_ROOT
        / "server-mtc-source"
        / profile
    )

    # MTC client source is the frozen CA client population.
    client_mtc_source = client_ca

    assert_files([
        # Direct X.509.
        server_direct / "server.pem",
        server_direct / "server.key",
        client_direct / "client-0000.pem",
        client_direct / "client-0000.key",

        # CA X.509.
        server_ca / "server.pem",
        server_ca / "server.key",
        server_ca / "root.pem",
        client_ca / "client-0000.pem",
        client_ca / "client-0000.key",
        client_ca / "ca.pem",

        # MTC.
        server_mtc / "landmark-0000.pem",
        server_mtc / "trust.bin",
        client_mtc / "landmark-0000.pem",
        client_mtc / "trust.bin",
        server_mtc_source / "server-0000.key",
        client_mtc_source / "client-0000.key",
    ])

    return [
        # =====================================================
        # 1. X.509 Direct / Direct
        # =====================================================
        {
            "name":
                f"{profile}_x509_direct_direct",

            "kind": "x509-direct",

            "volumes": [
                (server_direct, "/server-x509"),
                (client_direct, "/client-x509"),
            ],

            "server": [
                "-accept", "4433",

                "-cert",
                "/server-x509/server.pem",

                "-key",
                "/server-x509/server.key",

                # The client leaf itself is the trust anchor.
                "-CAfile",
                "/client-x509/client-0000.pem",

                "-Verify", "1",
                "-verify_return_error",

                *TLS_FLAGS,

                "-num_tickets", "0",
                "-www",
                "-state",
            ],

            "client": [
                "-connect",
                f"{SERVER_NAME}:4433",

                "-servername", "server",

                # The server leaf itself is the trust anchor.
                "-CAfile",
                "/server-x509/server.pem",

                "-cert",
                "/client-x509/client-0000.pem",

                "-key",
                "/client-x509/client-0000.key",

                *TLS_FLAGS,

                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
        },

        # =====================================================
        # 2. X.509 CA / CA
        # =====================================================
        {
            "name":
                f"{profile}_x509_ca_ca",

            "kind": "x509-ca",

            "volumes": [
                (server_ca, "/server-x509"),
                (client_ca, "/client-x509"),
            ],

            "server": [
                "-accept", "4433",

                "-cert",
                "/server-x509/server.pem",

                "-key",
                "/server-x509/server.key",

                # Client CA -> client.
                "-CAfile",
                "/client-x509/ca.pem",

                "-Verify", "1",
                "-verify_return_error",

                *TLS_FLAGS,

                "-num_tickets", "0",
                "-www",
                "-state",
            ],

            "client": [
                "-connect",
                f"{SERVER_NAME}:4433",

                "-servername", "server",

                # Server CA -> server.
                "-CAfile",
                "/server-x509/root.pem",

                "-cert",
                "/client-x509/client-0000.pem",

                "-key",
                "/client-x509/client-0000.key",

                *TLS_FLAGS,

                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
        },

        # =====================================================
        # 3. MTC / MTC
        # =====================================================
        {
            "name":
                f"{profile}_mtc_mtc_n{n}",

            "kind": "mtc",

            "volumes": [
                (server_mtc, "/server-mtc"),
                (client_mtc, "/client-mtc"),
                (
                    server_mtc_source,
                    "/server-source",
                ),
                (
                    client_mtc_source,
                    "/client-source",
                ),
            ],

            "server": [
                "-accept", "4433",

                "-cert",
                "/server-mtc/landmark-0000.pem",

                "-key",
                "/server-source/server-0000.key",

                "-mtc_id",
                mtc_id,

                "-mtc_client_trust",
                "/client-mtc/trust.bin",

                "-mtc_landmark",

                "-Verify", "1",
                "-verify_return_error",

                *TLS_FLAGS,

                "-num_tickets", "0",
                "-www",
                "-state",
            ],

            "client": [
                "-connect",
                f"{SERVER_NAME}:4433",

                "-servername", "server",

                "-mtc_trust",
                "/server-mtc/trust.bin",

                "-cert",
                "/client-mtc/landmark-0000.pem",

                "-key",
                "/client-source/client-0000.key",

                "-mtc_client_id",
                mtc_id,

                "-mtc_landmark",

                *TLS_FLAGS,

                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
        },
    ]


def assert_contains(text, patterns, label):
    missing = [
        pattern
        for pattern in patterns
        if pattern not in text
    ]

    if missing:
        raise AssertionError(
            f"{label} missing patterns: {missing}"
        )


def run_case(case, root):
    print()
    print(
        f"=== PREFLIGHT {case['name']} ===",
        flush=True,
    )

    docker_rm(SERVER_NAME)

    server_cmd = (
        base_server_cmd(case["volumes"])
        + case["server"]
    )

    server = run(server_cmd)

    container_id = server.stdout.strip()

    if not container_id:
        raise AssertionError(
            f"{case['name']}: server did not start"
        )

    time.sleep(1.0)

    try:
        client_cmd = (
            base_client_cmd(case["volumes"])
            + case["client"]
        )

        client = run(
            client_cmd,
            check=False,
        )

        logs = run(
            ["docker", "logs", SERVER_NAME],
            check=False,
        )

        client_text = (
            (client.stdout or "")
            + (client.stderr or "")
        )

        server_text = (
            (logs.stdout or "")
            + (logs.stderr or "")
        )

        raw = root / "raw"
        raw.mkdir(
            parents=True,
            exist_ok=True,
        )

        (
            raw
            / f"{case['name']}.client.log"
        ).write_text(
            client_text,
            encoding="utf-8",
        )

        (
            raw
            / f"{case['name']}.server.log"
        ).write_text(
            server_text,
            encoding="utf-8",
        )

        if client.returncode != 0:
            raise AssertionError(
                f"{case['name']}: "
                f"s_client returned "
                f"{client.returncode}"
            )

        # Client authenticated the server.
        assert_contains(
            client_text,
            [
                "Verification: OK",
                (
                    "New, TLSv1.3, Cipher is "
                    "TLS_AES_256_GCM_SHA384"
                ),
                "Verify return code: 0 (ok)",
            ],
            f"{case['name']} client",
        )

        # Server authenticated the client and verified
        # CertificateVerify + Finished.
        assert_contains(
            server_text,
            [
                (
                    "SSL_accept:SSLv3/TLS "
                    "read client certificate"
                ),
                (
                    "SSL_accept:SSLv3/TLS "
                    "read certificate verify"
                ),
                (
                    "SSL_accept:SSLv3/TLS "
                    "read finished"
                ),
            ],
            f"{case['name']} server",
        )

        # Additional evidence that the experimental MTC
        # verification path was actually exercised.
        if case["kind"] == "mtc":
            assert_contains(
                client_text,
                ["MTC_VERIFY"],
                f"{case['name']} MTC client",
            )

            assert_contains(
                server_text,
                ["MTC_VERIFY"],
                f"{case['name']} MTC server",
            )

        print(
            f"PASS {case['name']}",
            flush=True,
        )

        return {
            "name": case["name"],
            "kind": case["kind"],
            "result": "PASS",
            "client_returncode":
                client.returncode,
            "client_verification": True,
            "server_client_certificate":
                True,
            "server_client_certificate_verify":
                True,
            "server_client_finished":
                True,
            "mtc_verify_client":
                (
                    "MTC_VERIFY" in client_text
                    if case["kind"] == "mtc"
                    else None
                ),
            "mtc_verify_server":
                (
                    "MTC_VERIFY" in server_text
                    if case["kind"] == "mtc"
                    else None
                ),
        }

    finally:
        docker_rm(SERVER_NAME)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--profile",
        choices=PROFILES,
        default="ecdsa-p256",
    )

    parser.add_argument(
        "--n",
        type=int,
        default=8,
    )

    args = parser.parse_args()

    root = args.root

    if not root.is_absolute():
        root = REPO / root

    result_root = (
        REPO / "artifacts" / "results"
    )

    if not root.is_relative_to(result_root):
        raise SystemExit(
            "root must be under artifacts/results"
        )

    if root.exists() and any(root.iterdir()):
        raise SystemExit(
            f"Refusing to overwrite non-empty root: "
            f"{root}"
        )

    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    cases = case_definitions(
        args.profile,
        args.n,
    )

    docker_network_reset()

    observations = []

    try:
        for case in cases:
            observations.append(
                run_case(case, root)
            )

    finally:
        docker_rm(SERVER_NAME)

        run(
            [
                "docker",
                "network",
                "rm",
                NETWORK,
            ],
            check=False,
        )

    summary = {
        "result": "PASS",
        "experiment":
            "mutual-auth-crossover-v2",
        "profile": args.profile,
        "mtc_tree_size": args.n,
        "case_count": len(observations),
        "expected_case_count": 3,
        "tls": {
            "version": "TLS 1.3",
            "group": "X25519",
            "cipher":
                "TLS_AES_256_GCM_SHA384",
            "tickets": False,
            "resumption": False,
            "mutual_authentication": True,
        },
        "cases": observations,
    }

    metadata = {
        "created_utc":
            datetime.now(timezone.utc).isoformat(),
        "image": IMAGE,
        "openssl": OPENSSL,
        "mtc_status": "MTC-experimental",
        "purpose": (
            "Positive preflight for X.509 "
            "Direct/Direct, X.509 CA/CA, "
            "and MTC/MTC"
        ),
    }

    (
        root / "summary.json"
    ).write_text(
        json.dumps(
            summary,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    (
        root / "metadata.json"
    ).write_text(
        json.dumps(
            metadata,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print(
        "=== MUTUAL AUTH CROSSOVER V2 "
        "PREFLIGHT PASS ==="
    )
    print(
        f"profile = {args.profile}"
    )
    print(
        f"MTC N = {args.n}"
    )
    print(
        f"cases = {len(observations)}/3"
    )
    print(root)


if __name__ == "__main__":
    main()
