#!/usr/bin/env python3
import argparse
import json
import os
import platform
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"
NETWORK = "mt-mutual-auth"
SERVER_NAME = "mt-mutual-preflight-server"

COMMON_ENV = {
    "LD_LIBRARY_PATH": "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib",
}

TLS_FLAGS = [
    "-tls1_3",
    "-groups", "X25519",
    "-ciphersuites", "TLS_AES_256_GCM_SHA384",
]


def host_cpu_frequency():
    for name in ("hw.cpufrequency_max", "hw.cpufrequency"):
        try:
            value = subprocess.check_output(
                ["/usr/sbin/sysctl", "-n", name],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if value.isdigit() and int(value) > 0:
            return f"{int(value) / 1_000_000_000:.2f} GHz"
    return "not reported by OS (dynamic frequency)"

PQ_PROVIDER_FLAGS = [
    "-provider-path", "/opt/openssl/lib/ossl-modules",
    "-provider", "default",
    "-provider", "oqsprovider",
]


def run(cmd, *, check=True, capture=True):
    result = subprocess.run(
        cmd,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and result.returncode != 0:
        raise SystemExit(
            "COMMAND FAILED\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + (result.stdout or "")
            + "\nSTDERR:\n"
            + (result.stderr or "")
        )
    return result


def docker_rm(name):
    run(["docker", "rm", "-f", name], check=False)


def docker_network_reset():
    run(["docker", "network", "rm", NETWORK], check=False)
    run(["docker", "network", "create", NETWORK])


def docker_env_args(env):
    args = []
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    return args


def base_server_cmd(volumes, env):
    cmd = [
        "docker", "run", "-d",
        "--name", SERVER_NAME,
        "--network", NETWORK,
    ]
    cmd += docker_env_args(env)
    for host, guest in volumes:
        cmd += ["-v", f"{host}:{guest}:ro"]
    cmd += [
        "--entrypoint", OPENSSL,
        IMAGE,
        "s_server",
    ]
    return cmd


def base_client_cmd(volumes, env):
    cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK,
    ]
    cmd += docker_env_args(env)
    for host, guest in volumes:
        cmd += ["-v", f"{host}:{guest}:ro"]
    cmd += [
        "--entrypoint", OPENSSL,
        IMAGE,
        "s_client",
    ]
    return cmd


def case_definitions(manual, server_mtc):

    return [
        {
            "name": "x509_server_x509_client",
            "env": COMMON_ENV,
            "volumes": [(manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/work/server.pem",
                "-key", "/work/server.key",
                "-CAfile", "/work/client-ca.pem",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-CAfile", "/work/server-ca.pem",
                "-cert", "/work/client.pem",
                "-key", "/work/client.key",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
            "expect_client": [
                "Verification: OK",
                "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
                "Verify return code: 0 (ok)",
            ],
            "expect_server": [
                "SSL_accept:SSLv3/TLS read client certificate",
                "SSL_accept:SSLv3/TLS read certificate verify",
                "SSL_accept:SSLv3/TLS read finished",
            ],
        },
        {
            "name": "pq_x509_server_pq_x509_client",
            "env": COMMON_ENV,
            "volumes": [(manual, "/work")],
            "server": [
                *PQ_PROVIDER_FLAGS,
                "-accept", "4433",
                "-cert", "/work/pq-server.pem",
                "-key", "/work/pq-server.key",
                "-CAfile", "/work/pq-client-ca.pem",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
            ],
            "client": [
                *PQ_PROVIDER_FLAGS,
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-CAfile", "/work/pq-server-ca.pem",
                "-cert", "/work/pq-client.pem",
                "-key", "/work/pq-client.key",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
            "expect_client": [
                "Verification: OK",
                "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
                "Verify return code: 0 (ok)",
            ],
            "expect_server": [
                "depth=1 CN=PQC Mutual Auth Client CA",
                "depth=0 CN=client",
                "SSL_accept:SSLv3/TLS read client certificate",
                "SSL_accept:SSLv3/TLS read certificate verify",
                "SSL_accept:SSLv3/TLS read finished",
            ],
        },
        {
            "name": "mtc_server_x509_client",
            "env": COMMON_ENV,
            "volumes": [(server_mtc, "/server-mtc"), (manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/server-mtc/batch16/mtc/ecdsa-p256/landmark-0000.pem",
                "-key", "/server-mtc/population/ecdsa-p256/0.key",
                "-mtc_id", "32473.101.1.1.1",
                "-mtc_landmark",
                "-CAfile", "/work/client-ca.pem",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-mtc_trust", "/server-mtc/batch16/mtc/ecdsa-p256/trust.bin",
                "-mtc_landmark",
                "-cert", "/work/client.pem",
                "-key", "/work/client.key",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
            "expect_client": [
                "Verification: OK",
                "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
                "Verify return code: 0 (ok)",
            ],
            "expect_server": [
                "depth=1 CN=Mutual Auth Client CA",
                "depth=0 CN=client",
                "SSL_accept:SSLv3/TLS read client certificate",
                "SSL_accept:SSLv3/TLS read certificate verify",
                "SSL_accept:SSLv3/TLS read finished",
            ],
        },
        {
            "name": "x509_server_mtc_client",
            "env": COMMON_ENV,
            "volumes": [(manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/work/server.pem",
                "-key", "/work/server.key",
                "-mtc_client_trust", "/work/mtc-client-n16/ecdsa-p256/trust.bin",
                "-mtc_landmark",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-CAfile", "/work/server-ca.pem",
                "-cert", "/work/mtc-client-n16/ecdsa-p256/landmark-0000.pem",
                "-key", "/work/mtc-client-source/client-0000.key",
                "-mtc_client_id", "32473.101.1.1.1",
                "-mtc_landmark",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
            "expect_client": [
                "Verification: OK",
                "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
                "Verify return code: 0 (ok)",
            ],
            "expect_server": [
                "MTC verification: OK",
                "SSL_accept:SSLv3/TLS read client certificate",
                "SSL_accept:SSLv3/TLS read certificate verify",
                "SSL_accept:SSLv3/TLS read finished",
            ],
        },
        {
            "name": "mtc_server_mtc_client",
            "env": COMMON_ENV,
            "volumes": [(server_mtc, "/server-mtc"), (manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/server-mtc/batch16/mtc/ecdsa-p256/landmark-0000.pem",
                "-key", "/server-mtc/population/ecdsa-p256/0.key",
                "-mtc_id", "32473.101.1.1.1",
                "-mtc_client_trust", "/work/mtc-client-n16/ecdsa-p256/trust.bin",
                "-mtc_landmark",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-mtc_trust", "/server-mtc/batch16/mtc/ecdsa-p256/trust.bin",
                "-cert", "/work/mtc-client-n16/ecdsa-p256/landmark-0000.pem",
                "-key", "/work/mtc-client-source/client-0000.key",
                "-mtc_client_id", "32473.101.1.1.1",
                "-mtc_landmark",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
            "expect_client": [
                "Verification: OK",
                "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
                "Verify return code: 0 (ok)",
            ],
            "expect_server": [
                "MTC verification: OK",
                "SSL_accept:SSLv3/TLS read client certificate",
                "SSL_accept:SSLv3/TLS read certificate verify",
                "SSL_accept:SSLv3/TLS read finished",
            ],
        },
    ]


def assert_contains(text, patterns, label):
    missing = [p for p in patterns if p not in text]
    if missing:
        raise AssertionError(f"{label} missing patterns: {missing}")


def negative_case_definitions(manual):
    return [
        {
            "name": "missing_client_credential",
            "env": COMMON_ENV,
            "volumes": [(manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/work/server.pem",
                "-key", "/work/server.key",
                "-CAfile", "/work/client-ca.pem",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-CAfile", "/work/server-ca.pem",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
                "-ign_eof",
            ],
            "expect_client": [
                "alert",
            ],
            "expect_server": [
                "peer did not return a certificate",
                "SSL_accept:error",
            ],
        },
        {
            "name": "wrong_x509_client_ca",
            "env": COMMON_ENV,
            "volumes": [(manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/work/server.pem",
                "-key", "/work/server.key",
                "-CAfile", "/work/client-ca.pem",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
                "-ign_eof",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-CAfile", "/work/server-ca.pem",
                "-cert", "/work/wrong-client.pem",
                "-key", "/work/wrong-client.key",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
                "-ign_eof",
            ],
            "expect_client": [
                "unknown ca",
            ],
            "expect_server": [
                "unable to get local issuer certificate",
                "certificate verify failed",
            ],
        },
        {
            "name": "untrusted_mtc_client_domain",
            "env": COMMON_ENV,
            "volumes": [(manual, "/work")],
            "server": [
                "-accept", "4433",
                "-cert", "/work/server.pem",
                "-key", "/work/server.key",
                "-mtc_client_trust", "/work/mtc-client-n16/ecdsa-p256/trust.bin",
                "-mtc_landmark",
                "-Verify", "1",
                "-verify_return_error",
                *TLS_FLAGS,
                "-num_tickets", "0",
                "-www",
                "-state",
                "-ign_eof",
            ],
            "client": [
                "-connect", f"{SERVER_NAME}:4433",
                "-servername", "server",
                "-CAfile", "/work/server-ca.pem",
                "-cert", "/work/mtc-client-n16-alt/ecdsa-p256/landmark-0000.pem",
                "-key", "/work/mtc-client-source-alt/client-0000.key",
                "-mtc_client_id", "32473.101.1.1.1",
                "-mtc_landmark",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
                "-ign_eof",
            ],
            "expect_client": [
                "handshake failure",
            ],
            "expect_server": [
                "handshake failure",
                "certificate verify failed",
            ],
        },
    ]


def run_case(case):
    docker_rm(SERVER_NAME)

    server_cmd = base_server_cmd(case["volumes"], case["env"]) + case["server"]
    server = subprocess.Popen(
        server_cmd,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    time.sleep(1)

    try:
        client_cmd = base_client_cmd(case["volumes"], case["env"]) + case["client"]
        client = subprocess.run(
            client_cmd,
            cwd=REPO,
            text=True,
            input="",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        docker_logs = run(
            ["docker", "logs", SERVER_NAME],
            check=False,
            capture=True,
        )
        server_log = docker_logs.stdout + docker_logs.stderr

        if client.returncode != 0:
            raise AssertionError(
                f"client failed with rc={client.returncode}\n{client.stdout}"
            )

        assert_contains(client.stdout, case["expect_client"], "client")
        assert_contains(server_log, case["expect_server"], "server")

        return {
            "name": case["name"],
            "result": "PASS",
            "client_returncode": client.returncode,
        }

    finally:
        docker_rm(SERVER_NAME)


def run_negative_case(case):
    docker_rm(SERVER_NAME)

    server_cmd = base_server_cmd(case["volumes"], case["env"]) + case["server"]
    server = subprocess.Popen(
        server_cmd,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    time.sleep(1)

    try:
        client_cmd = base_client_cmd(case["volumes"], case["env"]) + case["client"]
        client = subprocess.run(
            client_cmd,
            cwd=REPO,
            text=True,
            input="",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        docker_logs = run(
            ["docker", "logs", SERVER_NAME],
            check=False,
            capture=True,
        )
        server_log = docker_logs.stdout + docker_logs.stderr

        if client.returncode == 0:
            raise AssertionError(
                f"negative case unexpectedly succeeded\n{client.stdout}"
            )

        assert_contains(client.stdout, case["expect_client"], "client")
        assert_contains(server_log, case["expect_server"], "server")

        return {
            "name": case["name"],
            "result": "PASS",
            "client_returncode": client.returncode,
        }

    finally:
        docker_rm(SERVER_NAME)


def main():
    started = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON summary",
    )
    parser.add_argument(
        "--manual-root", type=Path,
        default=REPO / "artifacts/validation/mutual-auth-manual",
        help="X.509 and MTC client fixture root",
    )
    parser.add_argument(
        "--mtc-root", type=Path, required=True,
        help="current MTC N=16 fixture root",
    )
    parser.add_argument("--configured-profile", default="not-recorded", help="general protocol-validation profile recorded for provenance")
    parser.add_argument("--configured-leaf", type=int, default=0, help="general protocol-validation leaf recorded for provenance")
    parser.add_argument(
        "--output", type=Path,
        help="new result directory below artifacts/results",
    )
    args = parser.parse_args()

    manual = args.manual_root.resolve()
    server_mtc = args.mtc_root.resolve()
    for root, label in ((manual, "manual fixture root"), (server_mtc, "MTC fixture root")):
        if not root.is_dir():
            parser.error(f"{label} missing: {root}")
    output = args.output.resolve() if args.output else None
    results_root = (REPO / "artifacts/results").resolve()
    if output and (not output.is_relative_to(results_root) or output.exists()):
        parser.error("--output must be a new directory below artifacts/results")

    docker_network_reset()

    positive_results = []
    negative_results = []
    try:
        for case in case_definitions(manual, server_mtc):
            print(f"RUN positive {case['name']}", flush=True)
            case_started = time.monotonic()
            result = run_case(case)
            result["elapsed_seconds"] = time.monotonic() - case_started
            print(f"PASS positive {case['name']}", flush=True)
            positive_results.append(result)

        for case in negative_case_definitions(manual):
            print(f"RUN negative {case['name']}", flush=True)
            case_started = time.monotonic()
            result = run_negative_case(case)
            result["elapsed_seconds"] = time.monotonic() - case_started
            print(f"PASS negative {case['name']}", flush=True)
            negative_results.append(result)
    finally:
        run(["docker", "network", "rm", NETWORK], check=False)

    results = positive_results + negative_results
    summary = {
        "result": "PASS",
        "positive_case_count": len(positive_results),
        "negative_case_count": len(negative_results),
        "case_count": len(results),
        "passed": len([r for r in results if r["result"] == "PASS"]),
        "positive_cases": positive_results,
        "negative_cases": negative_results,
        "configuration": {
            "general_protocol_profile": args.configured_profile,
            "general_protocol_leaf": args.configured_leaf,
            "tree_size": 16,
            "mutual_auth_mtc_profile": "ecdsa-p256",
            "mutual_auth_mtc_leaf": 0,
            "classical_x509_profile": "ECDSA P-256",
            "post_quantum_x509_profile": "ML-DSA-65",
            "mtc_fixture_root": str(server_mtc),
            "manual_fixture_root": str(manual),
            "mtc_server_certificate": "batch16/mtc/ecdsa-p256/landmark-0000.pem",
            "mtc_server_key": "population/ecdsa-p256/0.key",
            "mtc_client_certificate": "mtc-client-n16/ecdsa-p256/landmark-0000.pem",
            "mtc_client_key": "mtc-client-source/client-0000.key"
        },
        "execution": {
            "elapsed_seconds": time.time() - started,
            "host": {
                "hostname": platform.node(),
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "cpu_frequency": host_cpu_frequency(),
                "cpu_count": os.cpu_count(),
                "python": platform.python_version(),
            },
        },
    }

    if output:
        output.mkdir(parents=True)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"PASS: {summary['passed']}/{summary['case_count']} mutual-auth preflights")


if __name__ == "__main__":
    main()
