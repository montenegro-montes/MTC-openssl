#!/usr/bin/env python3
import argparse
import csv
import json
import re
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"
NETWORK = "mt-mutual-auth-crossover-measurement"
SERVER_NAME = "mt-mutual-crossover-measurement-server"

COMMON_ENV = {
    "LD_LIBRARY_PATH": "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib",
}

TLS_FLAGS = [
    "-tls1_3",
    "-groups", "X25519",
    "-ciphersuites", "TLS_AES_256_GCM_SHA384",
]

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


def case_definitions():
    server_x509 = (
        REPO
        / "artifacts"
        / "validation"
        / "chain-depth-server-only-fixtures-full-20260918T101613Z"
        / "ecdsa-p521"
        / "ca-server"
    )

    client_x509 = (
        REPO
        / "artifacts"
        / "validation"
        / "mutual-auth-crossover"
        / "client-source"
        / "ecdsa-p521"
    )

    server_mtc_root = (
        REPO
        / "artifacts"
        / "validation"
        / "mutual-auth-crossover"
        / "server-mtc"
    )

    client_mtc_root = (
        REPO
        / "artifacts"
        / "validation"
        / "mutual-auth-crossover"
        / "client-mtc"
    )

    server_source = (
        REPO
        / "artifacts"
        / "validation"
        / "mutual-auth-crossover"
        / "server-source"
        / "ecdsa-p521-ca-server"
    )

    cases = [
        {
            "name": "x509_server_x509_client",
            "server_auth_mode": "x509-p521-ca-server",
            "client_auth_mode": "x509-p521-client",
            "crossover_n": 0,
            "env": COMMON_ENV,
            "volumes": [
                (server_x509, "/server-x509"),
                (client_x509, "/client-x509"),
            ],
            "server": [
                "-accept", "4433",
                "-cert", "/server-x509/server.pem",
                "-key", "/server-x509/server.key",
                "-CAfile", "/client-x509/ca.pem",
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
                "-CAfile", "/server-x509/root.pem",
                "-cert", "/client-x509/client-0000.pem",
                "-key", "/client-x509/client-0000.key",
                *TLS_FLAGS,
                "-no_ticket",
                "-verify_return_error",
                "-state",
            ],
        }
    ]

    for n in (16, 32, 64, 128):
        server_mtc = server_mtc_root / f"batch{n}" / "ecdsa-p521"
        client_mtc = client_mtc_root / f"batch{n}" / "ecdsa-p521"

        cases.append(
            {
                "name": f"mtc_server_mtc_client_n{n}",
                "server_auth_mode": "mtc-experimental-p521-ca-server",
                "client_auth_mode": "mtc-experimental-p521-client",
                "crossover_n": n,
                "env": COMMON_ENV,
                "volumes": [
                    (server_mtc, "/server-mtc"),
                    (client_mtc, "/client-mtc"),
                    (server_source, "/server-source"),
                    (client_x509, "/client-source"),
                ],
                "server": [
                    "-accept", "4433",
                    "-cert", "/server-mtc/landmark-0000.pem",
                    "-key", "/server-source/server-0000.key",
                    "-mtc_id", "32473.103.1.1.1",
                    "-mtc_client_trust", "/client-mtc/trust.bin",
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
                    "-mtc_trust", "/server-mtc/trust.bin",
                    "-cert", "/client-mtc/landmark-0000.pem",
                    "-key", "/client-source/client-0000.key",
                    "-mtc_client_id", "32473.103.1.1.1",
                    "-mtc_landmark",
                    *TLS_FLAGS,
                    "-no_ticket",
                    "-verify_return_error",
                    "-state",
                ],
            }
        )

    return cases

def parse_s_client(text):
    bytes_read = None
    bytes_written = None
    tls_version = None
    cipher = None

    m = re.search(r"SSL handshake has read (\d+) bytes and written (\d+) bytes", text)
    if m:
        bytes_read = int(m.group(1))
        bytes_written = int(m.group(2))

    m = re.search(r"New, (TLSv[0-9.]+), Cipher is ([A-Z0-9_]+)", text)
    if m:
        tls_version = m.group(1)
        cipher = m.group(2)

    return {
        "bytes_read": bytes_read,
        "bytes_written": bytes_written,
        "tls_version": tls_version,
        "cipher": cipher,
    }


def parse_mtc_timings(text, prefix):
    setup_ms = []
    verify_ms = []

    for m in re.finditer(r'MTC_SETUP \{[^}]*"mtc_setup_ms":([0-9.]+)', text):
        setup_ms.append(float(m.group(1)))

    for m in re.finditer(r'MTC_VERIFY \{[^}]*"mtc_credential_auth_ms":([0-9.]+)', text):
        verify_ms.append(float(m.group(1)))

    return {
        f"{prefix}_mtc_setup_ms": sum(setup_ms) if setup_ms else None,
        f"{prefix}_mtc_verify_ms": sum(verify_ms) if verify_ms else None,
    }


def add_mtc_totals(client_mtc, server_mtc):
    client_setup = client_mtc["client_mtc_setup_ms"]
    client_verify = client_mtc["client_mtc_verify_ms"]
    server_setup = server_mtc["server_mtc_setup_ms"]
    server_verify = server_mtc["server_mtc_verify_ms"]

    setup_values = [v for v in [client_setup, server_setup] if v is not None]
    verify_values = [v for v in [client_verify, server_verify] if v is not None]

    return {
        "mtc_setup_ms": sum(setup_values) if setup_values else None,
        "mtc_verify_ms": sum(verify_values) if verify_values else None,
    }


def measure_case(case, round_index):
    docker_rm(SERVER_NAME)

    server_cmd = base_server_cmd(case["volumes"], case["env"]) + case["server"]
    subprocess.Popen(
        server_cmd,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    time.sleep(1)

    try:
        client_cmd = base_client_cmd(case["volumes"], case["env"]) + case["client"]

        t0 = time.perf_counter()
        client = subprocess.run(
            client_cmd,
            cwd=REPO,
            text=True,
            input="",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        t1 = time.perf_counter()

        docker_logs = run(["docker", "logs", SERVER_NAME], check=False, capture=True)
        server_log = docker_logs.stdout + docker_logs.stderr

        if client.returncode != 0:
            raise AssertionError(
                f"{case['name']} failed with rc={client.returncode}\\n{client.stdout}\\n{server_log}"
            )

        if "Verification: OK" not in client.stdout:
            raise AssertionError(f"{case['name']} missing client verification evidence")

        if "SSL_accept:SSLv3/TLS read client certificate" not in server_log:
            raise AssertionError(f"{case['name']} missing server client-certificate evidence")

        parsed = parse_s_client(client.stdout)
        client_mtc = parse_mtc_timings(client.stdout, "client")
        server_mtc = parse_mtc_timings(server_log, "server")
        mtc = add_mtc_totals(client_mtc, server_mtc)

        return {
            "client_stdout": client.stdout,
            "server_log": server_log,
            "case_name": case["name"],
            "round": round_index,
            "client_returncode": client.returncode,
            "handshake_wall_ms": (t1 - t0) * 1000.0,
            "bytes_read": parsed["bytes_read"],
            "bytes_written": parsed["bytes_written"],
            "tls_version": parsed["tls_version"],
            "cipher": parsed["cipher"],
            "server_auth_mode": case["server_auth_mode"],
            "client_auth_mode": case["client_auth_mode"],
            "client_mtc_setup_ms": client_mtc["client_mtc_setup_ms"],
            "client_mtc_verify_ms": client_mtc["client_mtc_verify_ms"],
            "server_mtc_setup_ms": server_mtc["server_mtc_setup_ms"],
            "server_mtc_verify_ms": server_mtc["server_mtc_verify_ms"],
            "mtc_setup_ms": mtc["mtc_setup_ms"],
            "mtc_verify_ms": mtc["mtc_verify_ms"],
        }

    finally:
        docker_rm(SERVER_NAME)


def write_outputs(root, observations, args):
    root.mkdir(parents=True, exist_ok=True)

    raw_dir = root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    for obs in observations:
        raw_client = obs.pop("client_stdout", "")
        raw_server = obs.pop("server_log", "")
        stem = f"{obs['round']:04d}-{obs['case_name']}"
        (raw_dir / f"{stem}.client.log").write_text(raw_client, encoding="utf-8")
        (raw_dir / f"{stem}.server.log").write_text(raw_server, encoding="utf-8")

    fields = [
        "case_name",
        "round",
        "client_returncode",
        "handshake_wall_ms",
        "bytes_read",
        "bytes_written",
        "tls_version",
        "cipher",
        "server_auth_mode",
        "client_auth_mode",
        "client_mtc_setup_ms",
        "client_mtc_verify_ms",
        "server_mtc_setup_ms",
        "server_mtc_verify_ms",
        "mtc_setup_ms",
        "mtc_verify_ms",
    ]

    with (root / "observations.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(observations)

    by_case = {}
    for obs in observations:
        by_case.setdefault(obs["case_name"], []).append(obs)

    summary_cases = {}
    for name, rows in by_case.items():
        wall = [r["handshake_wall_ms"] for r in rows]
        read = [r["bytes_read"] for r in rows if r["bytes_read"] is not None]
        written = [r["bytes_written"] for r in rows if r["bytes_written"] is not None]
        summary_cases[name] = {
            "count": len(rows),
            "handshake_wall_ms_median": statistics.median(wall),
            "handshake_wall_ms_mean": statistics.mean(wall),
            "bytes_read_median": statistics.median(read) if read else None,
            "bytes_written_median": statistics.median(written) if written else None,
        }

    summary = {
        "result": "PASS",
        "observation_count": len(observations),
        "case_count": len(by_case),
        "rounds": args.rounds,
        "cases": summary_cases,
    }

    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "image": IMAGE,
        "openssl": OPENSSL,
        "network": NETWORK,
        "tls": {
            "version": "TLS 1.3",
            "group": "X25519",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "tickets": False,
            "resumption": False,
            "client_auth_required": True,
        },
        "scope": "positive mutual-authentication measurement only",
        "mtc_status": "MTC-experimental",
    }

    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()

    if args.preflight:
        args.rounds = 1

    root = args.root
    if not root.is_absolute():
        root = REPO / root

    if not root.is_relative_to(REPO / "artifacts/results"):
        raise SystemExit("root must be under artifacts/results")

    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty root: {root}")

    docker_network_reset()

    observations = []
    try:
        for round_index in range(args.rounds):
            for case in case_definitions():
                print(f"RUN round={round_index} case={case['name']}", flush=True)
                obs = measure_case(case, round_index)
                observations.append(obs)
                print(
                    f"PASS round={round_index} case={case['name']} "
                    f"wall_ms={obs['handshake_wall_ms']:.3f} "
                    f"bytes_read={obs['bytes_read']} "
                    f"bytes_written={obs['bytes_written']}",
                    flush=True,
                )
    finally:
        run(["docker", "network", "rm", NETWORK], check=False)

    write_outputs(root, observations, args)
    print(f"PASS wrote {len(observations)} observations to {root}")


if __name__ == "__main__":
    main()
