#!/usr/bin/env python3

import argparse
import csv
import json
import random
import re
import shutil
import statistics
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

IMAGE = "mt-tls-mtc-mutual:local"
OPENSSL = "/opt/openssl-mtc/bin/openssl"

NETWORK = "mt-mutual-auth-crossover-v2-measurement"
SERVER_NAME = "mt-mutual-auth-crossover-v2-server"

LD_LIBRARY_PATH = (
    "/opt/openssl-mtc/lib:"
    "/opt/openssl/lib:"
    "/opt/oqs/lib"
)

TLS_FLAGS = [
    "-tls1_3",
    "-groups", "X25519",
    "-ciphersuites", "TLS_AES_256_GCM_SHA384",
]


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
            + " ".join(map(str, cmd))
            + "\n\nSTDOUT:\n"
            + (r.stdout or "")
            + "\nSTDERR:\n"
            + (r.stderr or "")
        )

    return r


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker_rm():
    run(
        ["docker", "rm", "-f", SERVER_NAME],
        check=False,
    )


def network_reset():
    run(
        ["docker", "network", "rm", NETWORK],
        check=False,
    )

    run(
        ["docker", "network", "create", NETWORK]
    )


def parse_profile_metrics(text):
    found = re.findall(
        r"^PROFILE_METRICS (\{.*\})$",
        text,
        re.MULTILINE,
    )

    if len(found) != 1:
        raise RuntimeError(
            "expected exactly one PROFILE_METRICS "
            f"record, got {len(found)}"
        )

    return json.loads(found[0])


def parse_mtc_timings(text, prefix):
    setup = [
        float(x)
        for x in re.findall(
            r'MTC_SETUP \{[^}]*"mtc_setup_ms":([0-9.]+)',
            text,
        )
    ]

    verify = [
        float(x)
        for x in re.findall(
            r'MTC_VERIFY \{[^}]*'
            r'"mtc_credential_auth_ms":([0-9.]+)',
            text,
        )
    ]

    return {
        f"{prefix}_mtc_setup_ms":
            sum(setup) if setup else "",

        f"{prefix}_mtc_verify_ms":
            sum(verify) if verify else "",
    }


def case_definitions():
    cases = []

    # ========================================================
    # Six X.509 baselines:
    #
    # P256 Direct/Direct
    # P256 CA/CA
    # P384 Direct/Direct
    # P384 CA/CA
    # P521 Direct/Direct
    # P521 CA/CA
    # ========================================================

    for profile in PROFILES:
        mtc_id = PROFILES[profile]["mtc_id"]

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

        cases.append({
            "name":
                f"{profile}_x509_direct_direct",

            "profile": profile,
            "auth_family": "x509",
            "x509_chain_profile": "direct-server",
            "tree_size": "",

            "volumes": [
                (server_direct, "/server"),
                (client_direct, "/client"),
            ],

            "server": [
                "-accept", "4433",
                "-cert", "/server/server.pem",
                "-key", "/server/server.key",

                "-CAfile",
                "/client/client-0000.pem",

                "-Verify", "1",
                "-verify_return_error",

                *TLS_FLAGS,

                "-num_tickets", "0",
                "-www",
                "-state",
                "-lab_metrics",
            ],

            "client": [
                "-connect",
                f"{SERVER_NAME}:4433",

                "-servername", "server",
                "-verify_hostname", "server",

                "-CAfile",
                "/server/server.pem",

                "-cert",
                "/client/client-0000.pem",

                "-key",
                "/client/client-0000.key",

                *TLS_FLAGS,

                "-no_ticket",
                "-verify_return_error",
                "-state",
                "-lab_metrics",
            ],
        })

        cases.append({
            "name":
                f"{profile}_x509_ca_ca",

            "profile": profile,
            "auth_family": "x509",
            "x509_chain_profile": "ca-server",
            "tree_size": "",

            "volumes": [
                (server_ca, "/server"),
                (client_ca, "/client"),
            ],

            "server": [
                "-accept", "4433",
                "-cert", "/server/server.pem",
                "-key", "/server/server.key",

                "-CAfile",
                "/client/ca.pem",

                "-Verify", "1",
                "-verify_return_error",

                *TLS_FLAGS,

                "-num_tickets", "0",
                "-www",
                "-state",
                "-lab_metrics",
            ],

            "client": [
                "-connect",
                f"{SERVER_NAME}:4433",

                "-servername", "server",
                "-verify_hostname", "server",

                "-CAfile",
                "/server/root.pem",

                "-cert",
                "/client/client-0000.pem",

                "-key",
                "/client/client-0000.key",

                *TLS_FLAGS,

                "-no_ticket",
                "-verify_return_error",
                "-state",
                "-lab_metrics",
            ],
        })

        # ====================================================
        # MTC is independent of the X.509 comparator depth.
        #
        # One MTC series per profile and N.
        # ====================================================

        server_source = (
            ARTIFACT_ROOT
            / "server-mtc-source"
            / profile
        )

        client_source = client_ca

        for n in MTC_N_VALUES[profile]:

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

            cases.append({
                "name":
                    f"{profile}_mtc_mtc_n{n}",

                "profile": profile,
                "auth_family":
                    "mtc-experimental",

                "x509_chain_profile": "",
                "tree_size": n,

                "volumes": [
                    (server_mtc, "/server-mtc"),
                    (client_mtc, "/client-mtc"),
                    (
                        server_source,
                        "/server-source",
                    ),
                    (
                        client_source,
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
                    "-lab_metrics",
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
                    "-lab_metrics",
                ],
            })

    return cases


def validate_case_files(case):
    for host, _guest in case["volumes"]:
        require(
            host.exists(),
            f"{case['name']}: missing {host}",
        )


def server_command(case, metrics_dir):
    cmd = [
        "docker", "run", "-d",

        "--name", SERVER_NAME,
        "--network", NETWORK,

        "-e",
        f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}",

        "-e",
        "PROFILE_DETAIL=0",

        "-e",
        "PROFILE_METRICS_DIR=/metrics",
    ]

    for host, guest in case["volumes"]:
        cmd += [
            "-v",
            f"{host.resolve()}:{guest}:ro",
        ]

    cmd += [
        "-v",
        f"{metrics_dir.resolve()}:/metrics",

        "--entrypoint", OPENSSL,
        IMAGE,

        "s_server",
        *case["server"],
    ]

    return cmd


def client_command(case):
    cmd = [
        "docker", "run", "--rm",

        "--network", NETWORK,

        "-e",
        f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}",

        "-e",
        "PROFILE_DETAIL=0",
    ]

    for host, guest in case["volumes"]:
        cmd += [
            "-v",
            f"{host.resolve()}:{guest}:ro",
        ]

    cmd += [
        "--entrypoint", OPENSSL,
        IMAGE,

        "s_client",
        *case["client"],
    ]

    return cmd


def measure_case(
    case,
    *,
    phase,
    round_index,
    order_index,
    root,
):
    docker_rm()

    metrics_dir = root / "server-metrics"
    metrics_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    server = run(
        server_command(
            case,
            metrics_dir,
        )
    )

    require(
        bool(server.stdout.strip()),
        f"{case['name']}: server did not start",
    )

    # Server startup is outside all native TLS timings.
    time.sleep(0.4)

    try:
        client = run(
            client_command(case),
            check=False,
            input_text="",
        )

        client_log = (
            (client.stdout or "")
            + (client.stderr or "")
        )

        server_logs = run(
            ["docker", "logs", SERVER_NAME],
            check=False,
        )

        server_log = (
            (server_logs.stdout or "")
            + (server_logs.stderr or "")
        )

        require(
            client.returncode == 0,
            (
                f"{case['name']}: "
                f"s_client rc={client.returncode}"
            ),
        )

        require(
            "Verification: OK" in client_log,
            f"{case['name']}: verification failed",
        )

        require(
            "Verify return code: 0 (ok)"
            in client_log,
            (
                f"{case['name']}: "
                "verify return code != 0"
            ),
        )

        require(
            (
                "New, TLSv1.3, Cipher is "
                "TLS_AES_256_GCM_SHA384"
            )
            in client_log,
            f"{case['name']}: TLS/cipher mismatch",
        )

        require(
            (
                "Peer Temp Key: X25519"
                in client_log
                or
                "Server Temp Key: X25519"
                in client_log
            ),
            f"{case['name']}: X25519 missing",
        )

        require(
            (
                "SSL_accept:SSLv3/TLS "
                "read client certificate"
            )
            in server_log,
            (
                f"{case['name']}: "
                "client Certificate missing"
            ),
        )

        require(
            (
                "SSL_accept:SSLv3/TLS "
                "read certificate verify"
            )
            in server_log,
            (
                f"{case['name']}: "
                "client CertificateVerify missing"
            ),
        )

        require(
            (
                "SSL_accept:SSLv3/TLS "
                "read finished"
            )
            in server_log,
            (
                f"{case['name']}: "
                "client Finished missing"
            ),
        )

        client_metrics = parse_profile_metrics(
            client.stderr
        )

        client_random = (
            client_metrics["client_random"]
        )

        server_metric_path = (
            metrics_dir
            / f"{client_random}.json"
        )

        for _ in range(40):
            if server_metric_path.is_file():
                break
            time.sleep(0.05)

        require(
            server_metric_path.is_file(),
            (
                f"{case['name']}: "
                "server metrics missing"
            ),
        )

        server_metrics = json.loads(
            server_metric_path.read_text()
        )

        require(
            not client_metrics["reused"],
            f"{case['name']}: client resumed",
        )

        require(
            not server_metrics["reused"],
            f"{case['name']}: server resumed",
        )

        directional_fields = [
            "server_certificate_message_bytes",
            "client_certificate_message_bytes",
            "server_certificate_verify_message_bytes",
            "client_certificate_verify_message_bytes",
        ]

        for field in directional_fields:
            require(
                client_metrics[field]
                == server_metrics[field],
                (
                    f"{case['name']}: "
                    f"endpoint mismatch {field}"
                ),
            )

        # Preserve historical server-only semantics.
        for endpoint, metrics in (
            ("client", client_metrics),
            ("server", server_metrics),
        ):
            require(
                metrics[
                    "certificate_message_bytes"
                ]
                == metrics[
                    "server_certificate_message_bytes"
                ],
                (
                    f"{case['name']}: "
                    f"{endpoint} legacy cert "
                    "semantics changed"
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
                    f"{case['name']}: "
                    f"{endpoint} legacy CV "
                    "semantics changed"
                ),
            )

        server_certificate_bytes = (
            client_metrics[
                "server_certificate_message_bytes"
            ]
        )

        client_certificate_bytes = (
            client_metrics[
                "client_certificate_message_bytes"
            ]
        )

        require(
            server_certificate_bytes > 0,
            f"{case['name']}: server cert bytes 0",
        )

        require(
            client_certificate_bytes > 0,
            f"{case['name']}: client cert bytes 0",
        )

        certificate_total_bytes = (
            server_certificate_bytes
            + client_certificate_bytes
        )

        client_handshake_total = (
            client_metrics[
                "handshake_read_bytes"
            ]
            + client_metrics[
                "handshake_written_bytes"
            ]
        )

        server_handshake_total = (
            server_metrics[
                "handshake_read_bytes"
            ]
            + server_metrics[
                "handshake_written_bytes"
            ]
        )

        require(
            client_handshake_total
            == server_handshake_total,
            (
                f"{case['name']}: "
                "handshake byte mismatch "
                f"{client_handshake_total} != "
                f"{server_handshake_total}"
            ),
        )

        tls_bio_total = (
            client_metrics[
                "transport_read_bytes"
            ]
            + client_metrics[
                "transport_written_bytes"
            ]
        )

        if (
            case["auth_family"]
            == "mtc-experimental"
        ):
            require(
                "MTC_VERIFY" in client_log,
                (
                    f"{case['name']}: "
                    "client MTC_VERIFY missing"
                ),
            )

            require(
                "MTC_VERIFY" in server_log,
                (
                    f"{case['name']}: "
                    "server MTC_VERIFY missing"
                ),
            )

        client_mtc = parse_mtc_timings(
            client_log,
            "client",
        )

        server_mtc = parse_mtc_timings(
            server_log,
            "server",
        )

        stem = (
            f"{phase}-"
            f"r{round_index:03d}-"
            f"o{order_index:02d}-"
            f"{case['name']}"
        )

        raw = root / "raw"
        raw.mkdir(
            parents=True,
            exist_ok=True,
        )

        (
            raw / f"{stem}.client.log"
        ).write_text(
            client_log,
            encoding="utf-8",
        )

        (
            raw / f"{stem}.server.log"
        ).write_text(
            server_log,
            encoding="utf-8",
        )

        shutil.copyfile(
            server_metric_path,
            raw / f"{stem}.server-metrics.json",
        )

        return {
            "phase": phase,
            "round": round_index,
            "order": order_index,

            "case_name":
                case["name"],

            "profile":
                case["profile"],

            "auth_family":
                case["auth_family"],

            "x509_chain_profile":
                case["x509_chain_profile"],

            "tree_size":
                case["tree_size"],

            "client_random":
                client_random,

            # ---------------------------------------------
            # PRIMARY CROSSOVER METRIC
            # ---------------------------------------------
            "server_certificate_bytes":
                server_certificate_bytes,

            "client_certificate_bytes":
                client_certificate_bytes,

            "certificate_total_bytes":
                certificate_total_bytes,

            # ---------------------------------------------
            # CertificateVerify, diagnostic only.
            # ---------------------------------------------
            "server_certificate_verify_bytes":
                client_metrics[
                    "server_certificate_verify_message_bytes"
                ],

            "client_certificate_verify_bytes":
                client_metrics[
                    "client_certificate_verify_message_bytes"
                ],

            # ---------------------------------------------
            # SECONDARY BYTE METRICS
            # ---------------------------------------------
            "handshake_total_bytes":
                client_handshake_total,

            "handshake_read_bytes":
                client_metrics[
                    "handshake_read_bytes"
                ],

            "handshake_written_bytes":
                client_metrics[
                    "handshake_written_bytes"
                ],

            "tls_bio_total_bytes":
                tls_bio_total,

            "tls_bio_read_bytes":
                client_metrics[
                    "transport_read_bytes"
                ],

            "tls_bio_written_bytes":
                client_metrics[
                    "transport_written_bytes"
                ],

            # ---------------------------------------------
            # NATIVE TIMINGS
            # ---------------------------------------------
            "client_handshake_wall_ms":
                client_metrics[
                    "handshake_wall_ms"
                ],

            "server_handshake_wall_ms":
                server_metrics[
                    "handshake_wall_ms"
                ],

            "client_handshake_cpu_ms":
                client_metrics[
                    "handshake_cpu_ms"
                ],

            "server_handshake_cpu_ms":
                server_metrics[
                    "handshake_cpu_ms"
                ],

            "tcp_connect_wall_ms_native":
                client_metrics.get(
                    "tcp_connect_wall_ms_native"
                ),

            "connection_establishment_wall_ms_native":
                client_metrics.get(
                    "connection_establishment_wall_ms_native"
                ),

            "client_mtc_setup_ms":
                client_mtc[
                    "client_mtc_setup_ms"
                ],

            "client_mtc_verify_ms":
                client_mtc[
                    "client_mtc_verify_ms"
                ],

            "server_mtc_setup_ms":
                server_mtc[
                    "server_mtc_setup_ms"
                ],

            "server_mtc_verify_ms":
                server_mtc[
                    "server_mtc_verify_ms"
                ],

            "success": 1,
        }

    finally:
        docker_rm()


def write_csv(path, rows, fields):
    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(rows)


def image_metadata():
    image_id = run(
        [
            "docker",
            "image",
            "inspect",
            "-f",
            "{{.Id}}",
            IMAGE,
        ]
    ).stdout.strip()

    hashes = run(
        [
            "docker", "run", "--rm",
            IMAGE,
            "cat",
            "/opt/openssl-mtc/"
            "MUTUAL_METRICS_SHA256",
        ],
        check=False,
    ).stdout.strip()

    return image_id, hashes


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--warmups",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=20260919,
    )

    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be >= 1")

    if args.warmups < 0:
        parser.error("--warmups must be >= 0")

    root = args.root

    if not root.is_absolute():
        root = REPO / root

    result_root = (
        REPO / "artifacts/results"
    )

    if not root.is_relative_to(result_root):
        raise SystemExit(
            "root must be under artifacts/results"
        )

    if root.exists() and any(root.iterdir()):
        raise SystemExit(
            f"refusing to overwrite "
            f"non-empty root: {root}"
        )

    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    cases = case_definitions()

    require(
        len(cases) == 23,
        f"expected 23 cases, got {len(cases)}",
    )

    require(
        sum(
            1
            for case in cases
            if case["auth_family"] == "x509"
        )
        == 6,
        "expected six X.509 cases",
    )

    require(
        sum(
            1
            for case in cases
            if case["auth_family"]
            == "mtc-experimental"
        )
        == 17,
        "expected seventeen MTC cases",
    )

    for case in cases:
        validate_case_files(case)

    image_id, build_hashes = (
        image_metadata()
    )

    network_reset()

    measured = []
    warmups = []

    try:
        phases = [
            ("warmup", args.warmups),
            ("measured", args.runs),
        ]

        for phase, count in phases:

            for round_index in range(
                1,
                count + 1,
            ):
                order = list(cases)

                phase_offset = (
                    1000000
                    if phase == "warmup"
                    else 0
                )

                rng = random.Random(
                    args.seed
                    + phase_offset
                    + round_index
                )

                rng.shuffle(order)

                print()
                print(
                    f"=== {phase.upper()} "
                    f"ROUND {round_index}/{count} ===",
                    flush=True,
                )

                for order_index, case in enumerate(
                    order,
                    start=1,
                ):
                    print(
                        f"{phase} "
                        f"round={round_index} "
                        f"order={order_index:02d}/23 "
                        f"case={case['name']}",
                        flush=True,
                    )

                    observation = measure_case(
                        case,
                        phase=phase,
                        round_index=round_index,
                        order_index=order_index,
                        root=root,
                    )

                    if phase == "warmup":
                        warmups.append(
                            observation
                        )
                    else:
                        measured.append(
                            observation
                        )

    finally:
        docker_rm()

        run(
            [
                "docker",
                "network",
                "rm",
                NETWORK,
            ],
            check=False,
        )

    expected_measured = (
        args.runs * len(cases)
    )

    expected_warmups = (
        args.warmups * len(cases)
    )

    require(
        len(measured) == expected_measured,
        (
            f"expected {expected_measured} "
            f"measured observations, "
            f"got {len(measured)}"
        ),
    )

    require(
        len(warmups) == expected_warmups,
        (
            f"expected {expected_warmups} "
            f"warmups, got {len(warmups)}"
        ),
    )

    fields = list(
        (measured or warmups)[0].keys()
    )

    write_csv(
        root / "observations.csv",
        measured,
        fields,
    )

    write_csv(
        root / "warmups.csv",
        warmups,
        fields,
    )

    # ========================================================
    # Certificate bytes must be invariant for every cell.
    # ========================================================

    by_case = {}

    for row in measured:
        by_case.setdefault(
            row["case_name"],
            [],
        ).append(row)

    case_summary = {}

    for name, rows in sorted(
        by_case.items()
    ):
        cert_values = sorted({
            int(r["certificate_total_bytes"])
            for r in rows
        })

        server_cert_values = sorted({
            int(r["server_certificate_bytes"])
            for r in rows
        })

        client_cert_values = sorted({
            int(r["client_certificate_bytes"])
            for r in rows
        })

        require(
            len(cert_values) == 1,
            (
                f"{name}: Certificate total "
                f"not invariant: {cert_values}"
            ),
        )

        require(
            len(server_cert_values) == 1,
            (
                f"{name}: server Certificate "
                "not invariant"
            ),
        )

        require(
            len(client_cert_values) == 1,
            (
                f"{name}: client Certificate "
                "not invariant"
            ),
        )

        handshake_values = [
            int(r["handshake_total_bytes"])
            for r in rows
        ]

        wall_values = [
            float(
                r["client_handshake_wall_ms"]
            )
            for r in rows
        ]

        case_summary[name] = {
            "count": len(rows),

            "server_certificate_bytes":
                server_cert_values[0],

            "client_certificate_bytes":
                client_cert_values[0],

            "certificate_total_bytes":
                cert_values[0],

            "handshake_total_bytes_median":
                statistics.median(
                    handshake_values
                ),

            "handshake_total_bytes_min":
                min(handshake_values),

            "handshake_total_bytes_max":
                max(handshake_values),

            "client_handshake_wall_ms_median":
                statistics.median(
                    wall_values
                ),
        }

    summary = {
        "result": "PASS",

        "experiment":
            "mutual-auth-crossover-v2",

        "measured_observations":
            len(measured),

        "warmup_observations":
            len(warmups),

        "case_count":
            len(cases),

        "x509_case_count": 6,
        "mtc_case_count": 17,

        "runs_per_case":
            args.runs,

        "warmups_per_case":
            args.warmups,

        "seed":
            args.seed,

        "primary_metric":
            "certificate_total_bytes",

        "primary_metric_definition": (
            "TLS Certificate handshake-message "
            "bytes sent by server plus TLS "
            "Certificate handshake-message bytes "
            "sent by client"
        ),

        "secondary_metrics": [
            "handshake_total_bytes",
            "tls_bio_total_bytes",
            "client_handshake_wall_ms",
            "server_handshake_wall_ms",
        ],

        "certificate_byte_invariance":
            "PASS",

        "cases":
            case_summary,
    }

    metadata = {
        "created_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "image":
            IMAGE,

        "image_id":
            image_id,

        "mutual_metrics_build_hashes":
            build_hashes,

        "openssl":
            OPENSSL,

        "tls": {
            "version": "TLS 1.3",
            "group": "X25519",
            "cipher":
                "TLS_AES_256_GCM_SHA384",
            "tickets": False,
            "resumption": False,
            "mutual_authentication": True,
        },

        "mtc_status":
            "MTC-experimental",

        "mtc_source_chain_profile":
            "ca-server",

        "x509_comparators": [
            "direct-server",
            "ca-server",
        ],

        "directional_metrics": {
            "legacy_certificate_message_bytes":
                "server Certificate message",

            "server_certificate_message_bytes":
                "server -> client Certificate",

            "client_certificate_message_bytes":
                "client -> server Certificate",
        },
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
        "=== MUTUAL AUTH CROSSOVER V2 PASS ==="
    )
    print(
        f"cases                = "
        f"{len(cases)}"
    )
    print(
        f"measured observations= "
        f"{len(measured)}"
    )
    print(
        f"warmup observations  = "
        f"{len(warmups)}"
    )
    print(
        "certificate invariance= PASS"
    )
    print(root)


if __name__ == "__main__":
    main()
