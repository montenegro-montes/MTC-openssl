#!/usr/bin/env python3
"""Native/PCAP validation pq-only Native <-> PCAP measurement driver.

This is an instrumentation-validation driver, not an authentication
performance benchmark. Native OpenSSL timings remain the primary timing
measurements; PCAP provides independent on-wire observations.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import re
import shutil
import subprocess
import time
from pathlib import Path

from pcap_capture import observation


SCENARIO = "pq"
PORT = 4434
OPENSSL = "/opt/measurement/openssl.sh"
FIXTURE = Path(
    os.environ["MEASUREMENT_FIXTURE_ROOT"]
)


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fields = list(rows[0])
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


NATIVE_FIELDS = ("tcp_connect_wall_ms_native", "handshake_wall_ms", "connection_establishment_wall_ms_native")


def native_failure(stderr, keylog=None):
    """Use existing diagnostic prefixes; never infer handshake completion."""
    result = {name: None for name in NATIVE_FIELDS}
    errors = []
    def records(prefix):
        found = []
        for line in stderr.splitlines():
            if line.startswith(prefix + " "):
                try:
                    value = json.loads(line.split(" ", 1)[1])
                    if not isinstance(value, dict): raise ValueError()
                    found.append(value)
                except ValueError: errors.append(prefix + " diagnostic incomplete or malformed")
        return found
    connection = records("NATIVE_CONNECTION_METRICS")
    completed = records("PROFILE_METRICS")
    if len(connection) == 1:
        value = connection[0].get("tcp_connect_wall_ms_native")
        if isinstance(value, (float,int)) and not isinstance(value,bool) and math.isfinite(value) and value >= 0:
            result["tcp_connect_wall_ms_native"] = value
    if completed:
        raise RuntimeError("Process failed after PROFILE_METRICS: not an incomplete TLS outcome")
    randoms = set()
    if keylog is not None and keylog.is_file():
        for line in keylog.read_text().splitlines():
            if not line or line.startswith("#"): continue
            parts = line.split()
            if len(parts) != 3 or not re.fullmatch("[0-9a-fA-F]{64}",parts[1]):
                raise RuntimeError("Malformed failed-attempt keylog identity")
            randoms.add(parts[1].lower())
    if len(randoms)>1: raise RuntimeError("Ambiguous failed-attempt client_random")
    return dict(result,client_random=next(iter(randoms),None),diagnostic_errors=errors)


def run_client(command, timeout):
    try:
        return subprocess.run(command,input="GET / HTTP/1.0\r\n\r\n",text=True,capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as error:
        def text(value):return value.decode(errors="replace") if isinstance(value,bytes) else (value or "")
        return subprocess.CompletedProcess(command,124,text(error.stdout),text(error.stderr)+"\nVALIDATION_TIMEOUT")


def server_metric(out: Path, client_random: str) -> dict:
    paths = list(out.glob(f"server-*/{client_random}.json"))
    if len(paths) != 1:
        raise RuntimeError(
            f"Expected exactly one server metric for {client_random}; "
            f"found {len(paths)}"
        )
    value = json.loads(paths[0].read_text())
    shutil.copyfile(paths[0], out / "server-metrics" / paths[0].name)
    return value


def client_args(host: str, keylog: Path | None) -> list[str]:
    args = [
        OPENSSL,
        "s_client",
        "-connect", f"{host}:{PORT}",
        "-servername", "server",
        "-verify_hostname", "server",
        "-verify_return_error",
        "-tls1_3",
        "-groups", "X25519",
        "-ciphersuites", "TLS_AES_256_GCM_SHA384",
        "-no_ticket",
        "-ign_eof",
        "-lab_metrics",
        "-CAfile", str(FIXTURE / "root.pem"),
    ]
    if keylog is not None:
        args += ["-keylogfile", str(keylog)]
    return args


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--failure-aware", action="store_true", help="Full constrained reliability outcomes only")
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--host", default="server")
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--scenarios", nargs="+", choices=[SCENARIO],
                        default=[SCENARIO])
    args = parser.parse_args()

    if args.runs < 1 or args.warmup < 0:
        parser.error("runs >= 1; warmup >= 0")

    run_root = Path(os.environ["MEASUREMENT_RUN_ROOT"])
    campaign_id = os.environ["MEASUREMENT_CAMPAIGN_ID"]
    seed = int(os.environ["MEASUREMENT_SEED"])

    if seed != args.seed:
        raise RuntimeError("MEASUREMENT_SEED and --seed disagree")

    out = run_root / campaign_id
    out.mkdir(exist_ok=True)
    (out / "logs").mkdir()
    (out / "server-metrics").mkdir()

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

    metadata = {
        "experiment": "native-pcap-validation",
        "purpose": "instrumentation validation; not authentication performance",
        "scenario": SCENARIO,
        "image_id": args.image_id,
        "seed": seed,
        "runs": args.runs,
        "warmup": args.warmup,
        "fixture": str(FIXTURE),
        "tls": "1.3",
        "group": "X25519",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "server_authentication_only": True,
        "tickets": False,
        "pcap_enabled": os.environ.get("MEASUREMENT_PCAP") == "1",
        "timing_domains": {
            "native": [
                "tcp_connect_wall_ms_native",
                "handshake_wall_ms",
                "connection_establishment_wall_ms_native",
            ],
            "pcap": [
                "tcp_connect_wall_ms",
                "tls_from_pcap_wall_ms",
                "connection_handshake_wall_ms",
            ],
            "difference": "native_minus_pcap",
        },
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    if args.failure_aware and os.environ.get("VALIDATION_NETWORK_FAMILY") != "combined":
        raise RuntimeError("Failure-aware mode is restricted to constrained")
    failures: list[dict] = []
    failure_fields = ["campaign_id","round_id","round","scenario","order_in_round","is_warmup","seed","success","failure_reason","timeout","returncode","client_random",*NATIVE_FIELDS,"diagnostic_errors"]
    with (out / "failures.csv").open("w", newline="") as stream:
        csv.DictWriter(stream,fieldnames=failure_fields).writeheader()
    measured_rows: list[dict] = []
    warmup_rows: list[dict] = []
    rng = random.Random(seed)

    def captured_sample(
        round_number: int,
        order: int,
        warm: bool,
        capture_keylog: Path | None,
    ) -> None:
        started = time.perf_counter()
        result = run_client(client_args(args.host, capture_keylog),
                            float(os.environ.get("HANDSHAKE_TIMEOUT_SECONDS","30")) if args.failure_aware else 20)
        process_wall_ms = (time.perf_counter() - started) * 1000

        prefix = "warmup" if warm else "sample"
        log_path = out / "logs" / f"{prefix}-{round_number:04d}-{SCENARIO}.log"
        log = result.stdout + result.stderr
        log_path.write_text(log)

        values = re.findall(r"^PROFILE_METRICS (\{.*\})$", result.stderr, re.M)
        if result.returncode != 0:
            diagnostic = native_failure(result.stderr,capture_keylog)
            reason = "timeout" if result.returncode == 124 else "tls_error"
            failure = dict(campaign_id=campaign_id, round_id=round_number+1,round=round_number,
                           scenario=SCENARIO,order_in_round=order+1,is_warmup=int(warm),seed=seed,
                           success=0,failure_reason=reason,timeout=int(reason=="timeout"),returncode=result.returncode,
                           **diagnostic)
            failures.append(failure)
            write_csv(out / "failures.csv",failures)
            if capture_keylog is not None:
                directory = capture_keylog.parent
                (directory/"tls-status.json").write_text(json.dumps(dict(status="TLS_MEASUREMENT_FAILURE",failure_reason=reason,returncode=result.returncode))+"\n")
                (directory/"native-timing.json").write_text(json.dumps(dict(campaign_id=campaign_id,round_id=round_number+1,scenario=SCENARIO,is_warmup=0,tls_status="TLS_MEASUREMENT_FAILURE",**diagnostic))+"\n")
            if not args.failure_aware:raise RuntimeError("Native/PCAP validation pq handshake failed")
            return
        if len(values) != 1:
            raise RuntimeError("Expected exactly one PROFILE_METRICS record")
        if "HTTP/1.0 200" not in log:
            raise RuntimeError("Missing successful HTTP response")
        if "Verify return code: 0 (ok)" not in log:
            raise RuntimeError("X.509 authentication verification missing")

        client = json.loads(values[0])
        client_random = client["client_random"]

        if not re.fullmatch(r"[0-9a-f]{64}", client_random):
            raise RuntimeError("Invalid client_random correlation value")

        server = server_metric(out, client_random)

        for side, metric in (("client", client), ("server", server)):
            if metric["side"] != side:
                raise RuntimeError(f"{side} metric side mismatch")
            if metric["client_random"] != client_random:
                raise RuntimeError(f"{side} client_random mismatch")
            if not metric["profile_valid"]:
                raise RuntimeError(f"{side} profile metric invalid")
            if metric["reused"]:
                raise RuntimeError(f"{side} reports reused connection")
            if metric["detail"]:
                raise RuntimeError(f"{side} unexpected PROFILE_DETAIL")
            if metric["server_cert_type"] != 0:
                raise RuntimeError(f"{side} expected X.509 certificate")

        if (
            client["certificate_message_bytes"]
            != server["certificate_message_bytes"]
        ):
            raise RuntimeError("Certificate message size mismatch")

        if (
            client["certificate_verify_message_bytes"]
            != server["certificate_verify_message_bytes"]
        ):
            raise RuntimeError("CertificateVerify size mismatch")

        if not client["certificate_verify_message_bytes"]:
            raise RuntimeError("Missing CertificateVerify")

        for field in (
            "tcp_connect_wall_ms_native",
            "handshake_wall_ms",
            "connection_establishment_wall_ms_native",
        ):
            value = client.get(field)
            if not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value) or value < 0:
                raise RuntimeError(f"Missing or invalid native timing: {field}")

        row = {
            "campaign_id": campaign_id,
            "round_id": round_number + 1,
            "round": round_number,
            "order": order,
            "order_in_round": order + 1,
            "scenario_order": order + 1,
            "scenario": SCENARIO,
            "seed": seed,
            "is_warmup": int(warm),
            "client_random": client_random,
            "handshake_wall_ms": client["handshake_wall_ms"],
            "tcp_connect_wall_ms_native":
                client["tcp_connect_wall_ms_native"],
            "connection_establishment_wall_ms_native":
                client["connection_establishment_wall_ms_native"],
            "handshake_client_cpu_ms": client["handshake_cpu_ms"],
            "handshake_server_cpu_ms": server["handshake_cpu_ms"],
            "transport_read_bytes": client["transport_read_bytes"],
            "transport_written_bytes": client["transport_written_bytes"],
            "certificate_message_bytes":
                client["certificate_message_bytes"],
            "certificate_verify_bytes":
                client["certificate_verify_message_bytes"],
            "client_process_http_wall_ms": process_wall_ms,
        }

        if warm:
            warmup_rows.append(row)
            write_csv(out / "warmups.csv", warmup_rows)
        else:
            measured_rows.append(row)
            write_csv(out / "samples.csv", measured_rows)

    def sample(round_number: int, order: int, warm: bool) -> None:
        with observation(
            out,
            SCENARIO,
            round_number,
            order,
            warm,
            PORT,
        ) as keylog:
            captured_sample(round_number, order, warm, keylog)

    for warm, rounds in ((True, args.warmup), (False, args.runs)):
        for round_number in range(rounds):
            # Keep the paired-round ordering contract explicit even though
            # Native/PCAP validation intentionally contains only one scenario.
            order = [SCENARIO]
            rng.shuffle(order)
            sample(round_number, 0, warm)
            print(
                "warmup" if warm else "round",
                round_number + 1,
                flush=True,
            )


if __name__ == "__main__":
    main()
