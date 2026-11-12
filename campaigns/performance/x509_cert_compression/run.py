#!/usr/bin/env python3
"""Compare TLS 1.3 X.509 Certificate and CompressedCertificate in MT.

Uses the same profile fixture, X25519MLKEM768 group and cipher in both
conditions. Docker startup is outside the instrumented TLS handshake interval.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import time
import uuid


IMAGE = "mt-tls-mtc-cert-comp-pq:local"
FIELDS = ("condition", "phase", "repetition", "handshake_wall_ms",
          "credential_verification_total_ms", "tls_bytes_read",
          "tls_bytes_written", "tls_bytes_total")
COMMON = ("-tls1_3", "-groups", "X25519MLKEM768", "-ciphersuites",
          "TLS_AES_256_GCM_SHA384")


def command(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, **kwargs)


def checked(result, context):
    if result.returncode:
        raise RuntimeError(f"{context}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def sample(image, network, server, fixture, artifacts, hostname, condition, phase, repetition, log_dir):
    client = ["docker", "run", "--rm", "--network", network,
              "-v", f"{artifacts}:/work:ro",
              "--entrypoint", "/opt/mtc/openssl.sh", image,
              "s_client", "-connect", f"{server}:4433",
              "-servername", hostname,
              "-CAfile", f"/work/{fixture.relative_to(artifacts)}/root.pem",
              "-verify_hostname", hostname, "-verify_return_error",
              "-no_ticket", "-lab_metrics", "-msg", *COMMON]
    if condition == "ordinary":
        client.append("-no_rx_cert_comp")
    result = command(*client, input="", timeout=30)
    log = result.stderr + "\n" + result.stdout
    (log_dir / f"{condition}-{phase}-{repetition}.log").write_text(log)
    checked(result, f"{condition} {phase} {repetition}")
    if "Verify return code: 0 (ok)" not in log:
        raise RuntimeError(f"TLS verification failed: {condition} {phase} {repetition}")
    compressed = bool(re.search(r"\bCompressedCertificate\b", log, re.I))
    if compressed != (condition == "compressed"):
        raise RuntimeError(f"Certificate compression was not confirmed: {condition} {phase} {repetition}")
    records = re.findall(r"NATIVE_METRICS\s+(\{[^\n]+\})", log)
    if len(records) != 1:
        raise RuntimeError("Expected exactly one NATIVE_METRICS record")
    metrics = json.loads(records[0])
    byte_matches = re.findall(r"SSL handshake has read (\d+) bytes and written (\d+) bytes", log)
    if len(byte_matches) != 1:
        raise RuntimeError("Expected exactly one OpenSSL handshake byte count")
    read, written = map(int, byte_matches[0])
    return {"condition": condition, "phase": phase, "repetition": repetition,
            "handshake_wall_ms": metrics["handshake_wall_ms"],
            "credential_verification_total_ms": metrics["credential_verification_total_ms"],
            "tls_bytes_read": read, "tls_bytes_written": written,
            "tls_bytes_total": read + written}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x509-fixture", type=Path, required=True,
                        help="Existing D=3 chain below artifacts")
    parser.add_argument("--profile", choices=("mldsa65", "slhdsa192s"), required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="New directory below artifacts/results")
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    artifacts = (repo / "artifacts").resolve()
    fixture = args.x509_fixture.resolve()
    output = args.output.resolve()
    if artifacts not in fixture.parents:
        parser.error("--x509-fixture must be below artifacts")
    if output.parent != artifacts / "results" or output.exists():
        parser.error("--output must be a new direct child of artifacts/results")
    if args.warmups < 0 or args.runs < 1:
        parser.error("--warmups must be nonnegative and --runs must be positive")
    for name in ("server.pem", "server.key", "intermediates.pem", "root.pem"):
        if not (fixture / name).is_file():
            parser.error(f"Missing fixture: {fixture / name}")
    manifest = json.loads((fixture / "manifest.json").read_text())
    if manifest.get("profile") != args.profile or manifest.get("depth", manifest.get("depth_including_root")) != 3:
        parser.error("Fixture manifest does not match the requested profile and D=3")
    if not args.execute:
        print(f"PLAN: {args.profile} X.509 D=3, X25519MLKEM768, ordinary/compressed, "
              f"{args.warmups} warmups + {args.runs} measured connections per condition")
        return
    checked(command("docker", "info", "--format", "{{.ServerVersion}}"), "Docker daemon")
    image_info = json.loads(checked(command("docker", "image", "inspect", args.image),
                                    "Docker image").stdout)[0]
    help_text = checked(command("docker", "run", "--rm", "--network", "none",
                                "--entrypoint", "/opt/mtc/openssl.sh", args.image,
                                "s_client", "-help"), "OpenSSL help").stderr
    if not all(option in help_text for option in ("lab_metrics", "no_rx_cert_comp")):
        raise RuntimeError("Image lacks required timing or certificate compression controls")
    server_help = checked(command("docker", "run", "--rm", "--network", "none",
                                  "--entrypoint", "/opt/mtc/openssl.sh", args.image,
                                  "s_server", "-help"), "OpenSSL server help").stderr
    if "cert_comp" not in server_help:
        raise RuntimeError("Image lacks server certificate compression")
    network = "mt-x509-cert-comp-" + uuid.uuid4().hex[:12]
    server = network + "-server"
    checked(command("docker", "network", "create", network), "Create network")
    try:
        output.mkdir()
        logs = output / "logs"
        logs.mkdir()
        (output / "config.json").write_text(json.dumps({
            "image": args.image, "image_id": image_info["Id"],
            "x509_fixture": str(fixture.relative_to(repo)),
            "certificate_sha256": hashlib.sha256((fixture / "server.pem").read_bytes()).hexdigest(),
            "intermediates_sha256": hashlib.sha256((fixture / "intermediates.pem").read_bytes()).hexdigest(),
            "root_sha256": hashlib.sha256((fixture / "root.pem").read_bytes()).hexdigest(),
            "profile": args.profile, "hostname": args.hostname, "x509_depth": 3,
            "openssl_group": "X25519MLKEM768", "warmups": args.warmups,
            "measured": args.runs, "conditions": ["ordinary", "compressed"]}, indent=2) + "\n")
        rows = []
        with (output / "samples.csv").open("x", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            for phase, count in (("warmup", args.warmups), ("measured", args.runs)):
                for repetition in range(1, count + 1):
                    conditions = ("ordinary", "compressed") if repetition % 2 else ("compressed", "ordinary")
                    for condition in conditions:
                        try:
                            checked(command("docker", "run", "-d", "--name", server,
                                            "--network", network, "-v", f"{artifacts}:/work:ro",
                                            "--entrypoint", "/opt/mtc/openssl.sh", args.image,
                                            "s_server", "-accept", "4433", "-cert",
                                        f"/work/{fixture.relative_to(artifacts)}/server.pem",
                                        "-key", f"/work/{fixture.relative_to(artifacts)}/server.key",
                                        "-cert_chain", f"/work/{fixture.relative_to(artifacts)}/intermediates.pem",
                                            "-num_tickets", "0", "-www", "-cert_comp", *COMMON), "Start server")
                            time.sleep(1)
                            state = checked(command("docker", "inspect", "--format",
                                                    "{{.State.Running}} {{.State.ExitCode}}", server),
                                            "Inspect server").stdout.strip()
                            server_log = command("docker", "logs", server)
                            server_log_text = server_log.stdout + server_log.stderr
                            (logs / f"{condition}-{phase}-{repetition}-server.log").write_text(server_log_text)
                            if "Error compressing certs" in server_log_text:
                                raise RuntimeError(f"Server could not precompress certificate: {server_log_text.strip()}")
                            if not state.startswith("true "):
                                raise RuntimeError(f"Server exited before client connection ({state}): "
                                                   f"{server_log_text.strip()}")
                            row = sample(args.image, network, server, fixture, artifacts,
                                         args.hostname,
                                         condition, phase, repetition, logs)
                            writer.writerow(row)
                            stream.flush()
                            rows.append(row)
                            print(f"{condition} {phase} {repetition}: {row['handshake_wall_ms']} ms, "
                                  f"{row['tls_bytes_read']} bytes read", flush=True)
                        finally:
                            server_log = command("docker", "logs", server)
                            (logs / f"{condition}-{phase}-{repetition}-server.log").write_text(
                                server_log.stdout + server_log.stderr)
                            command("docker", "rm", "-f", server)
        summary = {}
        for condition in ("ordinary", "compressed"):
            selected = [r for r in rows if r["condition"] == condition and r["phase"] == "measured"]
            summary[condition] = {field: {"median": statistics.median(float(r[field]) for r in selected),
                                          "mean": statistics.mean(float(r[field]) for r in selected)}
                                  for field in FIELDS[3:]}
        by_condition = {condition: {r["repetition"]: r for r in rows
                                    if r["condition"] == condition and r["phase"] == "measured"}
                        for condition in ("ordinary", "compressed")}
        summary["paired_compressed_minus_ordinary"] = {
            field: {"median": statistics.median(
                        float(by_condition["compressed"][i][field])
                        - float(by_condition["ordinary"][i][field]) for i in range(1, args.runs + 1)),
                    "mean": statistics.mean(
                        float(by_condition["compressed"][i][field])
                        - float(by_condition["ordinary"][i][field]) for i in range(1, args.runs + 1))}
            for field in FIELDS[3:]}
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    finally:
        command("docker", "rm", "-f", server)
        command("docker", "network", "rm", network)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"ERROR: {error}") from None
