"""Four-arm TLS 1.3 X.509 study with a locally available untrusted issuer."""

import argparse
import base64
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import time
import uuid
import zlib

from run import COMMON, IMAGE, checked, command


ARMS = ("full-ordinary", "full-zlib", "elided-ordinary", "elided-zlib")
FIELDS = ("condition", "phase", "repetition", "handshake_wall_ms",
          "credential_verification_total_ms", "tls_bytes_read",
          "tls_bytes_written", "tls_bytes_total", "compression_offered",
          "sent_message", "sent_certificates", "compression_algorithm")
REFERENCES = {"ecdsa-p384": 4126, "mldsa65": 17451,
              "slhdsa192s": 52433}
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----")


def cert_der(path):
    blocks = PEM.findall(path.read_bytes())
    if len(blocks) != 1:
        raise RuntimeError(f"Expected one certificate in {path}, found {len(blocks)}")
    return base64.b64decode(re.sub(rb"\s+", b"", blocks[0]), validate=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def handshake_message(log, direction, name):
    pattern = (rf"^{re.escape(direction)} TLS 1\.3, Handshake "
               rf"\[length [0-9a-f]+\], {name}\n"
               rf"((?:    [0-9a-f ]+\n)+)")
    matches = re.findall(pattern, log, re.M | re.I)
    if len(matches) != 1:
        return None
    return bytes.fromhex(matches[0])


def client_offers_compression(log):
    message = handshake_message(log, ">>>", "ClientHello")
    if message is None or message[0] != 1:
        raise RuntimeError("Missing ClientHello trace")
    offset = 4 + 2 + 32
    offset += 1 + message[offset]  # session id
    length = int.from_bytes(message[offset:offset + 2], "big")
    offset += 2 + length  # cipher suites
    offset += 1 + message[offset]  # compression methods
    length = int.from_bytes(message[offset:offset + 2], "big")
    offset += 2
    end = offset + length
    offers = False
    while offset < end:
        kind = int.from_bytes(message[offset:offset + 2], "big")
        size = int.from_bytes(message[offset + 2:offset + 4], "big")
        offers |= kind == 27
        offset += 4 + size
    if offset != end:
        raise RuntimeError("Malformed ClientHello extensions")
    return offers


def sent_certificates(log):
    ordinary = handshake_message(log, "<<<", "Certificate")
    compressed = handshake_message(log, "<<<", "CompressedCertificate")
    if (ordinary is None) == (compressed is None):
        raise RuntimeError("Expected exactly one Certificate or CompressedCertificate")
    if ordinary is not None:
        if ordinary[0] != 11:
            raise RuntimeError("Invalid Certificate handshake type")
        body, message, algorithm = ordinary[4:], "Certificate", "none"
    else:
        if compressed[0] != 25:
            raise RuntimeError("Invalid CompressedCertificate handshake type")
        alg = int.from_bytes(compressed[4:6], "big")
        if alg != 1:
            raise RuntimeError(f"Expected zlib algorithm 1, got {alg}")
        expected = int.from_bytes(compressed[6:9], "big")
        compressed_length = int.from_bytes(compressed[9:12], "big")
        if compressed_length != len(compressed) - 12:
            raise RuntimeError("CompressedCertificate compressed length mismatch")
        try:
            body = zlib.decompress(compressed[12:])
        except zlib.error as error:
            raise RuntimeError(f"Invalid zlib CompressedCertificate: {error}") from error
        if len(body) != expected:
            raise RuntimeError("CompressedCertificate uncompressed length mismatch")
        message, algorithm = "CompressedCertificate", "zlib"
    offset = 1 + body[0]  # certificate_request_context
    length = int.from_bytes(body[offset:offset + 3], "big")
    offset += 3
    end = offset + length
    if end != len(body):
        raise RuntimeError("Certificate list length mismatch")
    certificates = []
    while offset < end:
        size = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        certificates.append(body[offset:offset + size])
        offset += size
        extensions = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2 + extensions
    if offset != end:
        raise RuntimeError("Malformed Certificate list")
    return message, algorithm, certificates


def sample(args, network, server, fixture, artifacts, cert_hashes,
           condition, phase, repetition, logs):
    elided = condition.startswith("elided-")
    wants_zlib = condition.endswith("-zlib")
    client = ["docker", "run", "--rm", "--network", network,
              "-v", f"{artifacts}:/work:ro",
              "--entrypoint", "/opt/mtc/openssl.sh", args.image,
              "s_client", "-connect", f"{server}:4433",
              "-servername", args.hostname,
              "-no-CAfile", "-no-CApath", "-no-CAstore",
              "-verifyCAfile", f"/work/{fixture.relative_to(artifacts)}/root.pem",
              "-verify_hostname", args.hostname, "-verify_return_error",
              "-no_ticket", "-lab_metrics", "-msg", *COMMON]
    if elided:
        client.extend(("-verify_untrusted",
                       f"/work/{fixture.relative_to(artifacts)}/intermediates.pem"))
        if args.runs == 1:
            client.append("-verify_untrusted_trace")
    if not wants_zlib:
        client.append("-no_rx_cert_comp")
    result = command(*client, input="", timeout=60)
    log = result.stderr + "\n" + result.stdout
    (logs / f"{condition}-{phase}-{repetition}.log").write_text(log)
    checked(result, f"{condition} {phase} {repetition}")
    if "Verify return code: 0 (ok)" not in log:
        raise RuntimeError(f"Name or chain verification failed: {condition} {phase} {repetition}")
    offered = client_offers_compression(log)
    if offered != wants_zlib:
        raise RuntimeError(f"Unexpected ClientHello compression offer: {condition}")
    message, algorithm, certs = sent_certificates(log)
    expected = [cert_hashes["leaf"]]
    if not elided:
        expected.append(cert_hashes["intermediate"])
    if [digest(cert) for cert in certs] != expected:
        raise RuntimeError(f"Wrong certificates sent: {condition} {phase} {repetition}")
    if condition == "full-zlib" and message != "CompressedCertificate":
        raise RuntimeError("Full-chain zlib arm did not send CompressedCertificate")
    if not wants_zlib and message != "Certificate":
        raise RuntimeError("Ordinary arm unexpectedly sent CompressedCertificate")
    if elided and args.runs == 1:
        evidence = re.findall(r"AUX_VERIFY_CHAIN ([012]) ([0-9a-f]{64})", log)
        if evidence != [("0", cert_hashes["leaf"]),
                        ("1", cert_hashes["intermediate"]),
                        ("2", cert_hashes["root"])]:
            raise RuntimeError(f"Validated chain differs from fixture: {condition}")
    metrics = re.findall(r"NATIVE_METRICS\s+(\{[^\n]+\})", log)
    byte_counts = re.findall(r"SSL handshake has read (\d+) bytes and written (\d+) bytes", log)
    if len(metrics) != 1 or len(byte_counts) != 1:
        raise RuntimeError("Expected one native metrics record and one TLS byte count")
    metrics = json.loads(metrics[0])
    read, written = map(int, byte_counts[0])
    return {"condition": condition, "phase": phase, "repetition": repetition,
            "handshake_wall_ms": metrics["handshake_wall_ms"],
            "credential_verification_total_ms": metrics["credential_verification_total_ms"],
            "tls_bytes_read": read, "tls_bytes_written": written,
            "tls_bytes_total": read + written, "compression_offered": offered,
            "sent_message": message, "sent_certificates": len(certs),
            "compression_algorithm": algorithm}


def percentile95(values):
    ordered = sorted(values)
    position = 0.95 * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def reference_status(profile, observed):
    expected = REFERENCES[profile]
    if observed == expected:
        return "exact"
    if profile == "ecdsa-p384" and 4125 <= observed <= 4127:
        return "ECDSA DER signature length variation; verify the trace and direction counts"
    return "mismatch"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intermediate-elision", action="store_true", required=True)
    parser.add_argument("--x509-fixture", type=Path, required=True)
    parser.add_argument("--profile", choices=tuple(REFERENCES), required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--pilot-summary", type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    artifacts = (repo / "artifacts").resolve()
    fixture = args.x509_fixture.resolve()
    output = args.output.resolve()
    if artifacts not in fixture.parents or output.parent != artifacts / "results" or output.exists():
        parser.error("Fixture must be below artifacts and output must be a new direct child of artifacts/results")
    if args.warmups < 0 or args.runs < 1:
        parser.error("Invalid warmup or measurement count")
    if args.runs > 1 and args.pilot_summary is None:
        parser.error("Full campaign requires --pilot-summary from a passing one-sample pilot")
    for name in ("server.pem", "server.key", "intermediates.pem", "root.pem", "manifest.json"):
        if not (fixture / name).is_file():
            parser.error(f"Missing fixture: {fixture / name}")
    manifest = json.loads((fixture / "manifest.json").read_text())
    if manifest.get("profile") != args.profile or manifest.get("depth", manifest.get("depth_including_root")) != 3:
        parser.error("Fixture profile or D=3 mismatch")
    ders = {"leaf": cert_der(fixture / "server.pem"),
            "intermediate": cert_der(fixture / "intermediates.pem"),
            "root": cert_der(fixture / "root.pem")}
    cert_hashes = {key: digest(value) for key, value in ders.items()}
    if not args.execute:
        print(f"PLAN: {args.profile}, four arms, X25519MLKEM768, SNI {args.hostname}, "
              f"{args.warmups} warmups + {args.runs} measurements per arm")
        return
    checked(command("docker", "info", "--format", "{{.ServerVersion}}"), "Docker daemon")
    image = json.loads(checked(command("docker", "image", "inspect", args.image), "Docker image").stdout)[0]
    client_help = checked(command("docker", "run", "--rm", "--network", "none",
                                  "--entrypoint", "/opt/mtc/openssl.sh", args.image,
                                  "s_client", "-help"), "Client help").stderr
    server_help = checked(command("docker", "run", "--rm", "--network", "none",
                                  "--entrypoint", "/opt/mtc/openssl.sh", args.image,
                                  "s_server", "-help"), "Server help").stderr
    if not all(name in client_help for name in ("verify_untrusted", "verify_untrusted_trace",
                                                "verifyCAfile", "lab_metrics", "no_rx_cert_comp")):
        raise RuntimeError("Image lacks the untrusted issuer or measurement option; rebuild the experiment image")
    if "cert_comp" not in server_help:
        raise RuntimeError("Image lacks server certificate compression")
    if args.pilot_summary:
        pilot = json.loads(args.pilot_summary.read_text())
        if not pilot.get("pilot_pass") or pilot.get("image_id") != image["Id"] \
                or pilot.get("certificate_sha256") != cert_hashes \
                or pilot.get("profile") != args.profile or pilot.get("hostname") != args.hostname:
            raise RuntimeError("Pilot did not pass or image/fixture/configuration changed")
    network = "mt-x509-elision-" + uuid.uuid4().hex[:12]
    server = network + "-server"
    checked(command("docker", "network", "create", network), "Create network")
    try:
        output.mkdir()
        logs = output / "logs"
        logs.mkdir()
        (output / "config.json").write_text(json.dumps({
            "image": args.image, "image_id": image["Id"], "profile": args.profile,
            "hostname": args.hostname, "openssl_group": "X25519MLKEM768",
            "tls_version": "TLS1.3", "x509_depth": 3,
            "fixture": str(fixture.relative_to(repo)), "certificate_sha256": cert_hashes,
            "trust_anchor": "root.pem only", "auxiliary_untrusted": "intermediates.pem",
            "warmups": args.warmups, "measured": args.runs,
            "conditions": ARMS}, indent=2) + "\n")
        rows = []
        with (output / "samples.csv").open("x", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            for phase, count in (("warmup", args.warmups), ("measured", args.runs)):
                for repetition in range(1, count + 1):
                    ordered = ARMS[(repetition - 1) % 4:] + ARMS[:(repetition - 1) % 4]
                    for condition in ordered:
                        try:
                            server_cmd = ["docker", "run", "-d", "--name", server,
                                          "--network", network, "-v", f"{artifacts}:/work:ro",
                                          "--entrypoint", "/opt/mtc/openssl.sh", args.image,
                                          "s_server", "-accept", "4433", "-cert",
                                          f"/work/{fixture.relative_to(artifacts)}/server.pem",
                                          "-key", f"/work/{fixture.relative_to(artifacts)}/server.key"]
                            if condition.startswith("full-"):
                                server_cmd.extend(("-cert_chain", f"/work/{fixture.relative_to(artifacts)}/intermediates.pem"))
                            server_cmd.extend(("-num_tickets", "0", "-www", "-cert_comp", *COMMON))
                            checked(command(*server_cmd), "Start server")
                            time.sleep(1)
                            state = checked(command("docker", "inspect", "--format",
                                                    "{{.State.Running}}", server), "Inspect server").stdout.strip()
                            if state != "true":
                                raise RuntimeError(f"Server exited: {condition}")
                            server_start_log = command("docker", "logs", server)
                            if condition == "full-zlib" and "Error compressing certs" in (
                                    server_start_log.stdout + server_start_log.stderr):
                                raise RuntimeError("Full-chain server could not precompress its certificate")
                            row = sample(args, network, server, fixture, artifacts,
                                         cert_hashes, condition, phase, repetition, logs)
                            rows.append(row)
                            writer.writerow(row)
                            stream.flush()
                            print(f"{condition} {phase} {repetition}: {row['handshake_wall_ms']} ms, "
                                  f"{row['tls_bytes_total']} bytes, {row['sent_message']}", flush=True)
                        finally:
                            server_log = command("docker", "logs", server)
                            (logs / f"{condition}-{phase}-{repetition}-server.log").write_text(
                                server_log.stdout + server_log.stderr)
                            command("docker", "rm", "-f", server)
        measured = {arm: [r for r in rows if r["condition"] == arm and r["phase"] == "measured"]
                    for arm in ARMS}
        summary = {"profile": args.profile, "hostname": args.hostname,
                   "image_id": image["Id"], "certificate_sha256": cert_hashes,
                   "reference_total_bytes": REFERENCES[args.profile], "arms": {}}
        for arm, selected in measured.items():
            summary["arms"][arm] = {
                "n": len(selected),
                "tls_bytes_read_median": statistics.median(r["tls_bytes_read"] for r in selected),
                "tls_bytes_written_median": statistics.median(r["tls_bytes_written"] for r in selected),
                "tls_bytes_total_median": statistics.median(r["tls_bytes_total"] for r in selected),
                "handshake_wall_ms_median": statistics.median(r["handshake_wall_ms"] for r in selected),
                "handshake_wall_ms_p95": percentile95([r["handshake_wall_ms"] for r in selected]),
                "sent_messages": sorted({r["sent_message"] for r in selected}),
            }
        baseline = summary["arms"]["full-ordinary"]["tls_bytes_total_median"]
        elided = summary["arms"]["elided-ordinary"]["tls_bytes_total_median"]
        summary["intermediate_elision_savings_pct"] = 100 * (baseline - elided) / baseline
        summary["reference_status"] = reference_status(args.profile, baseline)
        summary["pilot_pass"] = (args.runs == 1 and summary["reference_status"] != "mismatch"
                                 and all(len(selected) == 1 for selected in measured.values()))
        summary["reference_match"] = summary["reference_status"] != "mismatch"
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        if not summary["reference_match"]:
            raise RuntimeError(f"Full-chain reference mismatch: observed {baseline}, expected {REFERENCES[args.profile]}; inspect traces before scaling or reporting")
    finally:
        command("docker", "rm", "-f", server)
        command("docker", "network", "rm", network)
