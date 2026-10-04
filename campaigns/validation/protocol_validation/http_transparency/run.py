#!/usr/bin/env python3
"""Optional HTTP transparency validation layered over the Chromium harness."""

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[4]
HARNESS_DIR = REPO / "campaigns/browser_client/chromium_mtc"
MTC = REPO / "src/mtc"
sys.path[:0] = [str(HARNESS_DIR), str(MTC)]

import http_log_integration as bridge
import rp_updater
from rp_state import RPStateStore
from trusted_subtrees import decode_trusted_subtrees

CASES = {
    "http-positive": "authenticated HTTP snapshot and subtree proofs produce MTS1 consumed by Chromium",
    "invalid-subtree-proof": "a corrupted first-landmark proof produces the validated empty-prefix MTS1 fallback",
    "invalid-snapshot": "a corrupted MCP2 snapshot is rejected before trusted state publication",
}


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def plan():
    print("HTTP transparency is an optional subvalidation; stages 05-120 are unchanged.")
    for name, description in CASES.items():
        print(f"{name}: {description}")
    print("Deferred: authenticated checkpoint evolution 8->16 via /proof/consistency.")


def command(case, arguments):
    if case == "http-positive":
        base = ["python3", "campaigns/browser_client/chromium_mtc/http_log_integration.py"]
    else:
        base = ["python3", "campaigns/validation/protocol_validation/http_transparency/run.py",
                "_negative", case]
    return base + list(arguments)


def show(case, arguments):
    print(shlex.join(command(case, arguments)))


def status():
    checker = bridge.DEFAULT_CHECKER
    ready = checker.is_file() and os.access(checker, os.X_OK)
    print(f"checker={checker}: {'ready' if ready else 'missing'}")
    roots = sorted((REPO / "artifacts/results").glob("http-transparency-*"))
    print(f"recorded_negative_results={len(roots)}")
    print("Chromium is required only for http-positive.")


def negative_parser(case, argv):
    parser = argparse.ArgumentParser(prog=f"http-transparency run {case}")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--log-url")
    source.add_argument("--log-data", type=Path)
    parser.add_argument("--log-host", default="127.0.0.1")
    parser.add_argument("--log-port", type=int, default=0)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--trusted-authority", type=Path, required=True)
    parser.add_argument("--checker", type=Path, default=bridge.DEFAULT_CHECKER)
    parser.add_argument("--landmarks", type=Path)
    parser.add_argument("--log-number", type=int)
    parser.add_argument("--now", type=int, default=int(time.time()))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if case == "invalid-subtree-proof" and (args.landmarks is None or args.log_number is None):
        parser.error("invalid-subtree-proof requires --landmarks and --log-number")
    if args.log_number is not None and not 0 < args.log_number < 1 << 16:
        parser.error("--log-number must be in 1..65535")
    if case == "invalid-snapshot" and args.log_data is None:
        parser.error("invalid-snapshot requires --log-data so the corrupted copy is served")
    return args


@contextmanager
def corrupt_subtree_response(records):
    original = rp_updater._get
    changed = {"value": False}

    def corrupted(base_url, path, binary=False):
        value = original(base_url, path, binary=binary)
        digest, size = bridge.response_digest(value)
        record = {"method": "GET", "path": path, "response_sha256": digest,
                  "response_bytes": size, "corrupted_for_validation": False}
        if path.startswith("/proof/subtree?") and not changed["value"]:
            value = dict(value)
            field = "proof" if value.get("proof") else "hash"
            if field == "proof":
                value[field] = list(value[field])
                value[field][0] = ("00" if value[field][0][:2] != "00" else "01") + value[field][0][2:]
            else:
                value[field] = ("00" if value[field][:2] != "00" else "01") + value[field][2:]
            changed["value"] = True
            record["corrupted_for_validation"] = True
        records.append(record)
        return value

    rp_updater._get = corrupted
    try:
        yield changed
    finally:
        rp_updater._get = original


def validate_negative_outcome(case, rp_state, rejected, proof_corrupted):
    current = RPStateStore(rp_state).load_current()
    generations = rp_state / "generations"
    published = sorted(generations.iterdir()) if generations.exists() else []

    if case == "invalid-subtree-proof":
        if not proof_corrupted:
            raise ValueError("no subtree proof response was available to corrupt")
        if rejected is not None or current is None or len(published) != 1:
            raise ValueError("invalid subtree proof did not publish the validated fallback state")
        mts1 = (rp_state / "current" / "trusted-subtrees.mts1").resolve(strict=True)
        trusted = decode_trusted_subtrees(mts1.read_bytes())
        if trusted:
            raise ValueError("corrupted first-landmark subtree was incorporated into MTS1")
        return {
            "expected_rejection": False,
            "rejection": None,
            "rp_current_published": True,
            "rp_generation_published": True,
            "trusted_subtree_count": 0,
            "fallback": "empty-complete-landmark-prefix",
        }

    unpublished = current is None and not published
    if rejected is None or not unpublished:
        raise ValueError("invalid snapshot did not fail before trusted state publication")
    return {
        "expected_rejection": True,
        "rejection": rejected,
        "rp_current_published": False,
        "rp_generation_published": False,
    }


def run_negative(case, args):
    default = REPO / "artifacts/results" / f"http-transparency-{case}-{stamp()}"
    output = (args.output or default).resolve()
    results = (REPO / "artifacts/results").resolve()
    if not output.is_relative_to(results) or output.exists():
        raise ValueError("--output must be a new directory below artifacts/results")
    output.mkdir(parents=True)
    rp_state = bridge.require_empty_rp_state(output / "rp-state")
    snapshot = bridge.require_file(args.snapshot, "snapshot")
    authority = bridge.require_file(args.trusted_authority, "trusted authority")
    checker = bridge.require_file(args.checker, "snapshot checker")
    if not os.access(checker, os.X_OK):
        raise ValueError("snapshot checker is not executable")

    served_snapshot = snapshot
    if case == "invalid-snapshot":
        data = bytearray(snapshot.read_bytes())
        if not data:
            raise ValueError("snapshot is empty")
        data[-1] ^= 1
        served_snapshot = output / "invalid-snapshot.mcp2"
        served_snapshot.write_bytes(data)

    service = (nullcontext(bridge.require_local_http_url(args.log_url))
               if args.log_url else bridge.local_log_service(
                   args.log_host, args.log_port, args.log_data, served_snapshot, output))
    requests = []
    rejected = None
    proof_corrupted = False
    with service as base_url:
        try:
            if case == "invalid-snapshot":
                with bridge.audit_updater_get(requests):
                    rp_updater.fetch_and_advance_checkpoint(base_url, authority, checker)
            else:
                sequence = bridge.read_landmark_sequence(args.landmarks, args.now)
                with corrupt_subtree_response(requests) as changed:
                    rp_updater.update_and_publish(
                        base_url, authority, checker, rp_state,
                        args.log_number, sequence, args.now)
                proof_corrupted = changed["value"]
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            rejected = str(error) or type(error).__name__

    if case == "invalid-snapshot" and not any(item["path"] == "/snapshot" for item in requests):
        raise ValueError("invalid snapshot was not fetched over HTTP")

    outcome = validate_negative_outcome(
        case, rp_state, rejected, proof_corrupted)
    evidence = {
        "case": case, "status": "PASS", "requests": requests,
        "inputs": {
            "snapshot": bridge.artifact_record(snapshot),
            "trusted_authority": bridge.artifact_record(authority),
            "checker": bridge.artifact_record(checker),
        },
        **outcome,
    }
    (output / "result.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("Result directory: " + str(output))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] == "plan":
        plan()
        return 0
    action = argv.pop(0)
    if action == "status":
        status()
        return 0
    if action == "build-checker":
        return subprocess.run([sys.executable, str(MTC / "build_check_snapshot.py"), *argv]).returncode
    if action in ("show", "run", "_negative"):
        if not argv or argv[0] not in CASES:
            raise ValueError("case must be one of: " + ", ".join(CASES))
        case = argv.pop(0)
        if action == "show":
            show(case, argv)
            return 0
        if action == "run" and case == "http-positive":
            return bridge.main(argv)
        return run_negative(case, negative_parser(case, argv))
    raise ValueError("usage: run.py plan|status|build-checker|show CASE|run CASE")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("ERROR: " + (str(error) or type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
