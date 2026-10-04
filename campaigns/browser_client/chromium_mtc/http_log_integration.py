#!/usr/bin/env python3
"""One-shot HTTP log -> RP state -> Chromium MTC integration experiment."""

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
MTC = REPO / "src" / "mtc"
DEFAULT_CHECKER = REPO / ".mt-state" / "mtc" / "check_snapshot"
sys.path[:0] = [str(HERE), str(MTC)]

import browser_validation as bv
from landmarks import Landmark, decode_publication
import rp_updater
from rp_state import RPStateStore


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def require_file(path, label):
    path = Path(path).resolve()
    bv.require(path.is_file() and not path.is_symlink(), f"{label} must be a regular file")
    return path


def read_landmark_sequence(path, now):
    latest, records = decode_publication(require_file(path, "landmark publication").read_bytes(), now)
    numbered = [Landmark(latest - offset, tree_size, expiration)
                for offset, (tree_size, expiration) in enumerate(records)]
    sequence = list(reversed(numbered))
    bv.require(sequence and sequence[0] == Landmark(0, 0, 0),
               "landmark publication does not contain the complete sequence through landmark zero")
    return sequence


def response_digest(value):
    if isinstance(value, bytes):
        data = value
    else:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest(), len(data)


@contextmanager
def audit_updater_get(records):
    original = rp_updater._get

    def audited(base_url, path, binary=False):
        started = utc_now()
        value = original(base_url, path, binary=binary)
        digest, size = response_digest(value)
        records.append({
            "method": "GET",
            "path": path,
            "started": started,
            "completed": utc_now(),
            "response_sha256": digest,
            "response_bytes": size,
        })
        return value

    rp_updater._get = audited
    try:
        yield
    finally:
        rp_updater._get = original


def managed_log_base_url(ready, host, requested_port):
    try:
        address = json.loads(Path(ready).read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    bv.require(isinstance(address, dict),
               "read-only HTTP transparency log reported an invalid address")
    port = address.get("port")
    bv.require(address.get("host") == host and type(port) is int
               and 0 < port < 65536
               and (requested_port == 0 or port == requested_port),
               "read-only HTTP transparency log reported an invalid address")
    return f"http://{host}:{port}/"


@contextmanager
def local_log_service(host, port, log_data, snapshot, output):
    log_data = Path(log_data).resolve()
    bv.require(log_data.is_dir() and not log_data.is_symlink(),
               "log data must be an existing non-symlink directory")
    ready = output / "log-service-ready.json"
    command = [
        sys.executable, "-B", str(MTC / "log_service.py"),
        "--host", host, "--port", str(port),
        "--data", str(log_data), "--snapshot", str(snapshot), "--read-only",
        "--ready-file", str(ready),
    ]
    bv.write(output / "log-service-command.json", {
        "command": command,
        "read_only": True,
        "started": utc_now(),
    })
    with (output / "log-service.stdout.log").open("xb") as stdout, \
            (output / "log-service.stderr.log").open("xb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        try:
            base_url = None
            for _ in range(50):
                if process.poll() is not None:
                    raise ValueError("read-only HTTP transparency log exited before readiness")
                base_url = managed_log_base_url(ready, host, port)
                if base_url:
                    try:
                        with socket.create_connection(
                                (host, urlsplit(base_url).port), timeout=0.1):
                            break
                    except OSError:
                        pass
                time.sleep(0.1)
            else:
                raise ValueError("read-only HTTP transparency log readiness not confirmed")
            bv.require(process.poll() is None,
                       "read-only HTTP transparency log exited during readiness")
            yield base_url
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def require_http_log_url(value):
    parsed = urlsplit(value)
    bv.require(parsed.scheme == "http" and parsed.hostname
               and parsed.port is not None and not parsed.username and not parsed.password
               and parsed.path in ("", "/") and not parsed.query and not parsed.fragment,
               "log URL must be an explicit http://host:port/ URL")
    return value.rstrip("/") + "/"


def require_empty_rp_state(path):
    path = Path(path).resolve()
    if path.exists():
        bv.require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()),
                   "RP state directory must start empty")
    else:
        path.mkdir(parents=True)
    return path


def update_once(base_url, authority, checker, rp_state, log_number, sequence, now):
    requests = []
    with audit_updater_get(requests):
        published = rp_updater.update_and_publish(
            base_url, authority, checker, rp_state, log_number, sequence, now)

    store = RPStateStore(rp_state)
    current = store.load_current()
    bv.require(current is not None, "RP updater did not publish current state")
    mts1 = (rp_state / "current" / "trusted-subtrees.mts1").resolve(strict=True)
    bv.validate_mts1(mts1, log_number)
    generations = sorted(path for path in (rp_state / "generations").iterdir()
                         if path.is_dir())
    bv.require(len(generations) == 1 and mts1.parent == generations[0].resolve(),
               "one-shot update did not create exactly one new RP generation")
    bv.require(current["checkpoint"] == published["checkpoint"],
               "published RP checkpoint does not match current state")
    return current, mts1, generations[0], requests


def mtc_credentials(fixture, validation, anchor, profile):
    selected = bv.prevalidated_mtc(fixture, validation, profile=profile)
    expected = bv.expected_anchor(selected)
    bv.require(bv.read(anchor) == expected, "supplied anchor does not match selected fixture")
    selected.update(anchor=str(anchor), anchor_sha256=bv.sha(anchor), anchor_origin="explicit")
    return {"mtc": selected}


def artifact_record(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": bv.sha(path), "bytes": path.stat().st_size}


def run(args):
    started = utc_now()
    output = REPO / "artifacts" / "results" / ("chromium-http-log-mtc-" + bv.stamp())
    output.mkdir(parents=True, exist_ok=False)
    rp_state = require_empty_rp_state(args.rp_state)
    fixture = Path(args.fixture).resolve()
    snapshot = require_file(args.snapshot, "snapshot")
    authority = require_file(args.trusted_authority, "trusted authority")
    checker = require_file(args.checker, "snapshot checker")
    bv.require(os.access(checker, os.X_OK), "snapshot checker is not executable")
    anchor = require_file(args.anchor, "Chromium anchor")
    landmarks = require_file(args.landmarks, "landmark publication")
    sequence = read_landmark_sequence(landmarks, args.now)
    anchor_config = bv.read(anchor)
    log_number = anchor_config.get("log_number")
    bv.require(type(log_number) is int and 0 < log_number < 1 << 16,
               "anchor has invalid log number")

    configuration = {
        "started": started,
        "fixture": str(fixture),
        "validation": str(Path(args.validation).resolve()),
        "anchor": str(anchor),
        "snapshot": str(snapshot),
        "trusted_authority": str(authority),
        "checker": str(checker),
        "landmarks": str(landmarks),
        "rp_state": str(rp_state),
        "now": args.now,
        "profile": args.profile,
        "log_number": log_number,
        "log_mode": "external" if args.log_url else "managed-read-only",
    }
    bv.write(output / "configuration.json", configuration)

    service = (nullcontext(require_http_log_url(args.log_url))
               if args.log_url else
               local_log_service(args.log_host, args.log_port,
                                 Path(args.log_data).resolve(), snapshot, output))
    try:
        with service as base_url:
            current, mts1, generation, requests = update_once(
                base_url, authority, checker, rp_state, log_number, sequence, args.now)
            snapshot_request = next((request for request in requests
                                     if request["path"] == "/snapshot"), None)
            bv.require(snapshot_request is not None, "RP updater did not request /snapshot")
            bv.require(snapshot_request["response_sha256"] == bv.sha(snapshot),
                       "HTTP snapshot differs from the configured snapshot")
            bv.write(output / "http-evidence.json", {
                "base_url": base_url,
                "requests": requests,
                "snapshot": artifact_record(snapshot),
            })
            bv.write(output / "rp-evidence.json", {
                "initial_state": "empty",
                "checkpoint": current["checkpoint"],
                "generation": str(generation.resolve()),
                "current_target": os.readlink(rp_state / "current"),
                "mts1": artifact_record(mts1),
            })

        credentials = mtc_credentials(fixture, args.validation, anchor, args.profile)
        browser = bv.browser_executable(args.chromium)
        case_output = output / "mtc-positive"
        result = bv.run_case("mtc-positive", credentials, browser, case_output,
                             output, args.timeout, False, trusted_subtrees=mts1)
        bv.write(case_output / "result.json", result)
        command_line = bv.read(case_output / "chromium-command.json")["command"]
        expected_switch = "--mtc-plants05-trusted-subtrees=" + str(mts1)
        bv.require(expected_switch in command_line,
                   "effective Chromium command does not select the published MTS1")

        evidence = {
            "started": started,
            "completed": utc_now(),
            "overall_pass": result["pass"] is True,
            "chain": {
                "http_log": True,
                "authenticated_checkpoint": True,
                "subtree_proof_requests": sum(
                    request["path"].startswith("/proof/subtree?") for request in requests),
                "mts1_published": True,
                "chromium_mts1_switch": True,
                "verify_mtc_inference": result["pass"] is True,
                "tls_13_pass": result["pass"] is True,
            },
            "browser": browser,
            "chromium_command": command_line,
            "browser_result": result,
            "artifacts": {
                "anchor": artifact_record(anchor),
                "snapshot": artifact_record(snapshot),
                "trusted_authority": artifact_record(authority),
                "snapshot_checker": artifact_record(checker),
                "landmarks": artifact_record(landmarks),
                "mts1": artifact_record(mts1),
                "fixture_manifest": artifact_record(fixture / "manifest.json"),
                "fixture_validation": artifact_record(args.validation),
            },
        }
        bv.write(output / "evidence.json", evidence)
        return output, 0 if evidence["overall_pass"] else 1
    except Exception as error:
        if not (output / "failure.json").exists():
            bv.write(output / "failure.json", {
                "started": started, "failed": utc_now(),
                "error": str(error) or type(error).__name__,
            })
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--log-url")
    source.add_argument("--log-data", type=Path)
    parser.add_argument("--log-host", default="127.0.0.1")
    parser.add_argument(
        "--log-port", type=int, default=0,
        help="managed log port (default: OS-selected loopback port)")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--trusted-authority", type=Path, required=True)
    parser.add_argument(
        "--checker", type=Path, default=DEFAULT_CHECKER,
        help=("snapshot checker (default: %(default)s; build with "
              "python3 src/mtc/build_check_snapshot.py --openssl-prefix PREFIX)"),
    )
    parser.add_argument("--landmarks", type=Path, required=True)
    parser.add_argument("--rp-state", type=Path, required=True)
    parser.add_argument("--chromium", type=Path)
    parser.add_argument("--profile", choices=bv.PROFILES, default=bv.PROFILE)
    parser.add_argument("--now", type=int, default=int(time.time()))
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    bv.require(args.log_url or (args.log_host in ("127.0.0.1", "localhost")
                               and 0 <= args.log_port < 65536),
               "managed log service requires an explicit loopback host and port")
    bv.require(5 <= args.timeout <= 300, "timeout must be between 5 and 300 seconds")
    output, status = run(args)
    print("Result directory: " + str(output))
    return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
