#!/usr/bin/env python3
"""Periodic remote relying-party update service for the MTC laboratory."""

import argparse
import json
from pathlib import Path
import signal
import sys
from threading import Event

from landmarks import Landmark, decode_publication
from rp_updater import RPHTTPError, update_and_publish_remote


def landmark_sequence(path):
    """Load a complete laboratory landmark publication."""
    data = Path(path).read_bytes()

    lines = data.decode("ascii").splitlines()
    if len(lines) < 2:
        raise ValueError("Invalid landmark publication")

    fields = lines[1].split()
    if len(fields) != 2:
        raise ValueError("Invalid newest landmark record")

    now = int(fields[1])
    latest, records = decode_publication(data, now)

    numbered = [
        Landmark(latest - offset, tree_size, expiration)
        for offset, (tree_size, expiration) in enumerate(records)
    ]
    sequence = list(reversed(numbered))

    if not sequence or sequence[0] != Landmark(0, 0, 0):
        raise ValueError(
            "Landmark publication does not contain the complete sequence "
            "through landmark zero"
        )

    return sequence, now


def update_once(args):
    sequence, now = landmark_sequence(args.landmarks)
    log_number = sequence[-1].number

    state = update_and_publish_remote(
        args.log_url,
        args.trusted_authority,
        args.checker,
        args.state_directory,
        args.rp_url,
        log_number,
        sequence,
        now,
    )

    return {
        "result": "UPDATED",
        "severity": "PASS",
        "checkpoint": state["checkpoint"],
        "retained_landmark": state["retained_landmark"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-url", required=True)
    parser.add_argument("--rp-url", required=True)
    parser.add_argument("--trusted-authority", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--landmarks", type=Path, required=True)
    parser.add_argument(
        "--state-directory",
        type=Path,
        default=Path("/var/lib/mtc-rp-updater"),
    )
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)

    if args.interval <= 0:
        parser.error("--interval must be positive")

    for path, label in (
        (args.trusted_authority, "trusted authority"),
        (args.checker, "snapshot checker"),
        (args.landmarks, "landmark publication"),
    ):
        if not path.is_file():
            parser.error(f"{label} is missing")

    stopped = Event()

    def stop(signum, frame):
        stopped.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop)

    while not stopped.is_set():
        try:
            result = update_once(args)
        except RPHTTPError as error:
            result = {
                "result": "UNAVAILABLE",
                "severity": "ERROR",
                "error": str(error),
            }
        except (ValueError, OSError) as error:
            result = {
                "result": "UPDATE_FAILED",
                "severity": "ALERT",
                "error": str(error),
            }

        print(
            json.dumps(result, sort_keys=True, separators=(",", ":")),
            flush=True,
        )

        if args.once:
            return 0 if result["severity"] == "PASS" else 1

        stopped.wait(args.interval)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
