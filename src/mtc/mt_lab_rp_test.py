#!/usr/bin/env python3
"""Reproducible MTC laboratory RP integration check."""

import argparse
import shutil
import tempfile
from pathlib import Path

from landmarks import Landmark, decode_publication
from rp_updater import update_and_publish
from trusted_subtrees import decode_trusted_subtrees


def landmark_sequence(path):
    data = path.read_bytes()

    # The newest record is the first record after the landmark number.
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


def run(args):
    fixture = args.fixture.resolve()
    authority = (
        fixture
        / "transparency"
        / "ecdsa-p256"
        / "trusted-authority.bin"
    )
    landmarks = (
        fixture
        / "batch16"
        / "mtc"
        / "ecdsa-p256"
        / "landmarks.txt"
    )

    if not authority.is_file():
        raise ValueError("RP trusted authority is missing")
    if not landmarks.is_file():
        raise ValueError("Landmark publication is missing")
    if not args.checker.is_file():
        raise ValueError("Snapshot checker is missing")

    sequence, now = landmark_sequence(landmarks)
    log_number = sequence[-1].number

    state = Path(tempfile.mkdtemp(prefix="mt-lab-rp-"))

    try:
        first = update_and_publish(
            args.base_url,
            authority,
            args.checker,
            state,
            log_number,
            sequence,
            now,
        )

        checkpoint = first["checkpoint"]

        if checkpoint["log_number"] != log_number:
            raise RuntimeError("Unexpected RP log number")

        current = state / "current"
        if not current.is_symlink():
            raise RuntimeError("RP current generation was not published")

        generation = current.resolve()

        for name in (
            "checkpoint.json",
            "trusted-subtrees.mts1",
            "retained-landmark.json",
        ):
            if not (generation / name).is_file():
                raise RuntimeError(f"Missing RP artifact: {name}")

        mts1 = (generation / "trusted-subtrees.mts1").read_bytes()
        trusted = decode_trusted_subtrees(mts1)

        first_target = current.readlink()

        second = update_and_publish(
            args.base_url,
            authority,
            args.checker,
            state,
            log_number,
            sequence,
            now,
        )

        second_target = current.readlink()
        generations = [
            path
            for path in (state / "generations").iterdir()
            if path.is_dir()
        ]

        if second["checkpoint"] != checkpoint:
            raise RuntimeError(
                "Persistent RP checkpoint changed unexpectedly"
            )
        if second_target != first_target:
            raise RuntimeError(
                "Idempotent RP update changed current generation"
            )
        if len(generations) != 1:
            raise RuntimeError(
                "Idempotent RP update created another generation"
            )

        print("checkpoint:", checkpoint)
        print("trusted_subtrees:", len(trusted))
        print("retained_landmark:", first["retained_landmark"])
        print("generations:", len(generations))
        print("PASS: MTC Log -> RP -> MTS1")
        print("PASS: persistent RP update")
    finally:
        shutil.rmtree(state, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
