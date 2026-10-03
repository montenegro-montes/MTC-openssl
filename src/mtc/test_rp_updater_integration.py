"""Real MCF1/HTTP integration test for the relying-party updater."""

import argparse
from pathlib import Path
import subprocess
import tempfile
import threading

import prepare
from build_check_snapshot import build_check_snapshot
from crypto_profiles import crypto_profile
from landmarks import Landmark
from local_log import LocalLog
from log_service import LogServer
from rp_state import RPStateStore
from rp_updater import fetch_and_advance_checkpoint, update_and_publish
from snapshots import export_snapshot
from trusted_subtrees import decode_trusted_subtrees


def rejected(operation, text):
    try:
        operation()
    except (ValueError, OSError):
        return
    raise AssertionError(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl-prefix", type=Path, required=True)
    parser.add_argument(
        "--profile",
        default="ecdsa-p256",
        choices=["ecdsa-p256", "mldsa65"],
    )
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()

    prefix = args.openssl_prefix.resolve()
    prepare.OPENSSL = str(prefix / "bin/openssl")

    profile = crypto_profile(args.profile)

    with tempfile.TemporaryDirectory(
            prefix="mtc-rp-update-integration-") as temporary:
        temp = Path(temporary)
        checker = temp / "check_snapshot"

        build_check_snapshot(prefix, checker, args.cc)

        def provision(label):
            keys = [temp / f"{label}-{i}.key" for i in range(2)]
            for key in keys:
                prepare.keygen(key, args.profile)

            public = [
                prepare.command(
                    "pkey", "-in", key, "-pubout", "-outform", "DER")
                for key in keys
            ]
            data = prepare.authority_config(
                profile["ca_id"],
                profile["cosigner_ids"],
                public,
                16,
            )
            authority = temp / f"{label}-authority.bin"
            authority.write_bytes(data)
            return keys, authority

        keys, authority = provision("trusted")

        log_directory = temp / "log"
        log = LocalLog(log_directory)
        entries = [bytes([i]) for i in range(16)]

        for entry in entries[:8]:
            log.append(entry)

        snapshot8 = temp / "snapshot-8.mcf1"
        export_snapshot(log, snapshot8, args.profile, keys)

        published = temp / "published.mcf1"
        published.write_bytes(snapshot8.read_bytes())

        server = LogServer(
            ("127.0.0.1", 0),
            log_directory,
            published,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
        )
        thread.start()

        base_url = "http://127.0.0.1:%d/" % server.server_address[1]

        try:
            # Bootstrap is authenticated by the real native MCF1 checker.
            state8 = fetch_and_advance_checkpoint(
                base_url,
                authority,
                checker,
            )
            assert state8["log_number"] == 1
            assert state8["tree_size"] == 8

            sequence = [
                Landmark(0, 0, 0),
                Landmark(1, 8, 100),
                Landmark(2, 16, 200),
            ]
            rp_directory = temp / "rp-state"

            # Bootstrap the persistent RP state while the authenticated HTTP
            # publication and the underlying log are still exactly N=8.
            published8 = update_and_publish(
                base_url,
                authority,
                checker,
                rp_directory,
                1,
                sequence,
                50,
            )
            assert published8["checkpoint"] == state8

            store = RPStateStore(rp_directory)
            retained8 = store.load_current()
            assert retained8["checkpoint"] == state8
            selected8 = store.current.readlink()

            trusted8 = decode_trusted_subtrees(
                published8["trusted_subtrees"])
            assert [(item.log_number, item.start, item.end)
                    for item in trusted8] == [
                (1, 0, 4),
                (1, 4, 8),
            ]

            # Grow the real persistent log and publish a new signed snapshot.
            log = LocalLog(log_directory)
            for entry in entries[8:]:
                log.append(entry)

            snapshot16 = temp / "snapshot-16.mcf1"
            export_snapshot(log, snapshot16, args.profile, keys)
            published.write_bytes(snapshot16.read_bytes())

            # Keep the focused checkpoint-evolution assertion: N=16 must be
            # RFC 9162-consistent with the independently retained N=8 state.
            state16 = fetch_and_advance_checkpoint(
                base_url,
                authority,
                checker,
                state8,
            )
            assert state16["log_number"] == 1
            assert state16["tree_size"] == 16
            assert {
                "tree_size": state16["tree_size"],
                "hash": state16["hash"],
            } == log.state()

            # Now exercise the complete operational transaction.  It must
            # recover N=8 from RPStateStore, authenticate N=16, verify the
            # RFC 9162 8->16 transition, validate Section 7.4 evidence, and
            # atomically select the new checkpoint + MTS1 generation.
            published_state = update_and_publish(
                base_url,
                authority,
                checker,
                rp_directory,
                1,
                sequence,
                50,
            )

            assert published_state["checkpoint"] == state16
            assert store.current.readlink() != selected8
            trusted = decode_trusted_subtrees(
                published_state["trusted_subtrees"])
            assert [(item.log_number, item.start, item.end)
                    for item in trusted] == [
                (1, 0, 4),
                (1, 4, 8),
                (1, 8, 12),
                (1, 12, 16),
            ]

            store = RPStateStore(rp_directory)
            retained = store.load_current()
            assert retained["checkpoint"] == state16
            assert retained["trusted_subtrees"] == (
                published_state["trusted_subtrees"])
            selected_before_failure = store.current.readlink()

            # A later unauthenticated publication must fail before atomic
            # state publication and leave the selected generation untouched.
            published.write_bytes(b"not-authenticated")
            rejected(
                lambda: update_and_publish(
                    base_url,
                    authority,
                    checker,
                    rp_directory,
                    1,
                    sequence,
                    50,
                ),
                "unauthenticated operational update accepted",
            )

            retained = store.load_current()
            assert store.current.readlink() == selected_before_failure
            assert retained["checkpoint"] == state16
            assert retained["trusted_subtrees"] == (
                published_state["trusted_subtrees"])

            # Restore the authentic N=16 publication for subsequent tests.
            published.write_bytes(snapshot16.read_bytes())

            # The same CA/cosigner keys may authenticate an independent
            # issuance-log domain.  Switching from retained log 1 to log 2
            # must bootstrap log 2 rather than request cross-log consistency.
            public = [
                prepare.command(
                    "pkey", "-in", key, "-pubout", "-outform", "DER")
                for key in keys
            ]
            authority_log2 = temp / "trusted-log2-authority.bin"
            authority_log2.write_bytes(
                prepare.authority_config(
                    profile["ca_id"],
                    profile["cosigner_ids"],
                    public,
                    16,
                    log_number=2,
                )
            )

            snapshot_log2 = temp / "snapshot-log2-16.mcf1"
            export_snapshot(
                log,
                snapshot_log2,
                args.profile,
                keys,
                log_number=2,
            )
            published.write_bytes(snapshot_log2.read_bytes())

            log2_state = update_and_publish(
                base_url,
                authority_log2,
                checker,
                rp_directory,
                2,
                sequence,
                50,
            )
            assert log2_state["checkpoint"]["log_number"] == 2
            assert log2_state["checkpoint"]["tree_size"] == 16
            assert log2_state["checkpoint"]["hash"] == state16["hash"]

            retained_log2 = store.load_current()
            assert retained_log2["checkpoint"] == log2_state["checkpoint"]
            assert retained_log2["checkpoint"]["log_number"] == 2

            trusted_log2 = decode_trusted_subtrees(
                retained_log2["trusted_subtrees"])
            assert trusted_log2
            assert all(item.log_number == 2 for item in trusted_log2)

            # Restore log 1 before the independent substituted-key test below.
            published.write_bytes(snapshot16.read_bytes())

            # An independently valid snapshot signed by substituted keys must
            # not authenticate against the relying party's provisioned trust.
            attacker_keys, attacker_authority = provision("attacker")
            substituted = temp / "substituted.mcf1"
            export_snapshot(log, substituted, args.profile, attacker_keys)

            published.write_bytes(substituted.read_bytes())

            rejected(
                lambda: fetch_and_advance_checkpoint(
                    base_url,
                    authority,
                    checker,
                    state16,
                ),
                "substituted signer keys accepted",
            )

            # Sanity check: the same object is valid only under the separately
            # provisioned attacker authority.
            attacker_state = fetch_and_advance_checkpoint(
                base_url,
                attacker_authority,
                checker,
            )
            assert attacker_state == state16

        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    print(
        "PASS: real MCF1 HTTP checkpoint authentication and "
        "RFC9162 RP evolution"
    )


if __name__ == "__main__":
    main()
