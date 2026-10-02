"""Focused draft-06 CosignedMessage and cosigning tests."""

import argparse
from pathlib import Path
import tempfile
from unittest.mock import patch

import core
import prepare


def verify(public, message, signature, family, directory):
    profile = prepare.crypto_profile(family)
    message_path = directory / "message.bin"
    signature_path = directory / "signature.bin"
    message_path.write_bytes(message)
    signature_path.write_bytes(signature)
    prepare.command(
        "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
        "-in", message_path, "-sigfile", signature_path,
        *(["-digest", profile["digest"]] if profile["digest"] else []),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    prepare.OPENSSL = args.openssl

    family = "ecdsa-p256"
    profile = prepare.crypto_profile(family)
    ca_id = profile["ca_id"]
    ca_cosigner, other_cosigner = profile["cosigner_ids"]
    assert ca_cosigner == ca_id
    assert other_cosigner != ca_cosigner

    subtree_hash = core.root([b"entry-0", b"entry-1"])
    expected_message = core.message(
        ca_cosigner, ca_id, 0, 2, subtree_hash, 0, 1)

    captured = []

    def deterministic_sign(key, data, selected_family):
        captured.append((key, data, selected_family))
        return b"deterministic-signature"

    with patch.object(prepare, "sign", side_effect=deterministic_sign):
        actual = prepare.cosign(
            ca_cosigner, Path("ca.key"), ca_id, 0, 2,
            subtree_hash, family)
        checkpoint = prepare.checkpoint_signature(
            ca_cosigner, Path("ca.key"), ca_id, 2,
            subtree_hash, 123, family)
    assert actual == (ca_cosigner, b"deterministic-signature")
    assert checkpoint == (ca_cosigner, b"deterministic-signature")
    assert captured == [
        (Path("ca.key"), expected_message, family),
        (Path("ca.key"), core.message(
            ca_cosigner, ca_id, 0, 2, subtree_hash, 123, 1), family),
    ]

    with tempfile.TemporaryDirectory(prefix="mtc-cosigning-") as temporary:
        directory = Path(temporary)
        keys = [directory / "ca.key", directory / "external.key"]
        public = [directory / "ca.pub", directory / "external.pub"]
        for key, pub in zip(keys, public):
            prepare.keygen(key, family)
            pub.write_bytes(prepare.command("pkey", "-in", key, "-pubout"))
        assert keys[0].read_bytes() != keys[1].read_bytes()

        signatures = [
            prepare.cosign(ident, key, ca_id, 0, 2, subtree_hash, family)
            for ident, key in zip((ca_cosigner, other_cosigner), keys)
        ]
        assert [ident for ident, _ in signatures] == [ca_cosigner, other_cosigner]
        for ident, signature in signatures:
            index = (ca_cosigner, other_cosigner).index(ident)
            verify(
                public[index],
                core.message(ident, ca_id, 0, 2, subtree_hash, 0, 1),
                signature,
                family,
                directory,
            )

        encoded = core.signatures(signatures, 3)
        assert encoded == core.signatures([
            (ident, signature) for ident, signature in signatures
        ], 3)

    print("PASS: draft-06 CosignedMessage and reusable cosigning")


if __name__ == "__main__":
    main()
