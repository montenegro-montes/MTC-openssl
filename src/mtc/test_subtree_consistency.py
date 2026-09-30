"""Draft-06 Section 4.4 subtree consistency proof tests."""

import hashlib

from core import (
    root,
    subtree_consistency,
    valid_subtree,
    verify_subtree_consistency,
)

D = [bytes([i]) for i in range(131)]

EXPECTED_C11 = (
    "b82806ad4265bb151c1119c0f4db437b"
    "b4d1a1f887b3a7fba1cd4ebf552e3e81"
)

EXPECTED_C13 = (
    "10fa99b37bf9bf9ffa26b412fbd98bd7"
    "5363256d0b75d61bc4538b9c9c5a0a74"
)


def accumulated_vectors():
    # Appendix C.1.1: subtree hashes and subtree validity.
    h = hashlib.sha256()
    for end in range(131):
        for start in range(end + 1):
            if valid_subtree(start, end):
                subtree_hash = root(D[start:end])
                h.update(
                    f"[{start}, {end}) {subtree_hash.hex()}\n".encode()
                )
    assert h.hexdigest() == EXPECTED_C11

    # Appendix C.1.3: subtree consistency proof construction.
    h = hashlib.sha256()
    for n in range(131):
        tree = D[:n]
        for end in range(n + 1):
            for start in range(end + 1):
                if not valid_subtree(start, end):
                    continue
                proof = subtree_consistency(tree, start, end)
                line = f"[{start}, {end}) {n}"
                for value in proof:
                    line += f" {value.hex()}"
                h.update(f"{line}\n".encode())
    assert h.hexdigest() == EXPECTED_C13


def verification_vectors():
    checked = 0

    for n in range(131):
        tree = D[:n]
        tree_hash = root(tree)

        for end in range(n + 1):
            for start in range(end + 1):
                if not valid_subtree(start, end):
                    continue

                node_hash = root(tree[start:end])
                proof = subtree_consistency(tree, start, end)

                assert verify_subtree_consistency(
                    start, end, n, node_hash, tree_hash, proof
                )
                checked += 1

                # Appendix C.1.3 step 3.
                if proof:
                    assert not verify_subtree_consistency(
                        start, end, n, node_hash, tree_hash, proof[:-1]
                    )
                    malformed = proof[:-1] + [proof[-1][:-1]]
                    assert not verify_subtree_consistency(
                        start, end, n, node_hash, tree_hash, malformed
                    )

                # Appendix C.1.3 step 4.
                assert not verify_subtree_consistency(
                    start, end, n, node_hash, tree_hash,
                    proof + [b"\0" * 32],
                )

                malformed = list(proof)
                if malformed:
                    malformed[-1] += b"\0"
                else:
                    malformed = [b"\0"]
                assert not verify_subtree_consistency(
                    start, end, n, node_hash, tree_hash, malformed
                )

                # Appendix C.1.3 step 5.
                corrupt_node = bytes([node_hash[0] ^ 1]) + node_hash[1:]
                assert not verify_subtree_consistency(
                    start, end, n, corrupt_node, tree_hash, proof
                )

                # Appendix C.1.3 step 6.
                if start != end:
                    corrupt_root = bytes([tree_hash[0] ^ 1]) + tree_hash[1:]
                    assert not verify_subtree_consistency(
                        start, end, n, node_hash, corrupt_root, proof
                    )

    assert checked == 42893


def boundary_tests():
    assert valid_subtree(0, 0)
    assert valid_subtree(0, 8)
    assert valid_subtree(8, 16)
    assert not valid_subtree(4, 9)

    assert not valid_subtree(-1, 0)
    assert not valid_subtree(2, 1)
    assert not valid_subtree(0, 1 << 48)

    try:
        subtree_consistency([b"x"] * 9, 4, 9)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid subtree accepted")


if __name__ == "__main__":
    boundary_tests()
    accumulated_vectors()
    verification_vectors()
    print("PASS: draft-06 subtree consistency proofs")
