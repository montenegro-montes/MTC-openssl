"""Focused process-boundary tests for the external cosigner CLI."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import core


OPENSSL = shutil.which("openssl")
assert OPENSSL is not None
RUNNER = (
    "import sys,prepare;prepare.OPENSSL=sys.argv[1];"
    "import cosigner_cli;cosigner_cli.main(sys.argv[2:])"
)


def encoded_proof(proof):
    return json.dumps([value.hex() for value in proof], separators=(",", ":"))


with tempfile.TemporaryDirectory(prefix="mtc-cosigner-cli-") as temporary:
    directory = Path(temporary)
    key = directory / "external.key"
    state = directory / "accepted.json"
    subprocess.run([
        OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt",
        "ec_paramgen_curve:P-256", "-out", key,
    ], check=True, capture_output=True)

    common = [
        "--identity", "32473.102",
        "--key", str(key),
        "--ca-id", "32473.101",
        "--family", "ecdsa-p256",
        "--log", "1",
        "--state", str(state),
    ]

    def invoke(*operation, check=True):
        result = subprocess.run(
            [sys.executable, "-c", RUNNER, OPENSSL, *common, *operation],
            check=check, capture_output=True, text=True)
        if not check:
            return result
        assert result.stderr == ""
        return json.loads(result.stdout)

    entries = [bytes([index]) for index in range(8)]
    checkpoint = core.root(entries)
    accepted = invoke(
        "accept-view", "--tree-size", str(len(entries)),
        "--root-hash", checkpoint.hex(),
        "--consistency-proof", encoded_proof(core.consistency(entries, 0)))
    assert accepted == {
        "root_hash": checkpoint.hex(),
        "tree_size": len(entries),
    }
    assert state.read_bytes() == (
        b'{"tree_size":8,"root_hash":"'
        + checkpoint.hex().encode("ascii") + b'"}\n')

    checkpoint_signature = invoke(
        "cosign-accepted", "--timestamp", "123")
    assert checkpoint_signature["identity"] == "32473.102"
    assert bytes.fromhex(checkpoint_signature["signature"])

    start, end = core.cover(0, len(entries))[0]
    subtree_hash = core.root(entries[start:end])
    subtree_signature = invoke(
        "cosign-subtree", "--start", str(start), "--end", str(end),
        "--subtree-hash", subtree_hash.hex(),
        "--subtree-consistency-proof",
        encoded_proof(core.subtree_consistency(entries, start, end)),
        "--timestamp", "0")
    assert subtree_signature["identity"] == "32473.102"
    assert bytes.fromhex(subtree_signature["signature"])

    retained = state.read_bytes()
    corrupt = core.subtree_consistency(entries, start, end)
    corrupt[0] = bytes([corrupt[0][0] ^ 1]) + corrupt[0][1:]
    rejected = invoke(
        "cosign-subtree", "--start", str(start), "--end", str(end),
        "--subtree-hash", subtree_hash.hex(),
        "--subtree-consistency-proof", encoded_proof(corrupt),
        "--timestamp", "0", check=False)
    assert rejected.returncode != 0
    assert rejected.stdout == ""
    assert state.read_bytes() == retained

print("PASS: external cosigner CLI process boundary")
