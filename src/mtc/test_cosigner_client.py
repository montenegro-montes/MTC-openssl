"""Focused tests for the process-based external cosigner client."""

from pathlib import Path
import shutil
import subprocess
import tempfile

import core
from cosigner_client import CosignerCLIClient, CosignerCLIError


OPENSSL = shutil.which("openssl")
assert OPENSSL is not None


def verify(public, signed_message, signature, directory):
    message_path = directory / "message.bin"
    signature_path = directory / "signature.bin"
    message_path.write_bytes(signed_message)
    signature_path.write_bytes(signature)
    subprocess.run([
        OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin",
        "-inkey", public, "-in", message_path,
        "-sigfile", signature_path, "-digest", "sha256",
    ], check=True, capture_output=True)


with tempfile.TemporaryDirectory(prefix="mtc-cosigner-client-") as temporary:
    directory = Path(temporary)
    source = Path(__file__).resolve().parent
    key = directory / "external.key"
    public = directory / "external.pub"
    state = directory / "accepted.json"
    subprocess.run([
        OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt",
        "ec_paramgen_curve:P-256", "-out", key,
    ], check=True, capture_output=True)
    public.write_bytes(subprocess.run([
        OPENSSL, "pkey", "-in", key, "-pubout",
    ], check=True, capture_output=True).stdout)

    # The wrapper is a test-only Python launcher that selects this host's
    # OpenSSL while still executing cosigner_cli.py as a separate process.
    python_wrapper = directory / "python-with-openssl"
    python_wrapper.write_text(
        "#!" + shutil.which("python3") + "\n"
        "import runpy,sys\n"
        f"sys.path.insert(0,{str(source)!r})\n"
        "import prepare\n"
        f"prepare.OPENSSL={OPENSSL!r}\n"
        "target=sys.argv.pop(1)\n"
        "runpy.run_path(target,run_name='__main__')\n")
    python_wrapper.chmod(0o700)

    client = CosignerCLIClient(
        "32473.102", key, "32473.101", "ecdsa-p256", state,
        python_executable=python_wrapper)
    entries = [bytes([index]) for index in range(8)]
    first_entries = entries[:3]
    first_root = core.root(first_entries)
    accepted = client.accept_view(3, first_root, [])
    assert accepted == {"tree_size": 3, "root_hash": first_root}
    retained_first = state.read_bytes()

    identity, signature = client.cosign_accepted(123)
    assert type(identity) is str and type(signature) is bytes
    assert identity == client.identity
    verify(
        public,
        core.message(identity, client.ca_id, 0, 3, first_root, 123, client.log),
        signature, directory)

    start, end = core.cover(0, 3)[0]
    subtree_hash = core.root(first_entries[start:end])
    subtree_proof = core.subtree_consistency(first_entries, start, end)
    subtree_identity, subtree_signature = client.cosign_subtree(
        start, end, subtree_hash, subtree_proof)
    assert type(subtree_identity) is str and type(subtree_signature) is bytes
    verify(
        public,
        core.message(
            subtree_identity, client.ca_id, start, end, subtree_hash,
            0, client.log),
        subtree_signature, directory)

    grown_root = core.root(entries)
    invalid_consistency = core.consistency(entries, 3)
    invalid_consistency[0] = (
        bytes([invalid_consistency[0][0] ^ 1]) + invalid_consistency[0][1:])
    try:
        client.accept_view(len(entries), grown_root, invalid_consistency)
    except CosignerCLIError as error:
        assert error.returncode != 0 and error.stderr
    else:
        raise AssertionError("invalid consistency proof was accepted")
    assert state.read_bytes() == retained_first

    invalid_subtree = list(subtree_proof)
    invalid_subtree[0] = (
        bytes([invalid_subtree[0][0] ^ 1]) + invalid_subtree[0][1:])
    for rejected_call in [
        lambda: client.cosign_subtree(
            start, end, subtree_hash, invalid_subtree),
        lambda: client.cosign_subtree(
            0, 1, core.root(first_entries[:1]),
            core.subtree_consistency(first_entries, 0, 1)),
    ]:
        try:
            rejected_call()
        except CosignerCLIError as error:
            assert error.returncode != 0 and error.stderr
        else:
            raise AssertionError("invalid subtree request was accepted")
        assert state.read_bytes() == retained_first

    missing_cli = CosignerCLIClient(
        client.identity, key, client.ca_id, client.family, state,
        python_executable=python_wrapper,
        cli_path=directory / "missing-cosigner-cli.py")
    try:
        missing_cli.cosign_accepted()
    except CosignerCLIError as error:
        assert error.returncode != 0
        assert "external cosigner CLI failed" in str(error)
        assert error.stderr
    else:
        raise AssertionError("missing CLI used a fallback")
    assert state.read_bytes() == retained_first

print("PASS: process-based external cosigner client")
