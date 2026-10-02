"""Focused localhost tests for the external cosigner HTTP transport."""

import http.client
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Thread

import core
import prepare
from cosigner_http_client import CosignerHTTPClient, CosignerHTTPError
from cosigner_http_service import CosignerHTTPServer


OPENSSL = shutil.which("openssl")
assert OPENSSL is not None
prepare.OPENSSL = OPENSSL


def verify(public, message, signature, directory, label):
    message_path = directory / f"{label}.message"
    signature_path = directory / f"{label}.signature"
    message_path.write_bytes(message)
    signature_path.write_bytes(signature)
    subprocess.run([
        OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin",
        "-inkey", public, "-in", message_path,
        "-sigfile", signature_path, "-digest", "sha256",
    ], check=True, capture_output=True)


with tempfile.TemporaryDirectory(prefix="mtc-cosigner-http-") as temporary:
    directory = Path(temporary)
    key = directory / "external.key"
    public = directory / "external.pub"
    state = directory / "accepted.json"
    prepare.keygen(key, "ecdsa-p256")
    public.write_bytes(prepare.command("pkey", "-in", key, "-pubout"))

    server = CosignerHTTPServer(
        ("127.0.0.1", 0), "32473.102", key, "32473.101",
        "ecdsa-p256", state)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    client = CosignerHTTPClient(f"http://{host}:{port}")
    try:
        entries = [bytes([index]) for index in range(8)]
        first = entries[:3]
        first_root = core.root(first)
        assert client.accept_view(3, first_root, []) == {
            "tree_size": 3, "root_hash": first_root}
        retained = state.read_bytes()
        assert json.loads(retained) == {
            "tree_size": 3, "root_hash": first_root.hex()}

        identity, signature = client.cosign_accepted(123)
        assert type(identity) is str and type(signature) is bytes
        verify(public, core.message(
            identity, "32473.101", 0, 3, first_root, 123, 1),
            signature, directory, "checkpoint")

        start, end = core.cover(0, 3)[0]
        subtree_hash = core.root(first[start:end])
        subtree_proof = core.subtree_consistency(first, start, end)
        subtree_identity, subtree_signature = client.cosign_subtree(
            start, end, subtree_hash, subtree_proof)
        assert type(subtree_identity) is str
        assert type(subtree_signature) is bytes
        verify(public, core.message(
            subtree_identity, "32473.101", start, end, subtree_hash, 0, 1),
            subtree_signature, directory, "subtree")

        grown_root = core.root(entries)
        invalid_consistency = core.consistency(entries, 3)
        invalid_consistency[0] = (
            bytes([invalid_consistency[0][0] ^ 1])
            + invalid_consistency[0][1:])
        invalid_subtree = list(subtree_proof)
        invalid_subtree[0] = (
            bytes([invalid_subtree[0][0] ^ 1])
            + invalid_subtree[0][1:])
        rejected = [
            lambda: client.accept_view(8, grown_root, invalid_consistency),
            lambda: client.cosign_subtree(
                start, end, subtree_hash, invalid_subtree),
            lambda: client.cosign_subtree(
                0, 1, core.root(first[:1]),
                core.subtree_consistency(first, 0, 1)),
        ]
        for operation in rejected:
            try:
                operation()
            except CosignerHTTPError as error:
                assert error.status == 400
                assert json.loads(error.body)["error"] == (
                    "Cosigner rejected request")
            else:
                raise AssertionError("invalid cosigner request was accepted")
            assert state.read_bytes() == retained

        connection = http.client.HTTPConnection(host, port, timeout=2)
        connection.request("GET", "/accept-view")
        response = connection.getresponse()
        assert response.status == 405 and response.getheader("Allow") == "POST"
        response.read();connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=2)
        connection.request("POST", "/unknown", body=b"{}")
        response = connection.getresponse()
        assert response.status == 404
        response.read();connection.close()

        malformed_requests = [
            (b"not-json", {}),
            (json.dumps({
                "tree_size": 3,
                "root_hash": first_root.hex(),
                "consistency_proof": [],
                "extra": True,
            }).encode(), {}),
            (json.dumps({
                "tree_size": 3,
                "root_hash": "00",
                "consistency_proof": [],
            }).encode(), {}),
            (b"{}", {"Transfer-Encoding": "chunked"}),
        ]
        for body, headers in malformed_requests:
            connection = http.client.HTTPConnection(host, port, timeout=2)
            connection.request(
                "POST", "/accept-view", body=body, headers=headers)
            response = connection.getresponse()
            assert response.status == 400
            response.read();connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=2)
        connection.putrequest("POST", "/accept-view")
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 411
        response.read();connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=2)
        connection.putrequest("POST", "/accept-view")
        connection.putheader("Content-Length", str(1024 * 1024 + 1))
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 413
        response.read();connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()

print("PASS: localhost external cosigner HTTP transport")
