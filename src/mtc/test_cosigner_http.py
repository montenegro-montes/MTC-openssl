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
        assert client.accepted_checkpoint() is None
        assert client.accept_view(3, first_root, []) == {
            "tree_size": 3, "root_hash": first_root}
        assert client.accepted_checkpoint() == {
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

    def openssl(*arguments):
        subprocess.run(
            [OPENSSL, *map(str, arguments)], check=True,
            capture_output=True)

    tls_ca_key = directory / "tls-ca.key"
    tls_ca_cert = directory / "tls-ca.pem"
    openssl(
        "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", tls_ca_key, "-out", tls_ca_cert,
        "-subj", "/CN=MTC test TLS CA", "-days", "1",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign")

    def issue_tls_certificate(name, common_name, extensions):
        issued_key = directory / f"{name}.key"
        request = directory / f"{name}.csr"
        certificate = directory / f"{name}.pem"
        command = [
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", issued_key, "-out", request,
            "-subj", f"/CN={common_name}",
        ]
        for extension in extensions:
            command += ["-addext", extension]
        openssl(*command)
        openssl(
            "x509", "-req", "-in", request,
            "-CA", tls_ca_cert, "-CAkey", tls_ca_key,
            "-CAcreateserial", "-out", certificate, "-days", "1",
            "-copy_extensions", "copy")
        return certificate, issued_key

    server_cert, server_key = issue_tls_certificate(
        "tls-server", "localhost", (
            "subjectAltName=DNS:localhost",
            "extendedKeyUsage=serverAuth",
        ))
    client_cert, client_key = issue_tls_certificate(
        "tls-client", "MTC test client", (
            "extendedKeyUsage=clientAuth",
        ))
    mtls_state = directory / "mtls-accepted.json"
    mtls_server = CosignerHTTPServer(
        ("127.0.0.1", 0), "32473.102", key, "32473.101",
        "ecdsa-p256", mtls_state,
        tls_cert=server_cert, tls_key=server_key,
        client_ca=tls_ca_cert, require_client_cert=True)
    mtls_thread = Thread(target=mtls_server.serve_forever, daemon=True)
    mtls_thread.start()
    _, mtls_port = mtls_server.server_address
    mtls_client = CosignerHTTPClient(
        f"https://localhost:{mtls_port}", ca_file=tls_ca_cert,
        client_cert=client_cert, client_key=client_key)
    try:
        mtls_entries = [b"mtls-0", b"mtls-1", b"mtls-2"]
        mtls_root = core.root(mtls_entries)
        assert mtls_client.accepted_checkpoint() is None
        assert mtls_client.accept_view(3, mtls_root, []) == {
            "tree_size": 3, "root_hash": mtls_root}
        assert mtls_client.accepted_checkpoint() == {
            "tree_size": 3, "root_hash": mtls_root}
        mtls_identity, mtls_signature = mtls_client.cosign_accepted(456)
        verify(public, core.message(
            mtls_identity, "32473.101", 0, 3, mtls_root, 456, 1),
            mtls_signature, directory, "mtls-checkpoint")

        retained_mtls_state = mtls_state.read_bytes()
        client_without_certificate = CosignerHTTPClient(
            f"https://localhost:{mtls_port}", ca_file=tls_ca_cert)
        try:
            client_without_certificate.cosign_accepted(457)
        except CosignerHTTPError as error:
            assert error.status is None
        else:
            raise AssertionError(
                "mTLS service accepted a client without a certificate")
        assert mtls_state.read_bytes() == retained_mtls_state
    finally:
        mtls_server.shutdown()
        mtls_server.server_close()
        mtls_thread.join(timeout=2)
        assert not mtls_thread.is_alive()

print("PASS: localhost external cosigner HTTP transport")
