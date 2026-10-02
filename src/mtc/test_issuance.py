import shutil
import tempfile
from pathlib import Path
from threading import Thread

import prepare
from cosigner_http_client import CosignerHTTPClient
from cosigner_http_service import CosignerHTTPServer
from issuance import synchronize_cosigner
from local_log import LocalLog


OPENSSL = shutil.which("openssl")
assert OPENSSL is not None
prepare.OPENSSL = OPENSSL

IDENTITY = "32473.102"
CA_ID = "32473.101"
FAMILY = "ecdsa-p256"


def start_server(key, state):
    server = CosignerHTTPServer(
        ("127.0.0.1", 0),
        IDENTITY,
        key,
        CA_ID,
        FAMILY,
        state,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    client = CosignerHTTPClient(f"http://{host}:{port}")
    return server, thread, client


def stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join()


with tempfile.TemporaryDirectory(prefix="mtc-issuance-") as temporary:
    directory = Path(temporary)
    log_directory = directory / "log"
    state = directory / "accepted.json"
    key = directory / "external.key"

    log = LocalLog(log_directory)
    prepare.keygen(key, FAMILY)

    server, thread, client = start_server(key, state)
    try:
        assert client.accepted_checkpoint() is None

        for index in range(16):
            log.append(f"entry-{index:04d}".encode())

        current, proof = synchronize_cosigner(log, client)
        assert current["tree_size"] == 16
        assert len(proof) == 0

        for index in range(16, 32):
            log.append(f"entry-{index:04d}".encode())

        current, proof = synchronize_cosigner(log, client)
        assert current["tree_size"] == 32

        checkpoint = client.accepted_checkpoint()
        assert checkpoint == {
            "tree_size": 32,
            "root_hash": bytes.fromhex(current["hash"]),
        }
    finally:
        stop_server(server, thread)

    # Reopen both persistent components.
    log = LocalLog(log_directory)
    server, thread, client = start_server(key, state)

    try:
        checkpoint = client.accepted_checkpoint()
        assert checkpoint is not None
        assert checkpoint["tree_size"] == 32

        for index in range(32, 64):
            log.append(f"entry-{index:04d}".encode())

        current, proof = synchronize_cosigner(log, client)
        assert current["tree_size"] == 64
        assert proof

        identity, signature = client.cosign_accepted(123)
        assert identity == IDENTITY
        assert signature

        checkpoint = client.accepted_checkpoint()
        assert checkpoint == {
            "tree_size": 64,
            "root_hash": bytes.fromhex(current["hash"]),
        }
    finally:
        stop_server(server, thread)

print("PASS: persistent issuance log growth through external HTTP cosigner")
