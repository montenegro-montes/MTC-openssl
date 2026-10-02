"""Minimal synchronous HTTP adapter for ExternalCosigner."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit

from cosigner import ExternalCosigner


MAX_BODY = 1024 * 1024


class ResponseSent(Exception):
    pass


def integer(value):
    if type(value) is not int:
        raise ValueError("expected integer")
    return value


def hash_value(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("expected 32-byte hexadecimal hash")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("expected 32-byte hexadecimal hash") from error
    if len(decoded) != 32:
        raise ValueError("expected 32-byte hexadecimal hash")
    return decoded


def proof_value(value):
    if not isinstance(value, list):
        raise ValueError("expected proof array")
    return [hash_value(item) for item in value]


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unexpected JSON fields")
    return value


class CosignerHTTPServer(HTTPServer):
    def __init__(self, address, identity, key, ca_id, family, state_path,
                 log=1, tls_cert=None, tls_key=None, client_ca=None,
                 require_client_cert=False):
        self.cosigner = ExternalCosigner(
            identity, key, ca_id, family, log=log, state_path=state_path)
        super().__init__(address, CosignerHTTPHandler)
        tls_values = (tls_cert, tls_key)
        if any(value is not None for value in tls_values):
            if any(value is None for value in tls_values):
                raise ValueError("TLS certificate and key are both required")
            if require_client_cert and client_ca is None:
                raise ValueError("client CA required for client certificates")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(tls_cert, tls_key)
            if client_ca is not None:
                context.load_verify_locations(cafile=client_ca)
                context.verify_mode = (
                    ssl.CERT_REQUIRED if require_client_cert
                    else ssl.CERT_OPTIONAL)
            self.socket = context.wrap_socket(self.socket, server_side=True)
        elif client_ca is not None or require_client_cert:
            raise ValueError("client certificate verification requires TLS")


class CosignerHTTPHandler(BaseHTTPRequestHandler):
    timeout = 2

    def setup(self):
        super().setup()
        self.connection.settimeout(self.timeout)

    def handle(self):
        try:
            super().handle()
        except OSError:
            self.close_connection = True

    def log_message(self, *args):
        pass

    def reply(self, status, value, allow=None):
        body = (json.dumps(
            value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        if code == 501:
            try:
                path = urlsplit(self.path).path
            except ValueError:
                self.reply(400, {"error": "Malformed request target"})
                return
            if path in self.endpoints:
                self.reply(405, {"error": "Method not allowed"}, "POST")
            else:
                self.reply(404, {"error": "Unknown endpoint"})
            return
        self.reply(code, {
            "error": self.responses.get(code, ("Request failed",))[0]})

    endpoints = {
        "/accept-view",
        "/cosign-accepted",
        "/cosign-subtree",
    }

    def do_POST(self):
        try:
            parsed = urlsplit(self.path)
            if parsed.path not in self.endpoints:
                self.reply(404, {"error": "Unknown endpoint"})
                return
            if parsed.query or parsed.fragment:
                raise ValueError("unexpected request parameters")
            request = self.read_json()
            action = self.action(parsed.path, request)
        except TimeoutError:
            self.close_connection = True
            self.reply(408, {"error": "Request body timed out"})
            return
        except ResponseSent:
            return
        except ValueError as error:
            self.reply(400, {"error": str(error)})
            return
        except OSError:
            self.close_connection = True
            self.reply(400, {"error": "Incomplete request body"})
            return
        try:
            value = action()
        except (ValueError, OverflowError):
            self.reply(400, {"error": "Cosigner rejected request"})
            return
        except Exception:
            self.reply(500, {"error": "Cosigner unavailable"})
            return
        self.reply(200, value)

    def read_json(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is unsupported")
        if not lengths:
            self.reply(411, {"error": "Content-Length required"})
            raise ResponseSent
        if len(lengths) != 1:
            raise ValueError("Ambiguous Content-Length")
        text = lengths[0]
        if not text.isascii() or not text.isdecimal() or len(text) > 15:
            raise ValueError("Invalid Content-Length")
        length = int(text)
        if length > MAX_BODY:
            self.reply(413, {"error": "Request exceeds 1 MiB"})
            raise ResponseSent
        deadline = time.monotonic() + self.timeout
        data = bytearray()
        while len(data) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self.connection.settimeout(remaining)
            chunk = self.rfile.read1(length - len(data))
            if not chunk:
                break
            data.extend(chunk)
        self.connection.settimeout(self.timeout)
        if len(data) != length:
            raise ValueError("Truncated request body")
        try:
            return json.loads(bytes(data).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Malformed JSON") from error

    def action(self, path, request):
        if path == "/accept-view":
            value = fields(request, (
                "tree_size", "root_hash", "consistency_proof"))
            tree_size = integer(value["tree_size"])
            root_hash = hash_value(value["root_hash"])
            proof = proof_value(value["consistency_proof"])
            def accept():
                accepted = self.server.cosigner.accept_view(
                    tree_size, root_hash, proof)
                return {
                    "tree_size": accepted.tree_size,
                    "root_hash": accepted.root_hash.hex(),
                }
            return accept
        if path == "/cosign-accepted":
            value = fields(request, ("timestamp",))
            timestamp = integer(value["timestamp"])
            def cosign_accepted():
                identity, signature = self.server.cosigner.cosign_accepted(
                    timestamp)
                return {"identity": identity, "signature": signature.hex()}
            return cosign_accepted
        value = fields(request, (
            "start", "end", "subtree_hash",
            "subtree_consistency_proof", "timestamp"))
        start = integer(value["start"])
        end = integer(value["end"])
        subtree_hash = hash_value(value["subtree_hash"])
        proof = proof_value(value["subtree_consistency_proof"])
        timestamp = integer(value["timestamp"])
        def cosign_subtree():
            identity, signature = self.server.cosigner.cosign_subtree(
                start, end, subtree_hash, proof, timestamp)
            return {"identity": identity, "signature": signature.hex()}
        return cosign_subtree

    def do_GET(self):
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self.reply(400, {"error": "Malformed request target"})
            return
        if parsed.query or parsed.fragment:
            self.reply(400, {"error": "unexpected request parameters"})
            return
        if parsed.path == "/accepted":
            accepted = self.server.cosigner.accepted
            if accepted is None:
                self.reply(200, {"accepted": None})
            else:
                self.reply(200, {"accepted": {
                    "tree_size": accepted.tree_size,
                    "root_hash": accepted.root_hash.hex(),
                }})
        elif parsed.path in self.endpoints:
            self.reply(405, {"error": "Method not allowed"}, "POST")
        else:
            self.reply(404, {"error": "Unknown endpoint"})

    do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca-id", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--log", type=int, default=1)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--client-ca")
    parser.add_argument("--require-client-cert", action="store_true")
    args = parser.parse_args()
    with CosignerHTTPServer(
            (args.host, args.port), args.identity, Path(args.key), args.ca_id,
            args.family, Path(args.state), args.log,
            args.tls_cert, args.tls_key, args.client_ca,
            args.require_client_cert) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
