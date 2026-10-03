"""Minimal urllib client for the external cosigner HTTP service."""

import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit


class CosignerHTTPError(RuntimeError):
    def __init__(self, message, status=None, body=b""):
        super().__init__(message)
        self.status = status
        self.body = body


class CosignerHTTPClient:
    def __init__(self, base_url, timeout=2, ca_file=None,
                 client_cert=None, client_key=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._log = None
        scheme = urlsplit(self.base_url).scheme
        tls_values = (client_cert, client_key)
        if any(value is not None for value in tls_values) and any(
                value is None for value in tls_values):
            raise ValueError("client certificate and key are both required")
        if scheme == "https":
            self.ssl_context = ssl.create_default_context(cafile=ca_file)
            if client_cert is not None:
                self.ssl_context.load_cert_chain(client_cert, client_key)
        elif ca_file is not None or client_cert is not None:
            raise ValueError("TLS configuration requires an https URL")
        else:
            self.ssl_context = None

    def _post(self, path, value):
        data = (json.dumps(
            value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        request = Request(
            self.base_url + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        return self._request(request)

    def _get(self, path):
        request = Request(self.base_url + path, method="GET")
        return self._request(request)

    def _request(self, request):
        try:
            with urlopen(
                    request, timeout=self.timeout,
                    context=self.ssl_context) as response:
                body = response.read(1024 * 1024 + 1)
                status = response.status
        except HTTPError as error:
            body = error.read(1024 * 1024 + 1)
            raise CosignerHTTPError(
                f"cosigner HTTP request failed with status {error.code}",
                error.code, body) from error
        except (URLError, OSError) as error:
            raise CosignerHTTPError(
                "unable to reach cosigner HTTP service") from error
        if status != 200:
            raise CosignerHTTPError(
                f"cosigner HTTP request failed with status {status}",
                status, body)
        if len(body) > 1024 * 1024:
            raise CosignerHTTPError("cosigner HTTP response exceeds 1 MiB")
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CosignerHTTPError(
                "cosigner HTTP service returned invalid JSON",
                status, body) from error
        if not isinstance(result, dict):
            raise CosignerHTTPError(
                "cosigner HTTP service returned an invalid response",
                status, body)
        return result

    def accepted_checkpoint(self):
        result = self._get("/accepted")
        try:
            if set(result) != {"log_number", "accepted"}:
                raise ValueError
            log_number = result["log_number"]
            if type(log_number) is not int or not 1 <= log_number <= 65535:
                raise ValueError
            accepted = result["accepted"]
            if accepted is None:
                self._log = log_number
                return None
            if not isinstance(accepted, dict) or set(accepted) != {
                    "tree_size", "root_hash"}:
                raise ValueError
            tree_size = accepted["tree_size"]
            root_hash = bytes.fromhex(accepted["root_hash"])
            if type(tree_size) is not int or not 0 <= tree_size < 1 << 48:
                raise ValueError
            if len(root_hash) != 32:
                raise ValueError
        except (TypeError, ValueError) as error:
            raise CosignerHTTPError(
                "cosigner HTTP service returned an invalid checkpoint") from error
        self._log = log_number
        return {"tree_size": tree_size, "root_hash": root_hash}

    @property
    def log(self):
        return self._log

    @staticmethod
    def _proof(proof):
        return [value.hex() for value in proof]

    def accept_view(self, tree_size, root_hash, consistency_proof):
        result = self._post("/accept-view", {
            "tree_size": tree_size,
            "root_hash": root_hash.hex(),
            "consistency_proof": self._proof(consistency_proof),
        })
        try:
            if set(result) != {"tree_size", "root_hash"}:
                raise ValueError
            accepted_size = result["tree_size"]
            accepted_root = bytes.fromhex(result["root_hash"])
            if type(accepted_size) is not int or len(accepted_root) != 32:
                raise ValueError
        except (TypeError, ValueError) as error:
            raise CosignerHTTPError(
                "cosigner HTTP service returned an invalid checkpoint") from error
        return {"tree_size": accepted_size, "root_hash": accepted_root}

    def _signature(self, path, value):
        result = self._post(path, value)
        try:
            if set(result) != {"identity", "signature"}:
                raise ValueError
            identity = result["identity"]
            signature = bytes.fromhex(result["signature"])
            if not isinstance(identity, str):
                raise ValueError
        except (TypeError, ValueError) as error:
            raise CosignerHTTPError(
                "cosigner HTTP service returned an invalid signature") from error
        return identity, signature

    def cosign_accepted(self, timestamp=0):
        return self._signature(
            "/cosign-accepted", {"timestamp": timestamp})

    def cosign_subtree(self, start, end, subtree_hash,
                       subtree_consistency_proof, timestamp=0):
        return self._signature("/cosign-subtree", {
            "start": start,
            "end": end,
            "subtree_hash": subtree_hash.hex(),
            "subtree_consistency_proof": self._proof(
                subtree_consistency_proof),
            "timestamp": timestamp,
        })
