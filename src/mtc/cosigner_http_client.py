"""Minimal urllib client for the external cosigner HTTP service."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class CosignerHTTPError(RuntimeError):
    def __init__(self, message, status=None, body=b""):
        super().__init__(message)
        self.status = status
        self.body = body


class CosignerHTTPClient:
    def __init__(self, base_url, timeout=2):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post(self, path, value):
        data = (json.dumps(
            value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        request = Request(
            self.base_url + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as response:
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
