"""Fail-closed relying-party checkpoint update primitives."""

import json
from pathlib import Path
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from core import verify_consistency
from snapshots import authenticate_snapshot


def _get(base_url, path, binary=False):
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        with urlopen(Request(url, method="GET"), timeout=5) as response:
            if response.status != 200:
                raise ValueError("HTTP request failed")
            data = response.read()
            content_type = response.headers.get_content_type()
    except (HTTPError, URLError, OSError) as exc:
        raise ValueError("HTTP request failed") from exc

    if binary:
        return data

    if content_type != "application/json":
        raise ValueError("Expected JSON response")

    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON response") from exc

    if not isinstance(value, dict):
        raise ValueError("Invalid JSON response")
    return value


def _checkpoint(state):
    if (not isinstance(state, dict)
            or set(state) != {"tree_size", "hash"}
            or type(state["tree_size"]) is not int
            or not 0 <= state["tree_size"] < 1 << 48
            or not isinstance(state["hash"], str)
            or len(state["hash"]) != 64):
        raise ValueError("Invalid checkpoint state")
    try:
        root_hash = bytes.fromhex(state["hash"])
    except ValueError as exc:
        raise ValueError("Invalid checkpoint state") from exc
    if len(root_hash) != 32:
        raise ValueError("Invalid checkpoint state")
    return state


def fetch_authenticated_checkpoint(
        base_url, trusted_authority, checker,
        authenticate=authenticate_snapshot):
    data = _get(base_url, "/snapshot", binary=True)

    with tempfile.TemporaryDirectory(prefix="mtc-rp-snapshot-") as temporary:
        snapshot = Path(temporary) / "snapshot.mcf1"
        snapshot.write_bytes(data)
        state = authenticate(snapshot, trusted_authority, checker)

    return dict(_checkpoint(state))


def advance_checkpoint(
        base_url, previous, candidate):
    candidate = _checkpoint(candidate)

    if previous is None:
        return dict(candidate)

    previous = _checkpoint(previous)
    old_size = previous["tree_size"]
    new_size = candidate["tree_size"]

    if new_size < old_size:
        raise ValueError("Checkpoint rollback")

    if new_size == old_size:
        if candidate["hash"] != previous["hash"]:
            raise ValueError("Checkpoint hash changed at same tree size")
        return dict(candidate)

    query = urlencode({"old": old_size, "new": new_size})
    result = _get(base_url, "/proof/consistency?" + query)

    required = {
        "old_size", "new_size", "old_hash", "new_hash", "proof", "unsigned"
    }
    if set(result) != required:
        raise ValueError("Invalid consistency response")

    if (result["old_size"] != old_size
            or result["new_size"] != new_size
            or result["old_hash"] != previous["hash"]
            or result["new_hash"] != candidate["hash"]
            or result["unsigned"] is not True
            or not isinstance(result["proof"], list)):
        raise ValueError("Consistency response does not match checkpoints")

    try:
        proof = [bytes.fromhex(value) for value in result["proof"]]
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid consistency proof") from exc

    if any(len(value) != 32 for value in proof):
        raise ValueError("Invalid consistency proof")

    if not verify_consistency(
            old_size, new_size,
            bytes.fromhex(previous["hash"]),
            bytes.fromhex(candidate["hash"]),
            proof):
        raise ValueError("Checkpoint consistency verification failed")

    return dict(candidate)


def fetch_and_advance_checkpoint(
        base_url, trusted_authority, checker, previous=None,
        authenticate=authenticate_snapshot):
    candidate = fetch_authenticated_checkpoint(
        base_url, trusted_authority, checker, authenticate)
    return advance_checkpoint(base_url, previous, candidate)
