"""Fail-closed relying-party checkpoint update primitives."""

import json
from pathlib import Path
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from core import verify_consistency
from landmarks import active, subtrees, validate_sequence
from snapshots import authenticate_snapshot, authenticate_snapshot_metadata
from rp_policy import RPFreshnessPolicy, check_checkpoint_freshness
from rp_state import RPStateStore
from trusted_subtrees import (
    SubtreeEvidence,
    encode_trusted_subtrees,
    validate_trusted_subtrees,
)


class RPHTTPError(ValueError):
    """The remote log service could not provide an HTTP response."""


def _get(base_url, path, binary=False):
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        with urlopen(Request(url, method="GET"), timeout=5) as response:
            if response.status != 200:
                raise RPHTTPError("HTTP request failed")
            data = response.read()
            content_type = response.headers.get_content_type()
    except (HTTPError, URLError, OSError) as exc:
        raise RPHTTPError("HTTP request failed") from exc

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
            or set(state) != {"log_number", "tree_size", "hash"}
            or type(state["log_number"]) is not int
            or not 1 <= state["log_number"] <= 65535
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
        authenticate=authenticate_snapshot,
        freshness_policy=None, now=None):
    data = _get(base_url, "/snapshot", binary=True)

    with tempfile.TemporaryDirectory(prefix="mtc-rp-snapshot-") as temporary:
        snapshot = Path(temporary) / "snapshot.mcp2"
        snapshot.write_bytes(data)

        if (freshness_policy is None
                or (isinstance(freshness_policy, RPFreshnessPolicy)
                    and not freshness_policy.enabled)):
            state = authenticate(snapshot, trusted_authority, checker)
        else:
            if not isinstance(freshness_policy, RPFreshnessPolicy):
                raise ValueError("invalid RP freshness policy")
            metadata = authenticate_snapshot_metadata(
                snapshot, trusted_authority, checker,
                authenticate=authenticate)
            check_checkpoint_freshness(
                metadata["timestamp"], freshness_policy, now)
            state = {
                "log_number": metadata["log_number"],
                "tree_size": metadata["tree_size"],
                "hash": metadata["hash"],
            }

    return dict(_checkpoint(state))


def advance_checkpoint(
        base_url, previous, candidate):
    candidate = _checkpoint(candidate)

    if previous is None:
        return dict(candidate)

    previous = _checkpoint(previous)
    if previous["log_number"] != candidate["log_number"]:
        raise ValueError("Cannot advance checkpoint across issuance logs")
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
        authenticate=authenticate_snapshot,
        freshness_policy=None, now=None):
    candidate = fetch_authenticated_checkpoint(
        base_url, trusted_authority, checker,
        authenticate=authenticate,
        freshness_policy=freshness_policy,
        now=now,
    )
    return advance_checkpoint(base_url, previous, candidate)


def fetch_subtree_evidence(
        base_url, sequence, now, reference_checkpoint):
    """Fetch untrusted Section 4.4 evidence for active landmarks."""
    validate_sequence(sequence)
    checkpoint = _checkpoint(reference_checkpoint)
    tree_size = checkpoint["tree_size"]

    evidence = []

    for landmark in active(sequence, now):
        # A reference checkpoint older than this landmark cannot validate it
        # or any newer landmark.  Let validate_trusted_subtrees retain the
        # complete older prefix.
        if landmark.tree_size > tree_size:
            break

        for start, end in subtrees(sequence, landmark.number):
            query = urlencode({
                "start": start,
                "end": end,
                "size": tree_size,
            })
            result = _get(base_url, "/proof/subtree?" + query)

            required = {
                "start", "end", "tree_size",
                "hash", "proof", "unsigned",
            }
            if set(result) != required:
                raise ValueError("Invalid subtree response")

            if (result["start"] != start
                    or result["end"] != end
                    or result["tree_size"] != tree_size
                    or result["unsigned"] is not True
                    or not isinstance(result["hash"], str)
                    or not isinstance(result["proof"], list)):
                raise ValueError(
                    "Subtree response does not match requested interval")

            try:
                node_hash = bytes.fromhex(result["hash"])
                proof = tuple(
                    bytes.fromhex(value) for value in result["proof"])
            except (TypeError, ValueError) as exc:
                raise ValueError("Invalid subtree evidence") from exc

            if (len(node_hash) != 32
                    or any(len(value) != 32 for value in proof)):
                raise ValueError("Invalid subtree evidence")

            evidence.append(
                SubtreeEvidence(start, end, node_hash, proof))

    return evidence


def build_trusted_subtree_configuration(
        base_url, log_number, sequence, now, reference_checkpoint,
        max_active_landmarks=None):
    """Build validated Section 7.4 trusted-subtree state and MTS1 bytes."""
    checkpoint = dict(_checkpoint(reference_checkpoint))
    if type(log_number) is not int or not 1 <= log_number <= 65535:
        raise ValueError("Invalid issuance log number")
    if checkpoint["log_number"] != log_number:
        raise ValueError("Trusted-subtree log differs from authenticated checkpoint")

    evidence = fetch_subtree_evidence(
        base_url, sequence, now, checkpoint)

    trusted = validate_trusted_subtrees(
        log_number,
        sequence,
        now,
        {
            "tree_size": checkpoint["tree_size"],
            "hash": checkpoint["hash"],
        },
        evidence,
        max_active_landmarks=max_active_landmarks,
    )

    mts1 = encode_trusted_subtrees(trusted)
    return trusted, mts1



def publish_remote_state(
        base_url, checkpoint, trusted_subtrees, retained_landmark=None):
    """Publish already-validated RP state to a remote RP server."""
    checkpoint = _checkpoint(checkpoint)

    if not isinstance(trusted_subtrees, bytes):
        raise ValueError("trusted-subtree state must be bytes")

    if (retained_landmark is not None
            and (type(retained_landmark) is not int
                 or not 1 <= retained_landmark < 1 << 48)):
        raise ValueError("invalid retained landmark")

    url = urljoin(
        base_url.rstrip("/") + "/",
        "internal/state",
    )

    headers = {
        "Content-Type": "application/octet-stream",
        "MTC-RP-Version": "1",
        "MTC-Log-Number": str(checkpoint["log_number"]),
        "MTC-Tree-Size": str(checkpoint["tree_size"]),
        "MTC-Checkpoint-Hash": checkpoint["hash"],
        "MTC-Retained-Landmark": (
            "none"
            if retained_landmark is None
            else str(retained_landmark)
        ),
    }

    request = Request(
        url,
        data=trusted_subtrees,
        headers=headers,
        method="PUT",
    )

    try:
        with urlopen(request, timeout=5) as response:
            if response.status != 204:
                raise RPHTTPError("RP state publication failed")
    except (HTTPError, URLError, OSError) as exc:
        raise RPHTTPError("RP state publication failed") from exc


def _prepare_update(
        base_url, trusted_authority, checker, store,
        log_number, sequence, now, max_active_landmarks=None,
        authenticate=authenticate_snapshot, freshness_policy=None):
    """Build one validated RP state update without publishing it."""
    current = store.load_current()

    previous = None
    if (current is not None
            and current["checkpoint"]["log_number"] == log_number):
        previous = current["checkpoint"]

    checkpoint = fetch_and_advance_checkpoint(
        base_url,
        trusted_authority,
        checker,
        previous=previous,
        authenticate=authenticate,
        freshness_policy=freshness_policy,
        now=now,
    )

    if checkpoint["log_number"] != log_number:
        raise ValueError(
            "Authenticated checkpoint issuance log differs from requested log"
        )

    trusted, mts1 = build_trusted_subtree_configuration(
        base_url,
        log_number,
        sequence,
        now,
        checkpoint,
        max_active_landmarks=max_active_landmarks,
    )

    return checkpoint, mts1, trusted.retained_landmark


def update_and_publish(
        base_url, trusted_authority, checker, state_directory,
        log_number, sequence, now, max_active_landmarks=None,
        authenticate=authenticate_snapshot, freshness_policy=None):
    """Run one complete fail-closed relying-party update transaction.

    freshness_policy is an optional local RP policy applied to the
    authenticated MCP2 checkpoint timestamp; it is not a Draft-07
    certificate or MTCProof verification requirement.
    """
    store = RPStateStore(state_directory)

    checkpoint, mts1, retained_landmark = _prepare_update(
        base_url,
        trusted_authority,
        checker,
        store,
        log_number,
        sequence,
        now,
        max_active_landmarks=max_active_landmarks,
        authenticate=authenticate,
        freshness_policy=freshness_policy,
    )

    return store.publish(checkpoint, mts1, retained_landmark)


def update_and_publish_remote(
        base_url, trusted_authority, checker, state_directory,
        rp_url, log_number, sequence, now, max_active_landmarks=None,
        authenticate=authenticate_snapshot, freshness_policy=None):
    """Run one fail-closed RP update and publish it to a remote RP server.

    state_directory is private updater state.  It records the last
    successfully distributed validated state used for subsequent
    checkpoint consistency verification.
    """
    store = RPStateStore(state_directory)

    checkpoint, mts1, retained_landmark = _prepare_update(
        base_url,
        trusted_authority,
        checker,
        store,
        log_number,
        sequence,
        now,
        max_active_landmarks=max_active_landmarks,
        authenticate=authenticate,
        freshness_policy=freshness_policy,
    )

    publish_remote_state(
        rp_url,
        checkpoint,
        mts1,
        retained_landmark,
    )

    return store.publish(checkpoint, mts1, retained_landmark)
