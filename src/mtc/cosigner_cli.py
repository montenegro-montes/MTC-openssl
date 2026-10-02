"""Minimal JSON/hex command-line boundary for ExternalCosigner."""

import argparse
import json

from cosigner import ExternalCosigner


def hash_value(value):
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid hexadecimal value") from error


def proof_value(value):
    try:
        encoded = json.loads(value)
        if not isinstance(encoded, list) or not all(
                isinstance(item, str) for item in encoded):
            raise ValueError
        return [bytes.fromhex(item) for item in encoded]
    except (json.JSONDecodeError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            "proof must be a JSON array of hexadecimal strings") from error


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--identity", required=True)
    result.add_argument("--key", required=True)
    result.add_argument("--ca-id", required=True)
    result.add_argument("--family", required=True)
    result.add_argument("--log", required=True, type=int)
    result.add_argument("--state", required=True)
    operations = result.add_subparsers(dest="operation", required=True)

    accept = operations.add_parser("accept-view")
    accept.add_argument("--tree-size", required=True, type=int)
    accept.add_argument("--root-hash", required=True, type=hash_value)
    accept.add_argument(
        "--consistency-proof", required=True, type=proof_value)

    accepted = operations.add_parser("cosign-accepted")
    accepted.add_argument("--timestamp", required=True, type=int)

    subtree = operations.add_parser("cosign-subtree")
    subtree.add_argument("--start", required=True, type=int)
    subtree.add_argument("--end", required=True, type=int)
    subtree.add_argument("--subtree-hash", required=True, type=hash_value)
    subtree.add_argument(
        "--subtree-consistency-proof", required=True, type=proof_value)
    subtree.add_argument("--timestamp", required=True, type=int)
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    cosigner = ExternalCosigner(
        arguments.identity, arguments.key, arguments.ca_id,
        arguments.family, arguments.log, arguments.state)
    if arguments.operation == "accept-view":
        accepted = cosigner.accept_view(
            arguments.tree_size, arguments.root_hash,
            arguments.consistency_proof)
        emit({
            "tree_size": accepted.tree_size,
            "root_hash": accepted.root_hash.hex(),
        })
        return
    if arguments.operation == "cosign-accepted":
        identity, signature = cosigner.cosign_accepted(arguments.timestamp)
    else:
        identity, signature = cosigner.cosign_subtree(
            arguments.start, arguments.end, arguments.subtree_hash,
            arguments.subtree_consistency_proof, arguments.timestamp)
    emit({"identity": identity, "signature": signature.hex()})


if __name__ == "__main__":
    main()
