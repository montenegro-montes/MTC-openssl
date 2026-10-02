"""Manual CA-side smoke client for the containerized external cosigner."""

import argparse
import json
from pathlib import Path

import core
from cosigner_http_client import CosignerHTTPClient, CosignerHTTPError


def client(arguments, certificate=True):
    options = {"ca_file": arguments.ca}
    if certificate:
        options.update(
            client_cert=arguments.client_cert,
            client_key=arguments.client_key,
        )
    return CosignerHTTPClient(arguments.url, **options)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("accept", "sign", "no-cert"))
    parser.add_argument("--url", default="https://localhost:8443")
    parser.add_argument("--ca", default="client/server-ca.pem")
    parser.add_argument("--client-cert", default="client/client.pem")
    parser.add_argument("--client-key", default="client/client.key")
    args = parser.parse_args()

    entries = [b"docker-smoke-0", b"docker-smoke-1", b"docker-smoke-2"]
    checkpoint = core.root(entries)
    if args.operation == "accept":
        accepted = client(args).accept_view(
            len(entries), checkpoint, core.consistency(entries, 0))
        print(json.dumps({
            "tree_size": accepted["tree_size"],
            "root_hash": accepted["root_hash"].hex(),
        }, sort_keys=True))
    elif args.operation == "sign":
        identity, signature = client(args).cosign_accepted(123)
        print(json.dumps({
            "identity": identity,
            "signature": signature.hex(),
        }, sort_keys=True))
    else:
        try:
            client(args, certificate=False).cosign_accepted(123)
        except CosignerHTTPError:
            print("PASS: client without certificate rejected")
        else:
            raise SystemExit("FAIL: client without certificate was accepted")


if __name__ == "__main__":
    main()
