"""Comparison of authenticated MTC checkpoint views."""

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from rp_updater import RPHTTPError, _checkpoint, advance_checkpoint


def _result(result, severity, first, second):
    return {
        "result": result,
        "severity": severity,
        "first": first,
        "second": second,
    }


def compare_checkpoints(
        first, second, log_url=None, advance=advance_checkpoint):
    """Compare two authenticated checkpoint views."""

    first = dict(_checkpoint(first))
    second = dict(_checkpoint(second))

    if first["log_number"] != second["log_number"]:
        return _result("DIFFERENT_LOG", "INFO", first, second)

    if first["tree_size"] == second["tree_size"]:
        if first["hash"] == second["hash"]:
            return _result("CONSISTENT", "PASS", first, second)
        return _result("SPLIT_VIEW", "ALERT", first, second)

    if log_url is None:
        return _result("NEEDS_CONSISTENCY", "INFO", first, second)

    if first["tree_size"] < second["tree_size"]:
        older, newer = first, second
    else:
        older, newer = second, first

    try:
        advanced = advance(log_url, older, newer)
    except RPHTTPError:
        return _result("UNAVAILABLE", "ERROR", first, second)
    except (ValueError, OSError):
        return _result("INCONSISTENT", "ALERT", first, second)

    if advanced != newer:
        return _result("INCONSISTENT", "ALERT", first, second)

    result = _result("CONSISTENT", "PASS", first, second)
    result.update({
        "consistency_verified": True,
        "consistency_old_size": older["tree_size"],
        "consistency_new_size": newer["tree_size"],
    })
    return result

def _load_checkpoint(path):
    try:
        value = json.loads(Path(path).read_text())
        return dict(_checkpoint(value))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid checkpoint file: {path}") from error


def _load_checkpoint_url(url):
    try:
        with urlopen(Request(url, method="GET"), timeout=5) as response:
            if response.status != 200:
                raise RPHTTPError("checkpoint HTTP request failed")
            data = response.read()
    except (HTTPError, URLError, OSError) as error:
        raise RPHTTPError("checkpoint HTTP request failed") from error
    try:
        value = json.loads(data)
        return dict(_checkpoint(value))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid checkpoint response: {url}") from error


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare two authenticated MTC checkpoint views."
    )
    first = parser.add_mutually_exclusive_group(required=True)
    first.add_argument("--first", help="first checkpoint JSON file")
    first.add_argument("--first-url", help="first checkpoint HTTP URL")
    second = parser.add_mutually_exclusive_group(required=True)
    second.add_argument("--second", help="second checkpoint JSON file")
    second.add_argument("--second-url", help="second checkpoint HTTP URL")
    parser.add_argument(
        "--log-url",
        help="MTC Log URL used to verify consistency when tree sizes differ",
    )
    args = parser.parse_args(argv)

    try:
        first = (_load_checkpoint_url(args.first_url) if args.first_url
                 else _load_checkpoint(args.first))
        second = (_load_checkpoint_url(args.second_url) if args.second_url
                  else _load_checkpoint(args.second))
        result = compare_checkpoints(
            first,
            second,
            log_url=args.log_url,
        )
    except ValueError as error:
        parser.error(str(error))

    print(json.dumps(result, sort_keys=True))

    if result["severity"] == "PASS":
        return 0
    if result["severity"] == "INFO":
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
