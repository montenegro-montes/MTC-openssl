#!/usr/bin/env python3
"""Build the native MCF1 snapshot checker against an OpenSSL prefix."""

import argparse
from pathlib import Path
import subprocess


SOURCE = Path(__file__).resolve().with_name("check_snapshot.c")
REPO = SOURCE.parents[2]
DEFAULT_OUTPUT = REPO / ".mt-state" / "mtc" / "check_snapshot"


def build_check_snapshot(openssl_prefix, output, cc="cc", extra_flags=()):
    prefix = Path(openssl_prefix).resolve()
    output = Path(output).resolve()
    lib = prefix / "lib"
    if not lib.is_dir():
        lib = prefix / "lib64"
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        cc,
        "-Wall", "-Wextra", "-Werror",
        *extra_flags,
        "-I" + str(prefix / "include"),
        str(SOURCE),
        "-L" + str(lib),
        "-Wl,-rpath," + str(lib),
        "-lcrypto",
        "-o", str(output),
    ], check=True)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl-prefix", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    print(build_check_snapshot(args.openssl_prefix, args.output, args.cc))


if __name__ == "__main__":
    main()
