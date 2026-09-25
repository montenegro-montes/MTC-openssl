#!/bin/sh
# Run inside the baseline BoringSSL container. No TLS or fixture generation.
set -eu
port_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
boringssl_dir=${BORINGSSL_DIR:-/opt/boringssl}
output_dir=$(mktemp -d /tmp/mtc-boringssl.XXXXXX)
echo "=== Compile isolated verifier ==="
cc -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra \
  -Werror=implicit-function-declaration -fmax-errors=12 \
  -I"$boringssl_dir/include" -c "$port_dir/check.c" -o "$output_dir/check.o"
echo "=== Locate BoringSSL libcrypto ==="
find "$boringssl_dir/build" -type f -name libcrypto.a > "$output_dir/libraries.txt"
if [ "$(wc -l < "$output_dir/libraries.txt" | tr -d ' ')" != 1 ]; then
  echo "Expected exactly one libcrypto.a; found:"
  cat "$output_dir/libraries.txt"
  exit 1
fi
crypto_library=$(cat "$output_dir/libraries.txt")
echo "=== Link isolated verifier ==="
c++ "$output_dir/check.o" "$crypto_library" -pthread -o "$output_dir/mtc-check"
echo "BUILD_OK: $output_dir/mtc-check"
echo "Compilation and linking only; cryptographic verification and TLS not tested."
