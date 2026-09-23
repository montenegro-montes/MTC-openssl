#!/bin/sh
set -eu
port_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture=${1:?Usage: test-clienthello.sh TRUST_BIN [standalone|landmark]}
output_dir=$(mktemp -d /tmp/mtc-clienthello.XXXXXX)
cc -std=c11 -D_POSIX_C_SOURCE=200809L \
  -Wall -Wextra -Werror=implicit-function-declaration \
  -I/opt/boringssl/include -c "$port_dir/clienthello-probe.c" -o "$output_dir/probe.o"
for library in ssl crypto; do
  find /opt/boringssl/build-mtc -type f -name "lib$library.a" > "$output_dir/$library.txt"
  test "$(wc -l < "$output_dir/$library.txt" | tr -d ' ')" = 1
done
c++ "$output_dir/probe.o" "$(cat "$output_dir/ssl.txt")" \
  "$(cat "$output_dir/crypto.txt")" -pthread -o "$output_dir/probe"
sha256sum "$fixture"
"$output_dir/probe" "$fixture" "${2:-standalone}"
