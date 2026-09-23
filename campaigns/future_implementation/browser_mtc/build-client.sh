#!/bin/sh
set -eu
port_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_dir=${1:?Usage: build-client.sh OUTPUT_DIRECTORY}
mkdir -p "$output_dir"
cc -std=c11 -D_POSIX_C_SOURCE=200809L \
  -Wall -Wextra -Werror=implicit-function-declaration \
  -I/opt/boringssl/include -c "$port_dir/tls-client.c" -o "$output_dir/client.o"
for library in ssl crypto; do
  find /opt/boringssl/build-mtc -type f -name "lib$library.a" > "$output_dir/$library.txt"
  test "$(wc -l < "$output_dir/$library.txt" | tr -d ' ')" = 1
done
c++ "$output_dir/client.o" "$(cat "$output_dir/ssl.txt")" \
  "$(cat "$output_dir/crypto.txt")" -pthread -o "$output_dir/tls-client"
echo "BUILD_OK: TLS client"
