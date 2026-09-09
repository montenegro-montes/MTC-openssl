#!/usr/bin/env bash
set -euo pipefail
source /opt/lab/scenario.sh
merkle_args=()
if [[ $MERKLE_ENABLED == 1 ]]; then
  merkle_args=(-merkle_root "${MERKLE_ROOT:-/work/merkle/$CERT_SCENARIO/root.bin}")
fi
printf 'GET / HTTP/1.0\r\n\r\n' | "$OPENSSL_BIN" s_client -connect "${TLS_HOST:-server}:4433" -servername server -verify_hostname server -verify_return_error -CAfile "/work/certs/$CERT_SCENARIO/ca.pem" -tls1_3 -groups "${GROUPS_TLS:-X25519}" -ciphersuites TLS_AES_256_GCM_SHA384 -no_ticket -ign_eof "${merkle_args[@]}" "$@"
