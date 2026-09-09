#!/usr/bin/env bash
set -euo pipefail
source /opt/lab/scenario.sh
merkle_args=()
if [[ $MERKLE_ENABLED == 1 ]]; then
  merkle_args=(-merkle_proof "${MERKLE_PROOF:-/work/merkle/$CERT_SCENARIO/proof-0000.bin}")
fi
exec "$OPENSSL_BIN" s_server -accept 4433 -tls1_3 -cert "/work/certs/$CERT_SCENARIO/server.pem" -key "/work/certs/$CERT_SCENARIO/server.key" -groups "${GROUPS_TLS:-X25519}" -ciphersuites TLS_AES_256_GCM_SHA384 -num_tickets 0 -www "${merkle_args[@]}" "$@"
