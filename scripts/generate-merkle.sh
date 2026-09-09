#!/usr/bin/env bash
set -euo pipefail
mkdir -p /work/merkle
for scenario in classic pq; do
  if [[ -e /work/merkle/$scenario ]]; then
    echo "Se conserva /work/merkle/$scenario (debe corresponder a sus certificados)."
    continue
  fi
  # Ordered fixture: server leaf first, CA certificate second. The CA's inclusion
  # is only a second tree leaf; it does not authenticate the Merkle root.
  /opt/mt/bin/mt_bundle "/work/merkle/$scenario" "/work/certs/$scenario/server.pem" "/work/certs/$scenario/ca.pem"
done
