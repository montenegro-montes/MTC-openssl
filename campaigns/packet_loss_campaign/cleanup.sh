#!/bin/sh
set -eu

compose_file="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)/docker/compose.network-loss.yaml"
ids="$(docker compose -f "$compose_file" ps -q 2>/dev/null || true)"
for id in $ids; do
    docker exec "$id" tc qdisc del dev eth0 root 2>/dev/null || true
done
docker compose -f "$compose_file" down --remove-orphans
echo "Packet-loss qdiscs and containers removed. Results, fixtures and images preserved."
