#!/bin/sh
set -eu
docker compose -f "$(dirname "$0")/../../docker/compose.network-combined.yaml" down --remove-orphans
