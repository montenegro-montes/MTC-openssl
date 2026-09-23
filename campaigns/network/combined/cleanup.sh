#!/bin/sh
set -eu
docker compose -f "$(dirname "$0")/../../../docker/network/compose.combined.yaml" down --remove-orphans
