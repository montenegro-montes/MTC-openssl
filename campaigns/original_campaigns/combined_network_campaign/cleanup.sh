#!/bin/sh
set -eu
docker compose -f "$(dirname "$0")/../../../docker/original_campaigns/compose.network-combined.yaml" down --remove-orphans
