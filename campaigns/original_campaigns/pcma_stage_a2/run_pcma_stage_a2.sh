#!/bin/sh
# No arguments print help. Experiments require --single or --full explicitly.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "${PYTHON:-python3}" "$SCRIPT_DIR/cli.py" "$@"
