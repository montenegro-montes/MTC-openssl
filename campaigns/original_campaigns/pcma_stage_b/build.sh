#!/bin/sh
# Native build only. Does not connect sockets or launch containers.
set -eu
if [ "$#" -ne 2 ]; then
  echo 'Usage: build.sh OPENSSL_PREFIX NEW_OUTPUT_DIRECTORY'; exit 0
fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
PREFIX=$1
OUT=$2
[ ! -e "$OUT" ] || { echo 'Output exists' >&2; exit 1; }
mkdir -p "$OUT"
LIBDIR="$PREFIX/lib"
[ -d "$LIBDIR" ] || LIBDIR="$PREFIX/lib64"
cc -O2 -std=c11 -Wall -Wextra -Werror -Wno-misleading-indentation -Wno-unused-function -D_GNU_SOURCE\
  -I"$PREFIX/include" -I"$ROOT/integration" -I"$ROOT/codigoOriginal/C/crypto" \
  "$ROOT/campaigns/original_campaigns/pcma_stage_b/native/driver.c" \
  "$ROOT/campaigns/original_campaigns/pcma_stage_b/native/tls.c" \
  "$ROOT/campaigns/original_campaigns/pcma_stage_b/native/protocol.c" \
  "$ROOT/integration/mt_wire.c" "$ROOT/codigoOriginal/C/crypto/merkle.c" \
  -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lssl -lcrypto -o "$OUT/pcma_tls"
"$OUT/pcma_tls" --version > "$OUT/build-version.txt"
python3 - "$ROOT" "$OUT" <<'PYBUILD'
import hashlib,json,sys
from pathlib import Path
root,out=map(Path,sys.argv[1:])
files=list((root/'campaigns/original_campaigns/pcma_stage_b/native').glob('*'))+[root/x for x in ('compact/compact.c','compact/compact.h','integration/mt_wire.c','integration/mt_wire.h','codigoOriginal/C/crypto/merkle.c','codigoOriginal/C/crypto/merkle.h','campaigns/original_campaigns/pcma_stage_b/build.sh')]
(out/'build-inputs.json').write_text(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_file()},indent=2)+'\n')
PYBUILD
