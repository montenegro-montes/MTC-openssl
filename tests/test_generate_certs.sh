#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/work"

cat >"$tmp/bin/openssl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MOCK_LOG"
printf '\n' >>"$MOCK_LOG"
out=''
while (($#)); do
  if [[ $1 == -out && $# -ge 2 ]]; then out=$2; shift 2; else shift; fi
done
[[ -z $out ]] || : >"$out"
MOCK

cat >"$tmp/bin/mt_bundle" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MOCK_BUNDLE_LOG"
printf '\n' >>"$MOCK_BUNDLE_LOG"
mkdir "$1"
touch "$1/root.bin" "$1/proof-0000.bin"
MOCK
chmod +x "$tmp/bin/openssl" "$tmp/bin/mt_bundle"

export PATH="$tmp/bin:$PATH"
export WORK_ROOT="$tmp/work"
export MERKLE_SCRIPT="$repo/scripts/fixtures/generate-merkle.sh"
export MT_BUNDLE="$tmp/bin/mt_bundle"
export MOCK_LOG="$tmp/openssl.log"
export MOCK_BUNDLE_LOG="$tmp/bundle.log"

bash "$repo/scripts/fixtures/generate-certs.sh" \
  --profile ecdsa-p384 --algorithm EC \
  --pkeyopt ec_paramgen_curve:P-384 \
  --digest sha384 --sigopt ecdsa_nonce_type:1 --days 45

test -f "$tmp/work/certs/ecdsa-p384/server.pem"
test -f "$tmp/work/certs/ecdsa-p384/server.der"
test -f "$tmp/work/certs/ecdsa-p384/generation-parameters.txt"
test -f "$tmp/work/merkle/ecdsa-p384/root.bin"
test "$(grep -c 'genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384' "$MOCK_LOG")" -eq 2
grep -q -- '-sha384' "$MOCK_LOG"
grep -q -- '-sigopt ecdsa_nonce_type:1' "$MOCK_LOG"
grep -q -- '-days 45' "$MOCK_LOG"
grep -q '^algorithm=EC$' "$tmp/work/certs/ecdsa-p384/generation-parameters.txt"
grep -q '^pkeyopt=ec_paramgen_curve:P-384$' "$tmp/work/certs/ecdsa-p384/generation-parameters.txt"
grep -q '^sigopt=ecdsa_nonce_type:1$' "$tmp/work/certs/ecdsa-p384/generation-parameters.txt"

before=$(wc -l <"$MOCK_LOG")
bash "$repo/scripts/fixtures/generate-certs.sh" \
  --profile ecdsa-p384 --algorithm EC --pkeyopt ec_paramgen_curve:P-256
test "$(wc -l <"$MOCK_LOG")" -eq "$before"

export WORK_ROOT="$tmp/default-work"
mkdir -p "$WORK_ROOT"
bash "$repo/scripts/fixtures/generate-certs.sh"
test -f "$WORK_ROOT/certs/classic/server.pem"
test -f "$WORK_ROOT/certs/pq/server.pem"
test -f "$WORK_ROOT/merkle/classic/root.bin"
test -f "$WORK_ROOT/merkle/pq/root.bin"
grep -q '^algorithm=EC$' "$WORK_ROOT/certs/classic/generation-parameters.txt"
grep -q '^pkeyopt=ec_paramgen_curve:P-256$' "$WORK_ROOT/certs/classic/generation-parameters.txt"
grep -q '^algorithm=ML-DSA-65$' "$WORK_ROOT/certs/pq/generation-parameters.txt"

export WORK_ROOT="$tmp/work"
if bash "$repo/scripts/fixtures/generate-certs.sh" --profile ../escape --algorithm EC \
  >"$tmp/invalid.out" 2>"$tmp/invalid.err"; then
  echo 'invalid profile unexpectedly accepted' >&2
  exit 1
fi
test ! -e "$tmp/escape"

bash "$repo/scripts/fixtures/generate-certs.sh" --help | grep -q -- '--pkeyopt OPTION'
echo 'PASS configurable certificate generation'
