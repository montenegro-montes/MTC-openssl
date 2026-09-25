#!/bin/sh
# Offline checks against existing public fixtures. All mutations are temporary.
set -eu
port_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture_dir=${1:?Usage: test-verifier.sh FIXTURE_DIRECTORY}
. "$port_dir/build-verifier.sh"
passed=0
failed=0
check() {
  label=$1 expected=$2 trust=$3 mode=$4 cert=$5
  actual=0
  "$output_dir/mtc-check" "$trust" "$mode" "$cert" > "$output_dir/case.log" 2>&1 || actual=$?
  if [ "$actual" = "$expected" ]; then
    echo "PASS $label"
    passed=$((passed + 1))
  else
    echo "FAIL $label expected=$expected actual=$actual"
    cat "$output_dir/case.log"
    failed=$((failed + 1))
  fi
}
echo "=== BoringSSL revision ==="
cat "$boringssl_dir/../boringssl-commit.txt"
for family in ecdsa-p256 ecdsa-p384 ecdsa-p521 mldsa44 mldsa65 mldsa87 slhdsa128s slhdsa192s slhdsa256s; do
  for name in authority.bin trust.bin standalone-0000.der landmark-0000.der; do
    test -s "$fixture_dir/$family/$name" || { echo "Missing fixture: $family/$name"; exit 1; }
    sha256sum "$fixture_dir/$family/$name"
  done
done
for family in ecdsa-p256 ecdsa-p384 ecdsa-p521 mldsa44 mldsa65 mldsa87; do
  for mode in 0 1; do
    if [ "$mode" = 0 ]; then kind=standalone; config=authority.bin; else kind=landmark; config=trust.bin; fi
    trust="$fixture_dir/$family/$config"
    cert="$fixture_dir/$family/$kind-0000.der"
    check "$family/$kind valid" 0 "$trust" "$mode" "$cert"
    check "$family/$kind wrong mode" 1 "$trust" "$((1 - mode))" "$cert"
    bytes=$(wc -c < "$cert")
    dd if="$cert" of="$output_dir/truncated.der" bs=1 count="$((bytes - 1))" 2>/dev/null
    check "$family/$kind truncated" 1 "$trust" "$mode" "$output_dir/truncated.der"
    cp "$cert" "$output_dir/trailing.der"
    printf '\000' >> "$output_dir/trailing.der"
    check "$family/$kind trailing byte" 1 "$trust" "$mode" "$output_dir/trailing.der"
    if [ "$mode" = 0 ]; then
      last=$(tail -c 1 "$cert" | od -An -tu1 | tr -d ' ')
      cp "$output_dir/truncated.der" "$output_dir/signature.der"
      octal=$(printf '%03o' "$((last ^ 1))")
      printf "\\$octal" >> "$output_dir/signature.der"
      check "$family/$kind altered signature" 1 "$trust" "$mode" "$output_dir/signature.der"
    fi
  done
done
for family in slhdsa128s slhdsa192s slhdsa256s; do
  check "$family unsupported standalone" 1 "$fixture_dir/$family/authority.bin" 0 "$fixture_dir/$family/standalone-0000.der"
  check "$family unsupported landmark" 1 "$fixture_dir/$family/trust.bin" 1 "$fixture_dir/$family/landmark-0000.der"
done
echo "RESULT: $passed PASS, $failed FAIL (offline verifier only; no TLS)"
test "$failed" = 0
