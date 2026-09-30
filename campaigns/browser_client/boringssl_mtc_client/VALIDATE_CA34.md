# Manual validation of the provisional 0xca34 migration

These commands were prepared but **not executed** for this migration. Run from
`/Users/joseantoniomontenegromontes/Desktop/MT`, in order, stopping on any failure.
Existing fixtures must still be within their validity dates for TLS. Do not
change the clock or bypass validation if they have expired. No fixture generation
or historical artifact rewriting is included. New image tags preserve old images.

## A. Static review

```bash
cd /Users/joseantoniomontenegromontes/Desktop/MT
git diff --check
git diff -- src/mtc campaigns/validation/protocol_validation docs campaigns/scaling bin/renders/protocol-validation.py
git status --short
git grep -n -i '0xffa7\|0xca34\|BORINGSSL_LAB_MTC_WIRE' -- src campaigns docs bin
rg -n '0xffa7|0xca34|BORINGSSL_LAB_MTC_WIRE|lab-wire.patch' campaigns/browser_client
```

`git diff` and `git grep` do not cover untracked files. Inspect the browser port
files directly if still untracked; no `git add` or commit is required. The only
active C use of the historical value should be its rejection in the probe.

## B. OpenSSL/MTC build and offline checks

Prerequisite: existing `mt-tls-lab:local` base image and the existing fixture tree.
The build also rebuilds the native retry peer from the shared MTC header.

```bash
docker build --progress=plain -f docker/base/Dockerfile.mtc -t mt-tls-mtc:ca34 .

docker run --rm --network none \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD:/repo:ro" -w /repo \
  --entrypoint sh mt-tls-mtc:ca34 -ec '
cc -Wall -Wextra -I/opt/openssl/include -I/repo/src/mtc \
  /repo/src/mtc/check.c -L/opt/openssl-mtc/lib \
  -Wl,-rpath,/opt/openssl-mtc/lib -lssl -lcrypto -o /tmp/mtc-check
python3 /repo/src/mtc/test_core.py
mkdir /tmp/mtc-test-batch
ln -s /repo/artifacts/mtc/n16-x25519-20260923T134045Z/batch16/mtc/ecdsa-p256 /tmp/mtc-test-batch/classic
ln -s /repo/artifacts/mtc/n16-x25519-20260923T134045Z/batch16/mtc/mldsa44 /tmp/mtc-test-batch/pq
MTC_BATCH=/tmp/mtc-test-batch python3 /repo/src/mtc/test_verifier.py
PYTHONPATH=/repo/src/mtc python3 -m unittest discover -s /repo/src/mtc -p test_retry.py
PYTHONPATH=/repo/src/mtc:/repo/campaigns/validation/protocol_validation \
  python3 -m unittest discover -s /repo/campaigns/validation/protocol_validation -p test_offline_semantics.py
'
```

The temporary `classic`/`pq` aliases point at existing public fixtures for the
legacy test interface. No fixture is generated or changed. The tests create
mutations only in temporary container directories. These are offline checks,
not proof of TLS retry interoperability.

## C. New capture and wire validation

Requires the existing `mt-tls-capture:local` image (tshark/tcpdump). Its old
OpenSSL binary is not used as a TLS endpoint: both endpoints use the new image.
Set a fresh output path, and capture standalone and landmark separately.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CAP="artifacts/protocol-validation/ca34-$STAMP"
FIX="artifacts/mtc/n16-x25519-20260923T134045Z/batch16/mtc/ecdsa-p256"
KEY="artifacts/mtc/n16-x25519-20260923T134045Z/population/ecdsa-p256/0.key"
mkdir -p artifacts/protocol-validation

protocol_ca34() {
  docker run --rm --network none -e PYTHONDONTWRITEBYTECODE=1 \
    -e PYTHONPATH=/repo/src/mtc:/repo/campaigns/validation/protocol_validation \
    -v "$PWD:/repo:ro" \
    -v "$PWD/artifacts/protocol-validation:/repo/artifacts/protocol-validation" \
    -w /repo --entrypoint python3 mt-tls-capture:local \
    "campaigns/validation/protocol_validation/$1" "${@:2}"
}

for MODE in standalone landmark; do
  bash campaigns/validation/protocol_validation/capture_handshake.sh \
    --mode "$MODE" --profile ecdsa-p256 --fixture-dir "$FIX" --server-key "$KEY" \
    --image mt-tls-mtc:ca34 --capture-image mt-tls-capture:local \
    --output "$CAP/$MODE" --execute || break
  protocol_ca34 extract_pcap.py "$CAP/$MODE" \
    --sender "$FIX/$MODE-0000.der" --output "$CAP/$MODE/extracted" || break
  protocol_ca34 verify_tls_transcript.py "$CAP/$MODE" \
    --openssl /opt/mtc/openssl.sh --output "$CAP/$MODE/independent.json" || break
done
```

Run the function/loop in bash or zsh. Inspect each extraction and independent
report: `trust_anchors_semantic_mapping.extension_codepoint` must be `0xca34`,
with matching CH/EE lists and an empty first CertificateEntry confirmation.
The current extractors only look up the active constant. They intentionally do
not revalidate old 0xffa7 captures. If PDML has no raw extension payload for a
recognized 0xca34 extension, preserve the failure and examine the exact-byte
transcript; do not infer payload bytes or substitute fixture data.

```bash
rg -n 'extension_codepoint|codepoint_status|wire_structure_match|message_semantics_match|status|reason' \
  "$CAP/standalone/extracted/extraction.json" "$CAP/standalone/independent.json" \
  "$CAP/landmark/extracted/extraction.json" "$CAP/landmark/independent.json"
```

## D. Native BoringSSL ClientHello probe

The baseline image must contain the pinned, unpatched upstream revision. The
Dockerfile checks the native header and does not apply any codepoint patch.

```bash
docker build --progress=plain \
  -f campaigns/browser_client/boringssl_mtc_client/Dockerfile.wire \
  -t mt-browser-boringssl:ca34 \
  campaigns/browser_client/boringssl_mtc_client

docker run --rm --network none \
  -v "$PWD/campaigns/browser_client/boringssl_mtc_client:/work/port:ro" \
  -v "$PWD/artifacts/mtc/n16-x25519-20260923T134045Z/batch16/mtc/ecdsa-p256:/work/fixtures:ro" \
  mt-browser-boringssl:ca34 \
  sh /work/port/test-clienthello.sh /work/fixtures/authority.bin
```

Expected: `PASS: TLS 1.3 ClientHello contains one matching 0xca34 extension; no 0xffa7`.

## E. BoringSSL TLS interoperability

First run one profile/mode, with its four existing positive/negative cases:

```bash
python3 campaigns/browser_client/boringssl_mtc_client/run-tls-smoke.py \
  --execute --mtc-root "$MTC_ROOT" \
  --profile ecdsa-p256 --mode standalone \
  --server-image mt-tls-mtc:ca34 --client-image mt-browser-boringssl:ca34
```

Only if it passes, run all six profiles, two modes and four cases (48 total):

```bash
python3 campaigns/browser_client/boringssl_mtc_client/run-tls-matrix.py \
  --execute --mtc-root "$MTC_ROOT" \
  --server-image mt-tls-mtc:ca34 --client-image mt-browser-boringssl:ca34
```

Expected: `MATRIX: 12 suites PASS, 0 suites FAIL`. This does not execute Chromium
or establish browser compatibility. All runners create new evidence directories.
