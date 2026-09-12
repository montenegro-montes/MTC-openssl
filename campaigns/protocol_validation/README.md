# Manual MTC protocol-conformance validation

**Preparation only. No validation, TLS, Docker, capture, build or fixture generation
was executed when preparing these files.** Wording: protocol-conformance validation
against the implemented subset of `draft-ietf-plants-merkle-tree-certs-05`.
Never interpret an overall PASS as full IETF draft compliance.

[FIELD_MAP.md](FIELD_MAP.md) is the byte-level decoder specification, implementation
map and checklist. Its references were read from the local draft, in targeted
sections only. Existing sources, fixtures, results and captures are not changed.

Files: `validate_mtc.py` checks a DER object offline using existing core.py and
OpenSSL; `negative_cases.py` prepares deterministic negative checks;
`capture_handshake.sh` / `capture.py` / `compose.yaml` capture one connection;
`extract_pcap.py` obtains DER **only from decrypted PCAP data**;
`report.py` joins the corresponding evidence into one JSON report.

## Bash menu

Open from the certification menu with option **6 — Protocolo MTC**, or directly:

```sh
bin/cryptographic_scaling/mt-cert-scaling protocol
# Equivalent:
bin/cryptographic_scaling/mt-protocol-validation menu
```

Initialize the separate configuration, then review **FIX**, **KEY** and **CAP**.
Defaults select legacy pq N=16, not Paper-1 mldsa65. It does not import the
certification campaign's paths because those fixtures use different CA IDs.
Dependencies are existing MTC N=16 fixtures and measurement/capture images;
X.509 chain scaling and crossover are not prerequisites.

The menu saves state in `.mt-state/protocol-validation/` and logs each selected
stage. `init`, `status`, `list`, `show` and opening the menu do not invoke Docker.
`run` executes exactly one manual stage. Outputs and PCAPs are never overwritten.
The offline stages run OpenSSL inside the existing measurement image, without TLS.

| Stage | Action |
|---|---|
| 10, 20, 30 | Existing object, landmark and standalone offline checks |
| 40, 50, 60, 70 | Landmark capture, extraction, wire-object validation, joined report |
| 80, 90, 100, 110 | Standalone capture, extraction, wire-object validation, joined report |
| 120 | Optional deterministic negatives with positive control |

Prior PASS reports are required at the corresponding gates; the standalone
capture requires a successful landmark protocol report. Underlying tools also
verify capture/fixture hashes. Directory existence is never treated as PASS.
Choose **Nueva campaña** (`new`) after a failure or for another attempt: previous
configuration/logs are archived, all scientific outputs remain intact, and routes
reset to the documented legacy defaults. Change FIX/KEY before the first run.
Once evidence exists, configuration is frozen; it cannot be silently redirected.
The lock covers this launcher only, not externally started campaigns.

## Inputs and prerequisites

Use existing **legacy pq**, N=16 fixtures for the first two representative captures.
Their scenarios remain `pq-mtc-experimental-landmark` and
`pq-mtc-experimental-standalone`. They are not the new Paper-1 `mldsa65` fixtures,
whose issuer IDs differ. The server private key must match leaf0's SPKI.
The default historical locations below follow the existing Compose configuration;
if your fixtures are elsewhere, change FIX/KEY to their actual existing paths.

Use the existing `mt-tls-measurement:local` and `mt-tls-capture:local` images.
The first must have the patched MTC OpenSSL; the second must already contain
Python3, tcpdump and tshark. **No script builds images or installs tools.**
Missing tools or a missing provider are blocking errors, not skipped PASS checks.
The workflow does not modify the active cert-scaling implementation/hash gate.
Do not use the performance campaign while interpreting these diagnostic captures.

Run the following manually from the repository root. The helper merely uses the
existing images, mounting inputs read-only and the new report directory writable:

```sh
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CAP="artifacts/protocol-validation/$STAMP"
FIX="artifacts/mtc/batch16-v2/pq"
KEY="artifacts/certs/pq/server.key"
mkdir -p artifacts/protocol-validation

protocol_tool() {
  local image="$1" script="$2"
  shift 2
  docker run --rm --network none \
    -v "$PWD:/repo:ro" \
    -v "$PWD/artifacts/protocol-validation:/repo/artifacts/protocol-validation" \
    -w /repo --entrypoint python3 "$image" \
    "campaigns/protocol_validation/$script" "$@"
}
```

All output names must be new. Stop on failure, preserve the failed output and
choose a fresh timestamp for another attempt. Metadata records exact image IDs,
source hashes, source commit, OpenSSL/liboqs/provider versions and input hashes.
The capture profile selector checks manifest identity; offline validation checks
actual key descriptions, IDs and signatures. No automatic retries or warmups.

## Required low-cost order

**1. One existing serialized object, offline.** With `authority.bin`, standalone
signatures authenticate the computed root, but there is no independent expected
root; the report correctly uses null for expected_root/root_match.

```sh
protocol_tool mt-tls-measurement:local validate_mtc.py \
  "$FIX/standalone-0000.der" --trust "$FIX/authority.bin" \
  --profile pq --mode standalone --output "$CAP/offline-existing.json"
```

**2. One N=16 landmark object offline.** The existing log entry supplies an
additional independent byte comparison for the reconstructed entry/SPKI binding.

```sh
protocol_tool mt-tls-measurement:local validate_mtc.py \
  "$FIX/landmark-0000.der" --trust "$FIX/trust.bin" \
  --entry "$FIX/log/000000.entry" --profile pq --mode landmark \
  --output "$CAP/offline-landmark.json"
```

**3. One N=16 standalone object offline**, now also against the signed checkpoint
and its expected subtree root:

```sh
protocol_tool mt-tls-measurement:local validate_mtc.py \
  "$FIX/standalone-0000.der" --trust "$FIX/trust.bin" \
  --entry "$FIX/log/000000.entry" --profile pq --mode standalone \
  --output "$CAP/offline-standalone.json"
```

**4. Capture exactly one landmark handshake.** Omitting `--execute` prints a plan.
This uses a fresh Compose project, the server's eth0 namespace and `tcp port 4433`,
as in the existing capture architecture but with one server/port only. No host
interfaces, health-check connections or unrelated traffic are captured. It writes
real tcpdump **PCAP** (`handshake.pcap`), not a PCAP renamed to `.pcapng`.

```sh
bash campaigns/protocol_validation/capture_handshake.sh \
  --mode landmark --profile pq --fixture-dir "$FIX" --server-key "$KEY" \
  --output "$CAP/landmark" --execute
```

**5. Extract exact on-wire DER**, with reassembly and TLS decryption:

```sh
protocol_tool mt-tls-capture:local extract_pcap.py "$CAP/landmark" \
  --sender "$FIX/landmark-0000.der" --output "$CAP/landmark/extracted"
```

**6. Validate the extracted object.** The input here is from PCAP, not FIX:

```sh
protocol_tool mt-tls-measurement:local validate_mtc.py \
  "$CAP/landmark/extracted/mtc-wire.bin" --trust "$FIX/trust.bin" \
  --entry "$FIX/log/000000.entry" --sender "$FIX/landmark-0000.der" \
  --profile pq --mode landmark --output "$CAP/landmark/object-validation.json"
```

**7. Join sender/wire/receiver comparison and protocol checks:**

```sh
protocol_tool mt-tls-measurement:local report.py --capture "$CAP/landmark" \
  --extraction "$CAP/landmark/extracted" \
  --object-report "$CAP/landmark/object-validation.json" \
  --output "$CAP/landmark/protocol-report.json"
```

**8. Repeat once for standalone**, only after the landmark report passes:

```sh
bash campaigns/protocol_validation/capture_handshake.sh \
  --mode standalone --profile pq --fixture-dir "$FIX" --server-key "$KEY" \
  --output "$CAP/standalone" --execute

protocol_tool mt-tls-capture:local extract_pcap.py "$CAP/standalone" \
  --sender "$FIX/standalone-0000.der" --output "$CAP/standalone/extracted"

protocol_tool mt-tls-measurement:local validate_mtc.py \
  "$CAP/standalone/extracted/mtc-wire.bin" --trust "$FIX/trust.bin" \
  --entry "$FIX/log/000000.entry" --sender "$FIX/standalone-0000.der" \
  --profile pq --mode standalone --output "$CAP/standalone/object-validation.json"

protocol_tool mt-tls-measurement:local report.py --capture "$CAP/standalone" \
  --extraction "$CAP/standalone/extracted" \
  --object-report "$CAP/standalone/object-validation.json" \
  --output "$CAP/standalone/protocol-report.json"
```

**9. Only if both pass**, repeat this sequence with existing N=16 fixtures for
`ecdsa-p256`, `mldsa65`, `slhdsa128s`, changing profile, FIX, KEY and output root.
For Paper-1 roots, FIX is `batch16/mtc/PROFILE`, KEY is `population/PROFILE/0.key`.
Do not rename their scenarios to `classic`/`pq`.

**10. Only after structural validation succeeds**, extend capture selection to
the remaining Paper-1 profiles. The offline validator already recognizes all nine;
the initial capture selector intentionally exposes only the three representative
Paper-1 algorithms plus legacy classic/pq. No full matrix is prepared or launched.

Optional deterministic negative checks, **not executed during preparation**:

```sh
protocol_tool mt-tls-measurement:local negative_cases.py \
  --fixtures "$FIX" --profile pq --output "$CAP/negative"
```

A positive control must pass first. Mutations are written only into the fresh
negative directory: truncation, trailing byte, bad length/index/issuer/proof hash,
signature, landmark number and checkpoint root. Failure to load a provider cannot
make an all-negative suite appear successful.

## Evidence boundaries and unresolved questions

- Native TLS1.3 carries the experimental certificate in Certificate (type11).
  Message order is ClientHello, ServerHello, EncryptedExtensions, Certificate,
  CertificateVerify, server Finished, client Finished. Server authentication only;
  fixed X25519/TLS_AES_256_GCM_SHA384, no tickets, PSK/resumption or early data.
- OpenSSL's existing **`-keylogfile`** exports secrets. `SSLKEYLOGFILE` environment
  support is not assumed. `-showcerts` exposes a reserialized received X509; the
  client does not preserve original raw DER. Compare its hash with the captured
  DER while documenting that limitation. Do not claim raw C-byte retention.
- tshark handles standard TLS framing/decryption; it is **not** assumed to decode
  the private proof. `extract_pcap.py` parses raw reassembled handshake bytes from
  PDML itself. If the installed version omits them, it stops with UNRESOLVED;
  there is no fallback to fixture bytes. Retain PDML/stderr for adapting extraction
  to that exact tshark version. Capture/decryption/extractor compatibility remains
  untested. CertificateVerify scheme is recorded, not mapped to guessed PQ IDs.
- Extraction records sequential TLS record numbers with packet numbers, handshake
  types/lengths, Certificate and CertificateVerify sizes, MTCProof and DER sizes,
  TCP stream and reassembly completion packet. All stream packet IDs and PDML
  are retained; completion packet alone is not a complete fragment attribution.
- Endpoint logs supply CertificateVerify/Finished acceptance evidence; there is no
  second independent cryptographic TLS-transcript verifier. `protocol-report.json`
  combines this with offline proof verification, rather than fabricating it.
- MCF1 is local out-of-band storage. The private 0xffa7 CH/EE/CertificateEntry
  negotiation is checked against source behavior, not claimed to implement the
  complete recommended trust_anchors extension. Draft OIDs/UTF8String are expressly
  experimental encodings in sections5.1/6.2, not unresolved guesses.
- Offline checks do not implement current-time PKIX validation or checkpoint
  freshness; native TLS additionally checks dates/hostname and rejects future
  checkpoint timestamps. No public transparency, general revocation, arbitrary
  extensions, evolving landmarks or full PKIX chain-building claim is made.
- Keep `tls.keys`, logs, received certificate, PCAP and hash metadata private as
  scientific artifacts. Do not edit any captured artifact; derived extraction and
  reports use fresh paths. No measurements from this workflow are performance data.
