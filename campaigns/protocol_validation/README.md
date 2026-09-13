# Manual MTC protocol-conformance validation

**No new TLS, Docker, capture, build or fixture generation was executed for the
2026-09-13 validation refinement. Pure-Python tests and one existing landmark
PCAP were checked offline; see the supplemental review below.** Wording: protocol-conformance validation
against the implemented subset of `draft-ietf-plants-merkle-tree-certs-05`.
Never interpret an overall PASS as full IETF draft compliance.

[FIELD_MAP.md](FIELD_MAP.md) is the byte-level decoder specification, implementation
map and checklist. Its references were read from the local draft, in targeted
sections only. Existing sources, fixtures, results and captures are not changed.

Files: `validate_mtc.py` checks a DER object offline using existing core.py and
OpenSSL; `negative_cases.py` prepares deterministic invalid-input stress checks;
`capture_handshake.sh` / `capture.py` / `compose.yaml` capture one connection;
`extract_pcap.py` obtains DER **only from decrypted PCAP data**;
`report.py` joins the corresponding evidence into one JSON report.

## Bash menu

Open from the certification menu with option **6 — MTC protocol**, or directly:

```sh
bin/cryptographic_scaling/mt-cert-scaling protocol
# Equivalent:
bin/cryptographic_scaling/mt-protocol-validation menu
```

New configurations select **Paper-1 mldsa65 N=16** from the MTC16 path saved by
`mt-cert-scaling`. Existing configurations without PROFILE preserve their legacy
pq meaning. No historical campaign is required for the new path.

### Before the first run

```sh
# Prepare image dependencies independently; no original campaign is invoked.
bin/cryptographic_scaling/mt-prepare run ALL

# First use only. Generate and validate N=16 if it does not already exist.

# First use only; imports the MTC16 path, not previous results.
bin/cryptographic_scaling/mt-protocol-validation status
bin/cryptographic_scaling/mt-protocol-validation run 10
```

If state or fixtures already exist, inspect `status` and continue from the next
required stage instead of repeating completed commands. Protocol initialization
only records PROFILE/FIX/KEY/CAP; it does not generate certificates. With new
Paper-1 configurations FIX is MTC16/batch16/mtc/mldsa65 and KEY is
MTC16/population/mldsa65/0.key. Neither the crossover nor X.509 chain fixtures are
required. Missing inputs produce an error; correct paths before retrying.

For a fresh protocol run after historical evidence already exists, use `new` to
archive the old launcher state and configure the Paper-1 defaults. To deliberately
initialize the historical pq workflow instead, use `init-legacy` with existing
historical fixtures. Do not relabel those fixtures as mldsa65: the CA IDs differ.
PROFILE, FIX and KEY can be set explicitly before any evidence is written.

The menu saves state in `.mt-state/protocol-validation/` and logs each selected
stage. `init`, `status`, `list`, `show` and opening the menu do not invoke Docker.
`run` executes exactly one manual stage. Outputs and PCAPs are never overwritten.
The offline stages run OpenSSL inside the existing measurement image, without TLS.

| Stage | Action |
|---|---|
| 10, 20, 30 | Existing object, landmark and standalone offline checks |
| 40, 50, 60, 70 | Landmark capture, extraction, wire-object validation, joined report |
| 80, 90, 100, 110 | Standalone capture, extraction, wire-object validation, joined report |
| 120 | Optional invalid-input stress checks with positive control |

Prior PASS reports are required at the corresponding gates; the standalone
capture requires a successful landmark protocol report. Underlying tools also
verify capture/fixture hashes. Directory existence is never treated as PASS.
Choose **New campaign** (`new`) after a failure or for another attempt: previous
configuration/logs are archived, all scientific outputs remain intact, and routes
reset to the Paper-1 defaults from the saved MTC16 path. Change FIX/KEY before the first run.
Once evidence exists, configuration is frozen; it cannot be silently redirected.
The lock covers this launcher only, not externally started campaigns.

## Historical manual examples (optional)

The commands below preserve the original representative **legacy pq** cases.
They are separate from the default Paper-1 Bash workflow above. Use existing **legacy pq**, N=16 fixtures for the first two representative captures.
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

Optional **invalid-input stress checks** (deterministic malformed objects, not load testing or randomized fuzzing), **not executed during preparation**:

```sh
protocol_tool mt-tls-measurement:local negative_cases.py \
  --fixtures "$FIX" --profile pq --output "$CAP/invalid-input-stress"
```

A positive control must pass first. Mutations are written only into the fresh
new stress-check directory: truncation, trailing byte, bad length/index/issuer/proof hash,
signature, landmark number and checkpoint root. Failure to load a provider cannot
make an invalid-input suite appear successful.

The launcher calls this stage `120.invalid-input-stress`; `run 120` works as
before and the old full name `120.negative` remains an alias. Existing directories
and reports are preserved. New runs use `CAP/invalid-input-stress`.

Each case writes the original object-validator `report.json` and a separate
`test-result.json`, for example:

```json
{
  "case": "signature",
  "expected": "REJECT",
  "observed": "REJECT",
  "test_result": "PASS",
  "validator_result": "FAIL",
  "reason": "OpenSSL signature verification failed"
}
```

This is the expected schema, not an executed result. `validator_result=FAIL`
means the object is invalid; `test_result=PASS` means its rejection was expected.
The console prints `PASS signature - invalid object correctly rejected`. Unexpected
acceptance or a validator operational error produces a failed test. Operational
errors use `observed=ERROR`, never `REJECT`. A valid positive control must pass
before mutations are tested. Raw validator stdout/stderr remain in per-case logs,
without confusing expected validator failures with top-level test failures.
The combined report is `stress-checks-summary.json`, with separate positive-control
and per-case results.

Future capture metadata reads `OQS_VERSION_TEXT` from the image's
`/opt/oqs/include/oqs/oqsconfig.h` and records `liboqs_version_source`. A missing or
unreadable version aborts metadata collection instead of silently recording null.
Historical metadata containing null is not overwritten or guessed from another
image or the host environment.

## Evidence boundaries and unresolved questions

- Native TLS1.3 carries the experimental certificate in Certificate (type11).
  Message order is ClientHello, ServerHello, EncryptedExtensions, Certificate,
  CertificateVerify, server Finished, client Finished. Server authentication only;
  fixed X25519/TLS_AES_256_GCM_SHA384, no tickets, PSK/resumption or early data.
- OpenSSL's existing **`-keylogfile`** exports secrets. `SSLKEYLOGFILE` environment
  support is not assumed. `-showcerts` exposes a reserialized received X509; the
  client does not preserve original raw DER. Compare its hash with the captured
  DER while documenting that limitation. Do not claim raw C-byte retention.
- tshark handles TLS framing/decryption. `extract_pcap.py` uses decoded PDML
  child fields for Certificate DER and structure; the parent handshake `value`
  may be empty. Independent transcript checks instead use `jsonraw` exact bytes
  and preserve duplicate JSON keys. No fixture supplies transcript payload.
- Extraction records sequential TLS record numbers with packet numbers, handshake
  types/lengths, Certificate and CertificateVerify sizes, MTCProof and DER sizes,
  TCP stream and reassembly completion packet. All stream packet IDs and PDML
  are retained; completion packet alone is not a complete fragment attribution.
- Endpoint acceptance and independent verification are separate layers.
  `verify_tls_transcript.py` provides optional offline verification; absent
  supplemental evidence remains NOT_EXECUTED in old reports.
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

## Initialize shared launcher paths

`mt-prepare run ALL` (or a successful `run N` / `rebuild`) initializes missing
cert-scaling configuration first, then protocol-validation configuration using
its N=16 path. Existing configurations, custom paths and results are preserved.
Do not run a separate launcher `init` afterward; inspect `status` instead.

If images were prepared before this change, configure the missing paths only:

```sh
bin/cryptographic_scaling/mt-prepare init
```

This command does not need Docker and does not generate fixtures. Run `mt-prepare run ALL` to also generate and validate N=16 fixtures automatically.
Existing fixture outputs are preserved; inspect status before repeating stages.

### Automatic N=16 prerequisites

`mt-prepare run ALL` prepares images and missing launcher configuration, then
runs certification stage 50 (N=16 generation) and stage 60 (functional TLS checks)
automatically when their outputs do not exist. No separate manual invocation of
those stages is needed. It checks the validation gate against fixture hashes,
current source hashes and the current MTC image before reporting success.
Existing incomplete, failed or stale evidence is preserved and reported as an
error; it is never overwritten. Existing custom protocol paths are preserved
and must match the prepared Paper-1 profile before setup reports readiness.

`run N` and `rebuild N` remain image-only preparation plus configuration, so the
certification image stage cannot recursively start fixture generation.
`init` only saves missing configuration. `run ALL` and `rebuild ALL` include
functional TLS validation, but no performance matrix or protocol capture.

## Run all protocol stages

```sh
bin/cryptographic_scaling/mt-protocol-validation run ALL
```

Runs stages 10–120 in order, including both TLS captures, extraction, offline
validation, joined reports and invalid-input stress checks. The menu offers the
same action. Completed stages recorded by this launcher are skipped; the first
error stops the batch. Existing outputs are never overwritten. A failed stage
with existing evidence requires inspection and a fresh campaign where appropriate;
`run ALL` does not automatically repair or resume partial captures. Batch locks
prevent another stage, batch or configuration change during execution.

## Supplemental offline validation (2026-09-13)

The exact revisions inspected are **MTC-05** and **trust-anchor-ids-04**, from the
preserved local copies, not a newer draft. [FIELD_MAP.md](FIELD_MAP.md) lists exact
sections and restrictions. TLS calculations follow [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html),
§§4.4.1, 4.4.3, 4.4.4 and 7.1.

### Observed evidence and limitations

The requested baseline `artifacts/protocol-validation/20260913T124747Z/` was absent
from this checkout. Its historical PQ PASS results could not be rechecked.
Another existing run, `20260913T142141Z`, has positive ML-DSA-65 landmark and
standalone JSON reports; it is **different evidence**, not a replacement baseline.
The existing landmark PCAP (13,979 bytes) was inspected offline using host
**tshark 4.6.8**. Its jsonraw exposes all seven exact handshake messages, even though
its preserved PDML has empty parent values. This does not establish jsonraw
compatibility for the historical container's tshark 4.0.17.

For that landmark capture only, independent server Finished and client Finished
checks passed with SHA384 using the matching client-random keylog entries.
CertificateVerify exact input and wire SPKI extraction were prepared; real PQ
signature verification was **NOT_EXECUTED** because the existing provider-enabled
OpenSSL environment was not launched. The supplemental result is **PARTIAL**, not
a complete independent TLS verification PASS. No secret values enter reports or docs.
The real supplemental JSON was written only to `/tmp/mtc-landmark-independent-final.json`.
It is local review output, not committed scientific evidence.

The private **0xffa7** codepoint remains experimental; TA-04 ExtensionType is
**TBD**. The observed single-candidate CH/EE lists and zero-length first-entry
confirmation support **PASS_EXPERIMENTAL_CODEPOINT** for this restricted semantic
mapping. The client sends individual CA.1.log.landmark, not recommended group
CA.2.log.landmark: MTC-05 §8.2.1 remains unresolved. The native implementation
also lacks general group membership and retry, and rejects an empty requested list
although TA-04 permits it. No negotiation behavior was changed to hide these gaps.

Timestamp reports separate (a) zero timestamp used for MTCProof signatures,
(b) checkpoint uint64 encoding and signed range, (c) unproven actual signing-time
and largest-observed-tree assertions, and (d) the native nonfuture local policy.
There is no invented maximum-age rule. The three existing NOT_IMPLEMENTED areas
remain unchanged: general revoked-range database, evolving multi-landmark
distribution and public independent cosigner ecosystem.

### Status vocabulary and compatibility

- PASS: that specific layer has observed successful evidence.
- PASS_EXPERIMENTAL_CODEPOINT: observed single-candidate structures/selection match,
  while 0xffa7 remains private. Not full trust_anchors or MTC compliance.
- LOCAL_POLICY: source-identified local rule; execution status is separate.
- UNRESOLVED: a mapping or assertion is still unsupported by sufficient evidence.
- NOT_EXECUTED: no corresponding verification result, including old report fields.
- NOT_APPLICABLE: no such signature/checkpoint in this mode.
- NOT_IMPLEMENTED: outside the supported implementation/verifier scope.
- PARTIAL: some independent checks passed but others were not executed/supported.
- NOT_READY_EXACT_TRANSCRIPT_BYTES_UNAVAILABLE: exact supported handshake bytes
  could not be recovered. The verifier does not synthesize missing bytes.
- FAIL: an executed check failed; an operational inability is not a signature PASS.

`report.py` preserves legacy object/transport evidence and adds `validation_layers`.
Without `--independent-report`, independent CV/Finished statuses remain NOT_EXECUTED.
With one, capture, keylog, metadata and wire-object digests must match. A supplied
independent FAIL makes the joined report fail. An old object's `draft_checks` remains
historical evidence; new detailed layers do not silently rewrite its assertions.
A top-level PASS continues to mean **implemented-subset conformance** for object,
transport structure and endpoint authentication, with other statuses explicitly separate.

### Manual offline commands (not a new capture)

Use fresh output names **outside** the original protocol-evidence directories.
Do not run `run ALL` to obtain supplemental transcript evidence.

```sh
# Set to an existing capture; this is the alternative run inspected here.
CAPTURE="artifacts/protocol-validation/20260913T142141Z/landmark"
REVIEW="artifacts/protocol-review/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$REVIEW"

# Host-side exact-byte/Finished verification; CV remains NOT_EXECUTED unless
# --openssl points to an existing provider-enabled executable.
PYTHONDONTWRITEBYTECODE=1 python3 campaigns/protocol_validation/verify_tls_transcript.py   "$CAPTURE" --output "$REVIEW/independent.json"   --tshark /Applications/Wireshark.app/Contents/MacOS/tshark

# Optional join of old object evidence and new independent evidence.
PYTHONDONTWRITEBYTECODE=1 python3 campaigns/protocol_validation/report.py   --capture "$CAPTURE" --extraction "$CAPTURE/extracted"   --object-report "$CAPTURE/object-validation.json"   --independent-report "$REVIEW/independent.json"   --output "$REVIEW/protocol-report.json"
```

For an independent PQ CertificateVerify check in the already-built capture image
(which inherits measurement/OpenSSL/provider tooling), the following is prepared
**for manual execution only; it was not run during development**. It starts no
TLS server/client and has no network access. It still starts a container, so it
is excluded from this task's low-resource execution allowance. If the old tshark
cannot expose exact bytes, preserve the NOT_READY result; do not rebuild here.

```sh
CAPTURE_IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["capture_image_id"])' "$CAPTURE/metadata.json")
docker run --rm --network none   -e PYTHONDONTWRITEBYTECODE=1   -v "$PWD:/repo:ro" -v "$PWD/$REVIEW:/review" -w /repo   --entrypoint python3 "$CAPTURE_IMAGE"   campaigns/protocol_validation/verify_tls_transcript.py "$CAPTURE"   --openssl /opt/mtc/openssl.sh --output /review/independent-pq.json
```

No full final protocol workflow is needed to join this evidence. Rechecking object
timestamp details would require a fresh offline `validate_mtc.py` report with the
original trust inputs/provider, not changing the historical object report.

Lightweight regression command:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover   -s campaigns/protocol_validation -p 'test_offline_semantics.py' -v
```

The tests use tiny synthetic byte strings and mocked cryptographic subprocesses;
20 passing unit tests are **not** 20 new TLS/cryptographic experiment results.
