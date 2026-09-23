# Isolated BoringSSL MTC verifier port

This directory is excluded from the current experimental study. The original
`src/mtc/` proof/negotiation semantics are unchanged by this port. `upstream-sources.sha256` records the
source snapshots used for this initial port; the local copies intentionally
diverge and do not automatically track upstream edits.

Initial adaptation removes OpenSSL 3 provider APIs. EC keys use curve NIDs
(P-256/SHA-256, P-384/SHA-384, P-521/SHA-512). ML-DSA-44/65/87 use BoringSSL's
EVP key identifiers and a NULL digest. SLH-DSA and other key types are rejected;
this is not full algorithm parity with the original verifier. Merkle hashing,
proof parsing and the requirement to verify both configured signers are retained.

The build script compiles and links `check.c` against BoringSSL libcrypto in a
temporary directory. It does not run verification, TLS, Docker or campaigns.
Run it explicitly inside the baseline container with this directory mounted
read-only at `/work/port`: `sh /work/port/build-verifier.sh`.

Status: the user reported successful compilation and linking with the pinned
BoringSSL baseline (`BUILD_OK`). This was not independently run by the agent.
`test-verifier.sh FIXTURE_DIRECTORY` rebuilds and runs 60 offline checks against
existing EC, ML-DSA and SLH-DSA fixtures, hashes its inputs, and places mutations
in the container's temporary directory. The user reported `60 PASS, 0 FAIL`;
the agent has not independently executed the suite or reviewed its full log.
They cover valid proofs, wrong modes, truncation, trailing bytes, a changed
cosignature and rejection of unsupported SLH-DSA. They are an initial smoke
suite, not exhaustive parser, signer-policy or TLS validation.
The verifier checks MTC proofs; it is not a complete
TLS certificate policy (hostname, validity, purpose, etc.). TLS extensions,
callbacks and Chromium integration are not ported yet. Declarations retained
in `mtc.h` do not imply implementations of its TLS functions in this directory.

## Native provisional wire codepoint

The active OpenSSL laboratory and this BoringSSL port now use provisional
`trust_anchors` 0xca34. This is not a final IANA assignment. The pinned TAI -04
specification still uses TBD; no draft version or message semantics changes here.
`Dockerfile.wire` builds the unpatched baseline revision into `build-mtc`.
The old codepoint patch and build define are removed. The C port uses the upstream
`TLSEXT_TYPE_trust_anchors` constant. The ClientHello probe requires one matching
0xca34 extension and explicitly rejects the historical private 0xffa7.
Rebuild both OpenSSL and BoringSSL images before testing: old image binaries
still use the old codepoint even when mounted client source has been updated.
The active validators do not accept a second wire codepoint.

`test-clienthello.sh AUTHORITY_BIN` uses memory BIOs with no sockets. Its peer
verification callback deliberately rejects peers; it is only a ClientHello test.

## Historical evidence boundary

All recorded results below, including the 12/12 matrix, precede this migration.
Historical experimental wire runs used **0xffa7**, with the then-required
`lab-wire.patch` / `BORINGSSL_LAB_MTC_WIRE` remapping of native 0xca34.
Those results and the original `upstream-sources.sha256` provenance are retained,
not relabeled. No builds, tests, validation scripts or TLS were run for the
0xca34 migration. Validation of the migrated source remains pending.
See [VALIDATE_CA34.md](VALIDATE_CA34.md) for ordered manual commands.

## Standalone TLS client and historical interoperability smoke test

`tls-client.c` implements a bounded IPv4-loopback TLS 1.3 client. It requires
the available-anchor list to contain its configured ID and an empty leaf
confirmation recognized by BoringSSL. Its custom verification callback requires
exactly one certificate, validates the MTC proof, DNS SAN, validity and server
purpose, then applies native X.509 leaf constraints using the MTC-authenticated
leaf as a local partial-chain trust anchor. Normal TLS CertificateVerify and
Finished checks remain in BoringSSL. This is a restricted direct-leaf profile,
not general PKIX, a browser trust policy or support for resumption/client auth.

`python3 campaigns/future_implementation/browser_mtc/run-tls-smoke.py` prints
a plan without Docker or TLS. Adding `--execute` builds the client against the
existing wire image and runs three connections to the existing OpenSSL MTC
image: valid EC P-256 standalone, wrong hostname, and altered cosignature.
The server starts with `--network none` and the client shares that isolated
network namespace; no host ports are published. Only temporary containers
created by the runner are removed. Existing inputs are read-only; public
copies, mutations, image IDs, source/input hashes and logs are retained under
a unique `artifacts/results/browser-mtc-tls-*` directory. Private keys are
mounted only into the server and are not copied to the evidence directory.
`--server-image`, `--client-image`, `--fixture`, and `--key` override defaults.

Local validation: C syntax against exported BoringSSL headers, shell syntax,
Python plan execution and diff whitespace checks pass. The TLS client build
and three live connections were subsequently executed by the user. Inspection
of `artifacts/results/browser-mtc-tls-yc8moi9a/` confirms all three cases passed:
TLSv1.3/TLS_AES_256_GCM_SHA384 completed for `server`, the wrong name failed
with `MTC_REJECT: hostname`, and the altered cosignature failed with
`MTC_REJECT: proof` and ECDSA `BAD_SIGNATURE`. This establishes the bounded
EC P-256 standalone interoperability smoke result, not general validation.
The earlier failed run `browser-mtc-tls-20_p_t38` is retained; it exposed a
hostname API porting error fixed by passing explicit string lengths.
Further negative negotiation, expiry, purpose, critical-extension and chain
tests, ML-DSA interoperability and landmark mode remain pending.

## Extended matrix and historical results 

The client now accepts an optional `standalone|landmark` argument (standalone
remains the default). Landmark loads and authenticates `trust.bin`. Initial ClientHello now requests the landmark group
derived from that configuration; the server selection remains the exact individual
landmark. There is no trust-anchor retry or fallback in this BoringSSL client.

The smoke runner now accepts `--profile` and `--mode`, and runs four cases:
valid, wrong hostname, altered proof and missing MTC negotiation. The last
case uses the existing ordinary X.509 certificate/key without `-mtc_id` and
requires a specific `MTC_REJECT: negotiation`; transport failures do not pass.
Default fixture/key paths follow the selected profile. The existing three-case
result above remains evidence for the earlier standalone implementation only.

`run-tls-matrix.py --execute` invokes all six EC/ML-DSA profiles in both modes,
with four cases per suite (48 planned connections). A failing suite stops at
its first failure; other suites still run. A new matrix evidence directory
records all child evidence paths and statuses. Without `--execute` the runner
only prints its plan. `--profiles ecdsa-p256 mldsa44` selects a smaller subset.
Image options are forwarded to the smoke runner. Image building and fixture
generation are not performed. Existing evidence is preserved.

Validation so far: client C syntax, Python syntax, both plan-only entrypoints,
and the presence/profile metadata of all six fixture families. Extended TLS
results, including ML-DSA TLS signature-algorithm interoperability, are pending.

Matrix evidence `browser-mtc-matrix-3_28fhzx` was inspected: P-256 and P-384
passed both modes (16 cases); P-521 and ML-DSA failed their eight initial valid
cases with server `tls_choose_sigalg: no suitable signature algorithm` before
credential verification. Those suites did not execute their negative cases.
The exported BoringSSL `ssl/extensions.cc` default verification preference list
omits P-521 and ML-DSA despite their implementation in `ssl_privkey.cc`.
The client now explicitly configures the six laboratory algorithms through
`SSL_CTX_set_verify_algorithm_prefs`. Local C syntax passes; runtime confirmation
of this correction is pending. Original matrix evidence is preserved.

Follow-up `browser-mtc-matrix-l_8i1i_5` passed all eight P-521/ML-DSA suites.
The agent inspected each child summary and the four expected client log
markers, confirming 32 cases across standalone and landmark. Together with
the 16 P-256/P-384 cases from the earlier matrix, all 48 planned cases have
passed across two revisions/runs. This is not a single full-matrix run of the
latest client: P-256/P-384 were not repeated after the explicit signature
preference change. No Chromium/browser integration is established by these
laboratory TLS results.

BoringSSL laboratory TLS matrix:
artifacts/results/browser-mtc-matrix-va6fwuke

Result:
12/12 suites PASS
48/48 TLS cases PASS
## Individual landmark versus initial landmark group

The active provisional codepoint remains **0xca34**. For CA `32473.101`, log 1,
last landmark 1, the three distinct signals are:

| Context | ID |
| --- | --- |
| Standalone CA anchor | `32473.101` |
| Selected individual landmark / explicit retry | `32473.101.1.1.1` |
| Initial landmark ClientHello group | `32473.101.2.1.1` |

Both verifier copies construct `signal` (individual or standalone CA) and
`request_signal` (initial group or standalone CA) from `caid`, `log`, `number`.
BoringSSL advertises `request_signal` but still requires the available-anchor
list to match `signal`, plus the empty CertificateEntry confirmation and proof
verification. The OpenSSL server maps that group to its corresponding configured
individual. A group is never used as the selected individual or retry target.
The smoke runner reads these coordinates from the existing MCF1 configuration;
its metadata reader does not authenticate it: authentication stays in `mtc_load`.

The memory-BIO probe now accepts an optional `landmark` argument with `trust.bin`
and checks the initial group. Its standalone default is unchanged.
New `test_ids.c` covers CA/individual/group construction; `test_trust_ids.py`
covers the runner reader and non-hardcoded coordinates.

Validation executed for the landmark-group change:
- CA/individual/group native ID construction: PASS
- trust-ID Python tests: PASS
- bounded retry Python tests: 17/17 PASS
- native retry test: PASS
- landmark TLS smoke: 4/4 PASS
- ClientHello probe: PASS, with exactly one `0xca34` extension and no `0xffa7`
- initial ClientHello landmark group: `32473.101.2.1.1`
- selected individual landmark / explicit retry: `32473.101.1.1.1` Existing historical BoringSSL handshake results advertised
individual landmark IDs; they do not validate the new group-advertising path,
regardless of whether their wire codepoint was 0xffa7 or 0xca34.

This remains an implemented experimental subset of MTC-05 / TAI-04. The loader
still restricts real configs to log 1 / landmark 1; generic ID formatting does
not enable evolving landmarks, general group-range selection, multiple active
logs, or complete draft conformance. Artifacts and certificate sizes are unchanged.
