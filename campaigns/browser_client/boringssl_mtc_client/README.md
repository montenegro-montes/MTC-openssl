# Isolated BoringSSL MTC laboratory port

This directory contains an experimental MTC-05 / TAI-04 subset, separate from
the main experimental study. It is not Chromium integration or a claim of full
draft conformance. `upstream-sources.sha256` records the original source snapshot,
not hashes of the current port. Local copies do not automatically track `src/mtc`.

## Current implementation

The verifier replaces OpenSSL 3 provider APIs with BoringSSL APIs. Supported
signer profiles are EC P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 and
ML-DSA-44/65/87. SLH-DSA and other key types are rejected. Merkle hashing remains
SHA-256 and both configured signer signatures are required where applicable.

`check.c` is an offline proof verifier, not a complete certificate policy.
`tls-client.c` additionally checks negotiation, exactly one certificate, MTC proof,
DNS SAN, validity, server purpose and native leaf constraints. Only after MTC
proof authentication does it use that leaf as a local partial-chain trust anchor.
BoringSSL retains CertificateVerify and Finished verification. The client is
restricted to TLS 1.3 over IPv4 loopback, with no resumption, client authentication,
trust-anchor retry or fallback. It explicitly enables the six laboratory TLS
signature algorithms, including P-521 and ML-DSA omitted by the pinned library's
default verification preferences.

The declarations retained in `mtc.h` do not imply that the OpenSSL TLS wrapper
functions are implemented here; the BoringSSL integration lives in `tls-client.c`.

## Wire codepoint and landmark IDs

The active laboratory uses native provisional `trust_anchors` **0xca34**.
This is not a final IANA assignment; the pinned TAI-04 text uses TBD.
`Dockerfile.wire` builds the pinned upstream baseline into `build-mtc` without
patching BoringSSL. The historical `lab-wire.patch` and
`BORINGSSL_LAB_MTC_WIRE` remapping to private **0xffa7** were removed.
Old images retain their compiled behavior; source changes alone do not rebuild
libraries. Preserve old image IDs and never relabel their evidence.

For CA `32473.101`, log 1 and last landmark 1:

| Context | ID |
| --- | --- |
| Standalone CA anchor | `32473.101` |
| Selected individual landmark / explicit OpenSSL retry | `32473.101.1.1.1` |
| Initial landmark ClientHello group | `32473.101.2.1.1` |

Both verifier copies construct `signal` (CA or individual) and `request_signal`
(CA or initial group) from `caid`, `log` and `number`. The BoringSSL client announces
`request_signal`, then requires the server's available-anchor list to match
`signal` and the leaf to carry the empty confirmation extension. The OpenSSL
server maps the group to its corresponding individual. The smoke runner reads
coordinates from MCA2/MTB2 configuration; its reader is not authentication.
The native loader still authenticates the checkpoint and proof.

Current recorded campaign fixtures remain log 1 / landmark 1. The typed loader
derives log and explicit uint48 landmark coordinates from MCA2/MTB2; it does not
infer either coordinate from checkpoint size. Generic ID formatting does not
implement evolving landmark policy or general group-range selection.
Individual IDs remain meaningful for exact selection and explicit OpenSSL retry;
this BoringSSL client does not implement retry itself.

## Tools and execution scope

- `build-verifier.sh`: compiles and links `check.c` inside the baseline container.
- `test-verifier.sh FIXTURE_DIRECTORY`: 60 offline acceptance/rejection checks,
  including unsupported SLH-DSA; mutations stay in temporary container storage.
- `test-clienthello.sh TRUST_BIN [standalone|landmark]`: memory-BIO probe, no
  sockets. Requires one matching 0xca34 extension and rejects 0xffa7. Use
  `authority.bin` for standalone or `trust.bin` for landmark. The probe's peer
  verification callback deliberately rejects peers; it does not complete TLS.
- `run-tls-smoke.py`: four cases for one profile/mode: valid, wrong hostname,
  altered proof and missing negotiation. Negative cases require their specific
  rejection reason; transport failure is not a pass.
- `run-tls-matrix.py`: six profiles, two modes and four cases (48 planned
  connections). Each suite stops on its first failure; other suites continue.

Both Python runners require an explicit MTC fixture root via `--mtc-root`;
`run-tls-smoke.py` also accepts explicit `--fixture` and `--key` inputs instead.
They require `--execute` for Docker/TLS; otherwise they print a plan. They build
the client against an existing library image, not Docker images or fixtures. The server has `--network none`; the client shares its namespace.
No host port is published. Only runner-owned temporary containers are removed.
Public inputs, mutations, logs, source/input hashes and image IDs are saved in
new `artifacts/results/browser-mtc-*` directories. Private keys are mounted only
into the server and are not copied into evidence directories.

Choose `--server-image` and `--client-image` explicitly: the default tags may
still refer to historical builds. For the group change, rebuild OpenSSL from
current source; an existing native-0xca34 BoringSSL library image can be reused
because the runner recompiles the mounted client. See
[VALIDATE_CA34.md](VALIDATE_CA34.md) for the staged migration checks. Its full
matrix commands concern the codepoint migration; group tests need the updated
OpenSSL image (for example `mt-tls-mtc:ca34-groups`).

## Recorded evidence, separated by implementation stage

The following statuses come from existing evidence, not a new execution during
this documentation review. Paths are relative to `artifacts/results/`.

| Evidence | Scope and result |
| --- | --- |
| User-reported offline verifier run | 60 PASS / 0 FAIL; full original log not independently reviewed here. |
| `browser-mtc-tls-20_p_t38` | Historical failure: zero-length hostname argument; preserved. |
| `browser-mtc-tls-yc8moi9a` | Historical private-codepoint P-256 standalone, original three cases: 3/3. |
| `browser-mtc-matrix-3_28fhzx` | Historical matrix: four suites passed; eight failed on TLS signature-algorithm selection. |
| `browser-mtc-matrix-l_8i1i_5` | After explicit signature preferences: eight previously failing suites passed, 32/32 cases. |
| `browser-mtc-matrix-va6fwuke` | Historical private-codepoint full matrix: 12/12 suites, 48/48 cases. |
| `browser-mtc-tls-ij338m57` | Native-0xca34 image pair, P-256 standalone: 4/4 cases. |
| `browser-mtc-matrix-f7gss_s9` | Same native-0xca34 image pair: 12/12 suites, 48/48 cases; before initial-group advertisement. |
| `browser-mtc-matrix-ctyry2rn` | 12/12 suites, 48/48 cases, but uses the old private-codepoint image pair; not additional 0xca34/group evidence. |
| `browser-mtc-tls-slsxxmnw`, `browser-mtc-tls-jvmh0hbb` | Updated OpenSSL group image plus native-0xca34 BoringSSL: P-256 landmark, 4/4 cases in each run. Metadata distinguishes requested `.2.1.1` and selected `.1.1.1`; client logs show successful TLS and the three expected rejections. |

The reviewed summaries identify the historical image pair by server
`35dd674b8d15…` / client `117db89741a8…`, the 0xca34 pair by server
`504d08488bfb…` / client `767fe2a612bf…`, and the group smoke server by
`f747073be94b…` with that same 0xca34 client library. Full immutable image IDs
and source hashes are in each child `summary.json`; directory names alone are
not protocol evidence. A TLS smoke result is not independent PCAP verification.

The previous README also recorded PASS for native ID construction, trust-ID
Python tests, 17/17 retry Python tests, the native retry test and the ClientHello
probe (one 0xca34, no 0xffa7). These remain reported results: that entry supplied
no durable log paths, and this review did not independently reproduce them.

## Remaining validation and limitations

The stored full 0xca34 matrix predates the group-advertising client. The inspected
group evidence covers P-256 landmark only; a full six-profile/two-mode matrix
with the new group path is not established by those earlier 48/48 results.
Independent wire/PCAP evidence for the current group path is separate from the
smoke metadata. Expiry, purpose, critical-extension and chain-negative coverage
is not established by the four-case smoke suite. Chromium certificate-policy
integration, browser interoperability, evolving logs/landmarks, general PKIX,
public cosigner operations and revocation remain outside these results.

Historical artifacts, PCAPs and certificate-size results are unchanged. No builds,
tests, Docker, TLS, campaigns or commits were executed for this README review.
