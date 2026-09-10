# Feasibility: MTC -05 on OpenSSL 3.5.8

Pre-implementation analysis, 10 September 2026. Preserved baseline:
`v0.3.0-profile` (`dc152ad`). SHA-256 inventory: `mtc/preservation.json`. The
original, Compact, and profiling phases were inspected together with their
generators, verifiers, metrics, and the OpenSSL source used inside the image.

Pinned references: [MTC -05](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-05.txt)
and its dependency [trust-anchor-ids -04](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-04.txt).
The requested revision is not replaced with a later draft.

OpenSSL implements neither MTC nor `trust_anchors`. It does process X.509
`Certificate`, `CertificateVerify`, `Finished`, and custom TLS extensions. The
Compact phase uses RPK and a different format and is not reused as if it were MTC.

| Draft feature | Draft requirement | OpenSSL support | Implementation | Exact / approximation |
|---|---|---|---|---|
| Issuance log | §5.2, ordered append-only entries | No | Immutable initial snapshot, log 1, shared population; fully rebuilt before signing | Limited profile; no public service or operational evolution |
| `TBSCertificateLogEntry` | §5.2.1 | No | DER retaining TBS fields, replacing SPKI with algorithm and hash; serial and signature omitted | Exact for supported profile |
| Merkle tree | §4, RFC 9162 | No | Independent tree split at the largest power of two; odd leaves are not duplicated | Exact |
| Inclusion proof | §4.3, §6.2 | No | Separate verifier with absolute indices and aligned subtree | Exact |
| Checkpoint | §5.2, §5.3 | No | Signed snapshot, nonzero timestamp, hash of all entries | Exact for initial snapshot |
| Subtree signatures | §5.3.1, §6.3 | EVP signing/verification | Domain-separated message, zero timestamp for certificates | Exact |
| Cosignatures | §7.3, configurable policy | EVP | CA plus one local cosigner; both rebuild snapshot; distinct keys | Exact cryptography; no operational independence or public transparency |
| Standalone certificate | §6.2–6.3 | X.509 container only | `MTCProof` in `signatureValue`; two covering subtrees under §4.5 | Exact format; experimental profile |
| Landmark-relative certificate | §6.4 | No | Initial sequence [0,N], subtree selection, empty signatures | Exact format; one active landmark |
| Landmark distribution | §7.4 | No | Local authenticated configuration with checkpoint and covering subtrees; bytes and prior validation measured | Local out-of-band transport; no update service or persistent cache |
| CA identification | §5.1 | Generic OID/Name support | Documented private identifiers 32473.* and experimental OID prescribed by -05 | Exact for experimentation |
| Trust-anchor identification | §5.1, §8 | No | Binary RELATIVE-OID IDs and specific landmark | Limited profile |
| TLS negotiation/signaling | §8 and TAI -04 §4 | Custom extensions | Lists in CH/EE and empty confirmation in CertificateEntry 0; private code 0xffa7; exact match and rejection when absent | Experimental: no IANA code, groups/retry, or multiple paths |
| Certificate message | §8 | Yes | Complete MTC X.509 certificate, without RPK or Compact encapsulation | Exact |
| CertificateVerify | TLS 1.3 | Yes | Native signature with original server key | Exact |
| Finished | TLS 1.3 | Yes | Native processing retained | Exact |
| Hostname validation | X.509/TLS | Yes | `X509_check_host` and native leaf checks after MTC authentication | DNS server leaf profile |
| Validity validation | X.509 | Yes | Leaf dates checked during TLS; trust snapshot authenticated beforehand | Exact for leaf |
| Path validation | §7.2 replaces signature authentication only | Partial | Validate MTC, then apply X.509 leaf controls; direct §7.1 trust configuration, no intermediate CA | Explicit limitation; not a general MTC PKIX validator |
| Revoked ranges | §7.5 | No for MTC configuration | Restrict serials to log and issued range; reject outside range | Static snapshot; no revocation updates |
| CA certificate representation | Optional source under §5.5 | No | Direct §7.1 configuration with SPKI keys; no simulated self-signed CA certificate | Permitted alternative; laboratory out-of-band format |

## Comparison decisions and limits

The implementation is called **MTC-experimental** even where core encodings
follow -05, and scenario names contain `mtc-experimental`. It makes no claim of
complete IETF conformance, interoperability, or Web PKI deployment. Limitations
in negotiation, log lifecycle, and path validation are not hidden behind command
line flags.

MTC CA keys are distinct from X.509 CA keys as required by §5.4. Server keys,
names, dates, and population remain fixed. Issuer-identification extensions that
refer to the former CA require documented adaptation or omission. ECDSA P-256
and ML-DSA-65 provide experimental continuity across families, not identical
nominal security levels. Key exchange remains X25519.

The default policy adds one local cosigner to the CA. The earlier X.509 baseline
has no SCTs, so standalone with a cosignature and X.509 without CT do not provide
equivalent properties. Signatures and proofs are reported separately. Landmark
mode moves authentication into prior configuration; its cost is counted and
amortization is not assumed.

Instrumentation is reused in an independent copy of the profiled build under
`/opt/openssl-mtc`. Fixtures and verifiers are validated first, followed by
negative TLS cases and regressions, smoke, and the full campaign. Scaling sizes
come from actual encodings rather than an assumed formula.
