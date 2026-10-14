# OpenSSL/MTC timing schema v2

All v2 durations are measured directly with `CLOCK_MONOTONIC`, stored as
`uint64_t` nanoseconds and exported as decimal integers. A missing measurement
is `null` in the native JSON record and an empty CSV cell; a measured zero is
`0`. Historical millisecond fields remain unchanged.

| Metric | Start | End | Includes | Excludes | Applies | Chromium relation |
|---|---|---|---|---|---|---|
| `credential_validation_total_ns` | Entry to the client `ssl_verify_internal()` wrapper | Return from the same invocation, including failure | Complete selected peer-credential validation: native X.509 path processing or the configured MTC callback and its local constraint checks | TLS `CertificateVerify`, earlier TLS parsing and later handshake states | X.509, Landmark, Standalone | Same logical operation as `credential_validation_total_ns` around `CertVerifyProc::Verify()`, but implementation boundaries are not instruction-identical |
| `handshake_total_ns` | `SSL_CB_HANDSHAKE_START` for the client `SSL` | Matching `SSL_CB_HANDSHAKE_DONE` | TLS handshake protocol processing and waits between those callbacks | DNS, TCP establishment, HTTP, shutdown and process/container startup | All successful measured handshakes | No current Chromium field with the same native boundary; PCAP and browser connection timings are not aliases |
| `mtc_total_ns` | Entry to internal `mtc_verify_timed()` verification | Return from that verification, including failure | Internal MTC proof validation | Surrounding X.509 constraint/store work performed by the custom callback | Landmark, Standalone | `mtc_total_ns` around BoringSSL `VerifyMTC()` |
| `merkle_leaf_hash_ns` | Before MTC leaf construction/hash | After `leaf_hash()` | Leaf encoding and hashing | Merkle path evaluation | Landmark, Standalone | `merkle_leaf_hash_ns` |
| `merkle_path_ns` | Before `mtc_eval()` | After `mtc_eval()` | Merkle inclusion-path evaluation | Leaf hashing and later trust/signature checks | Landmark, Standalone | `merkle_path_ns`; Chromium `merkle_proof_ns` is its historical alias |
| `merkle_total_ns` | Before leaf hashing | After path evaluation | Inclusive leaf-plus-path region | Landmark comparison and Standalone signatures | Landmark, Standalone | `merkle_total_ns` |
| `x509_signatures_ns` | Immediately before each effective selected-chain `EVP_DigestVerify()` | Immediately after it returns | Successful and failed cryptographic X.509 certificate-signature operations actually executed | Path construction, policy, cache work and MTC | X.509 built-in verifier only | `x509_signatures_ns` |
| `standalone_signatures_ns` | Immediately before each effective Standalone proof signature primitive | Immediately after it returns | Standalone cryptographic signature operations | Merkle work and unavailable cache measurements | Standalone | `standalone_signatures_ns` |
| `certificate_verify_crypto_ns` | Immediately before TLS `EVP_DigestVerify()` | Immediately after it returns | Peer TLS 1.3 `CertificateVerify` cryptography | Credential-chain validation | All certificate-authenticated TLS cases | `certificate_verify_crypto_ns`; Chromium keeps `elapsed_ns` as a historical alias |

## Historical fields

| Metric | Exact boundary and interpretation |
|---|---|
| `handshake_wall_ms` | The same `SSL_CB_HANDSHAKE_START` through `SSL_CB_HANDSHAKE_DONE` interval as `handshake_total_ns`, measured independently in milliseconds. It starts inside `SSL_connect()` and ends before `SSL_connect()` returns to the application. |
| `credential_verification_total_ms` | Complete `ssl_verify_internal()` wrapper interval. Historical compatibility field for both X.509 and MTC credentials. |
| `x509_verification_ms` | Exact compatibility alias of `credential_verification_total_ms`. Despite its name, it also contains MTC credential validation when the custom MTC callback is selected. It must not be interpreted as exclusive X.509 cryptography. |
| `client_authentication_verification_total_ms` | Sum of two separately measured local regions: `ssl_verify_internal()` and `tls_process_cert_verify()`. It excludes TLS state transitions and network wait between them; it is not a continuous interval. |
| `mtc_credential_auth_ms` | Custom MTC certificate callback from entry through successful completion, including internal MTC verification plus purpose/time/local-store constraint processing. Historical failures are exported as unavailable. It is broader than `mtc_total_ns`. |
| `certificate_verify_ms` | Complete `tls_process_cert_verify()` wrapper, including preparation and the signature primitive. It is broader than `certificate_verify_crypto_ns`. |

`x509_signatures_ns = null` is expected for MTC paths: the historical
`x509_verification_ms` name describes the outer credential-validation wrapper,
while no selected-chain X.509 certificate-signature primitive ran. Cache fields
remain `null` on OpenSSL until an attributable per-connection cache mechanism
exists; they are never synthesized as zero.

The expected containment relations, when both operands are present, are:

```text
handshake_total_ns >= credential_validation_total_ns
credential_validation_total_ns >= mtc_total_ns
credential_validation_total_ns >= x509_signatures_ns
handshake_total_ns >= certificate_verify_crypto_ns
```

These relations express nesting only. Inclusive and exclusive intervals must
not be added as independent components.
