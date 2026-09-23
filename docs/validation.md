# Local verification — 2026-09-09

Docker Desktop with Linux arm64 containers. The image was built successfully
with OpenSSL 3.5.8, liboqs 0.14.0, and oqsprovider 0.10.0. The original
executable is preserved and a separate executable is built with the Merkle
client and server options.

- The Compose configuration is valid; Bash syntax and Python compilation pass.
- 153 valid Merkle proof paths for trees with 1 to 17 leaves, together with
  mutations, truncations, and invalid inputs, pass under AddressSanitizer and
  UBSan.
- 50 TLS checks pass with ECDSA P-256 and ML-DSA-65: valid connection,
  HelloRetryRequest, normal interoperability, and rejection of incorrect roots,
  proofs, leaves, CAs, and hostnames, as well as expiration and missing proofs.
- A test-only peer sends invalid versions, indices, depths, and proof lengths
  over the network; the client rejects every case.
- The tests verify rejection of PSK, input sessions, reconnect, early data, raw
  public keys, advanced mode, and DANE, and enforce the identity requirement.
- Both Merkle scenarios complete verified HTTP connections between the Compose
  client and server services, with two functional samples each.
- `codigoOriginal/C/` and `codigoOriginal/Bash/` remain unchanged from the
  received content. Warnings about unused functions in the original sources
  remain.

Sizes observed during the functional checks, using the same certificates,
X25519, and `TLS_AES_256_GCM_SHA384`:

| Scenario | DER leaf (bytes) | Handshake read by client (bytes) | Written (bytes) |
|---|---:|---:|---:|
| ECDSA P-256 | 444 | 815–816 | 400 |
| ECDSA P-256 + Merkle | 444 | 897 | 405 |
| ML-DSA-65 | 5,563 | 9,172 | 400 |
| ML-DSA-65 + Merkle | 5,563 | 9,253 | 405 |

The demonstration tree has two leaves: a 77-byte proof payload plus a 4-byte
extension header. The client offer occupies 1 + 4 bytes. ECDSA signatures have
variable length. These values are `s_client` counters, not Ethernet/IP/TCP wire
bytes.

These are functional samples only and do not support performance conclusions.
CSVs and logs are under `artifacts/results/`. The Merkle samples record the hash
of the specific patch used; DANE exclusion was subsequently added and the full
suite was repeated. No statistical study has been run and the optional hybrid
group has not been tested. Certificate-size reduction outside MTC was not implemented
in this phase: this stage adds verification and bytes to X.509.
