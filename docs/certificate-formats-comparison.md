# Certificate and credential formats used in the laboratory

This document describes the two Merkle-based proposals implemented in this
repository and compares them with the post-quantum X.509 baseline. The primary
comparison uses the PQ fixtures with a Merkle population of **N=16**. Compact is
a repository-specific experimental protocol. MTC is always identified as
**MTC-experimental** because the implementation targets
`draft-ietf-plants-merkle-tree-certs-05` but does not claim complete conformance
or interoperability.

## Common TLS and cryptographic controls

All compared scenarios use TLS 1.3, X25519 key agreement,
`TLS_AES_256_GCM_SHA384`, server-only authentication, and no session tickets or
resumption. The server authentication key is ML-DSA-65 in the PQ scenarios.
`CertificateVerify` remains present and uses that key in every scenario, so all
three representations retain proof of possession of the server private key.

The X.509 baseline has a two-certificate direct chain: a self-signed ML-DSA-65
root CA and an ML-DSA-65 server leaf signed by that CA. The leaf is not
self-signed. Its subject is `CN=server`; its SAN contains `server`, `localhost`,
and `127.0.0.1`; and its purpose is TLS server authentication. The measured
fixture sizes are 5,563 bytes for the leaf DER and 7,501 bytes for the CA PEM.
PEM and DER sizes must not be compared directly because PEM includes base64 and
text delimiters.

## Compact Merkle credential

Compact replaces the transmitted X.509 leaf with a TLS Raw Public Key (RPK) and
a minimal custom credential. The credential contains one DNS name, validity
dates, the SHA-256 hash of the DER SubjectPublicKeyInfo, and the `serverAuth`
purpose. The N=16 PQ fixture contains:

| Component | Bytes | Role |
|---|---:|---|
| ML-DSA-65 SPKI | 1,974 | Public key transmitted as RPK |
| Compact credential | 61 | Identity, validity, purpose, and SPKI binding |
| Encoded Merkle proof | 173 | Inclusion in the N=16 tree |
| Persisted bundle | 244 | Credential, proof, and framing; signed-root field is empty |
| Signed root | 3,399 | 88-byte root header plus 3,309-byte ML-DSA-65 signature |

The CA signs one root for the certificate population instead of signing each
credential individually. In **warm** mode, the client has already authenticated
the signed root and the handshake sends the RPK, credential, and inclusion
proof. In **cold** mode, the server also sends the signed root and the client
verifies its CA signature during the handshake. Compact checks hostname,
validity, `serverAuth`, Merkle inclusion, and the binding to the received RPK.
It does not provide general X.509 path validation, policies, name constraints,
or an online revocation protocol.

The wire format and TLS extension used for Compact are local experimental
formats. RFC 7250 defines RPK transport, but it does not define this credential,
Merkle proof, or signed-root format. The complete encoding is documented in
[Compact Merkle protocol](compact-protocol.md).

The encoded proof is not stored in an X.509 certificate. It is persisted as
`proof-0000.bin`, embedded with the credential in `bundle-0000.bin`, and carried
in the private `0xffa6` extension in TLS `EncryptedExtensions`. The server public
key travels separately as RPK in the TLS `Certificate` message. The inspection
tool under `tools/binary_inspection/` decodes the `MTP1`, `MTC2`, `MCB2`, and
`MTR2` files and can verify credential inclusion without modifying fixtures.

## MTC-experimental certificate

MTC-experimental preserves an X.509 v3 DER container and its leaf semantics,
including subject, SAN, validity, purpose, and extensions. It replaces the
ordinary per-certificate CA signature with an `MTCProof` in `signatureValue`.
The experimental signature algorithm OID is `1.3.6.1.4.1.44363.47.0`; the issuer
identifies the MTC CA using the experimental issuer OID from the draft profile.
The logged entry binds the certificate data and the SHA-256 hash of the server
SPKI. The server key and `CertificateVerify` algorithm remain ML-DSA-65.

The N=16 tree uses the RFC 9162 tree shape and is covered by subtrees `[0,8)` and
`[8,16)`. Its inclusion proof has three SHA-256 sibling hashes, or 96 bytes.
Two modes are measured:

| Component or mode | Bytes | Role |
|---|---:|---|
| Common TBS content | 2,206 | X.509 leaf fields retained by both modes |
| Inclusion hashes | 96 | Three SHA-256 siblings |
| Standalone `MTCProof` | 6,746 | Proof plus CA and local-cosigner subtree signatures |
| Standalone certificate DER | 8,975 | Self-contained handshake certificate |
| Landmark `MTCProof` | 114 | Proof and landmark reference, without signatures |
| Landmark certificate DER | 2,341 | Certificate sent in the handshake |
| Predistributed landmark trust file | 10,772 | Keys, policy, checkpoint, signatures, and subtrees |

In **standalone** mode, the certificate carries subtree signatures from the MTC
CA and one additional local cosigner. In **landmark** mode, those signatures and
the authenticated checkpoint are predistributed in `trust.bin`; the handshake
certificate carries the inclusion proof and a landmark reference. The local
cosigner is part of the laboratory and does not support a claim of independent
public transparency.

The MTC CA/cosigner keys are deliberately different from the directly signing
X.509 CA key. The implementation validates the MTC proof and native X.509 leaf
controls, but it is not a general MTC/PKIX path validator. The precise profile
and deviations are documented in [MTC-experimental protocol](mtc-protocol.md)
and [MTC feasibility](mtc-feasibility.md).

## N=16 post-quantum comparison

The following values are measured TLS authentication bytes from the controlled
N=16 campaign. They are not certificate-file sizes and they are not total
Ethernet, IP, or TCP wire bytes.

| Scenario | TLS authentication bytes | Difference from PQ X.509 | Trust moved outside the handshake |
|---|---:|---:|---|
| PQ X.509 | 9,572 | reference | Root CA |
| Compact warm | 6,281 | -3,291 (-34.4%) | Signed Merkle root and CA |
| Compact cold | 9,648 | +76 (+0.8%) | CA only |
| MTC-experimental landmark | 6,382 | -3,190 (-33.3%) | 10,772-byte landmark trust file |
| MTC-experimental standalone | 13,010 | +3,438 (+35.9%) | CA/cosigner keys and policy |

Compact warm is 101 handshake bytes smaller than MTC landmark in this fixture.
That difference does not isolate the cost of the X.509 container: the schemes
also use different tree constructions, proof encodings, TLS signaling, and
trust models. Compact cold and MTC standalone similarly differ because MTC
standalone includes both a CA signature and a cosignature.

The warm and landmark reductions come from amortizing authenticated state across
multiple connections. A fair deployment comparison must include distribution,
storage, validation, update, expiry, and revocation costs for that state. The
standalone modes avoid depending on a previously distributed tree checkpoint,
but transmit the signature material in each handshake. Timing results must be
read from the same controlled campaign as the byte results; file sizes alone do
not predict handshake latency under RTT, bandwidth, or packet loss.

## Reproducibility sources

The values above come from the immutable N=16 fixture manifests at
`artifacts/compact/batch16/pq/manifest.json` and
`artifacts/mtc/batch16-v2/pq/manifest.json`, together with the controlled
campaign output summarized in [MTC results](mtc-results.md). Private key files
are fixtures for the local laboratory and must never be published as production
credentials.
