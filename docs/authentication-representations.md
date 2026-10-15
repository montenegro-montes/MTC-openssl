# Authentication representations used by the laboratory

This document fixes the byte boundaries and trust assumptions used by the
certificate-chain and MTC scaling experiment. X.509 hierarchy depth and MTC
tree depth are independent dimensions. The current MTC implementation has no
X.509-like intermediate hierarchy, so the experiment compares their online TLS
authentication representations rather than claiming equivalent trust models.

## X.509, including post-quantum X.509

The server sends the leaf followed by each intermediate toward the root. The
self-signed root is a local `-CAfile` trust anchor and is not sent. Every DER
certificate contains its TBSCertificate, signature algorithm and issuer
signature. TLS 1.3 adds five bytes per CertificateEntry (three-byte certificate
length and two-byte empty extensions length) and eight fixed bytes (four-byte
handshake header, one-byte empty request context and three-byte certificate-list
length). CertificateVerify is a separate TLS message containing the server's
proof-of-possession signature. PQ X.509 uses the same framing.

## MTC-experimental landmark

The implementation targets `draft-ietf-plants-merkle-tree-certs-07` and
`draft-ietf-tls-trust-anchor-ids-04`. The online CertificateEntry carries one
DER-shaped MTC certificate whose signatureValue BIT STRING contains:

```text
extensions<0..65535>          2-byte length + data
start                         6 bytes
end                           6 bytes
inclusion_path<0..65535>      2-byte length + 32 bytes per SHA-256 sibling
signatures<0..16777215>       3-byte length; empty in landmark mode
```

An empty-extension landmark proof therefore has 19 fixed bytes plus 32 bytes
per sibling. For the current initial snapshot at a power-of-two population
larger than one, `cover(0,N)` creates two covered subtrees and leaf zero belongs
to `[0,N/2)`, producing `log2(N)-1` sibling hashes. The N=1 proof has none.
DER length octets and TLS CertificateEntry framing are counted separately.
CertificateVerify remains a separate proof of possession.

The local `trust.bin` is predistributed. It includes `authority.bin` (CA and
cosigner identifiers and SPKIs and serial constraints), a signed checkpoint
and subtree roots. It is not sent in landmark mode. The online proof contains
the 12-byte `start`/`end` reference and inclusion path. Checkpoint signatures
are checked while loading trust material before the handshake.

## MTC-experimental standalone

Standalone uses the same leaf and inclusion path but also carries signed
subtree trust material in `signatures`: a CA signature and one local
cosignature, with relative-OID and vector framing. Only `authority.bin` is
predistributed. This measures the extra online cost of carrying signed trust.

## Measurement boundaries

Certificate DER bytes, transmitted-chain DER bytes, TLS Certificate-message
bytes, total TLS BIO bytes, MTC proof bytes and offline trust bytes are distinct
metrics. TLS BIO bytes exclude TCP/IP headers and retransmissions. The client
`peer_auth` timer is reported as authentication-processing time because it can
include more than cryptographic signature verification.
