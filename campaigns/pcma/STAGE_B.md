# PCMA Stage-B TLS integration plan

Stage B is not implemented. The present laboratory does not add a TLS scenario
named `pq-compact-pcma`, and no existing scenario has changed semantics.

A real implementation would extend the private Compact extension `0xffa6` with
explicit PCMA negotiation, carry a serialized `PCA1` value in ClientHello, and
carry `MTP2` instead of `MTP1` in EncryptedExtensions. The client verifier must
use state scoped to the verified `MTR2` root and complete credential/SPKI,
identity, validity, CertificateVerify and Finished checks exactly as Compact
does now. Missing state needs an explicit protocol fallback or fatal alert.

The current measurement driver launches a new `s_client` process for every
sample. It cannot measure progressive state without either a persistent client
driver or an authenticated cache file with transactional updates. That change
also needs privacy controls, cache update/rotation tests, extension downgrade
tests and separate protocol commits before a controlled campaign is prepared.

When implemented, Stage B should compare PQ X.509, `pq-compact-warm`, and a new
PCMA scenario under TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only
authentication, disabled tickets/resumption, the same image and the existing
byte/time definitions. It must record ClientHello bytes, server authentication
bytes, total handshake bytes and wall time. Stage-A CSV files must remain
separate from TLS measurements.
