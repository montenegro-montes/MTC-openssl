# PCMA Stage B protocol v1

This is a separate, opt-in TLS 1.3 experimental protocol. Production readiness
and end-to-end TLS success have not been established during preparation.

## Confirmed existing Compact warm flow

The authoritative implementation is `src/compact/compact.c`, included **without
modification** by `native/tls.c`. `src/compact/patch.py` adds the command-line options
to the copied OpenSSL `apps/s_client.c` / `apps/s_server.c`; it does not replace
native CertificateVerify or Finished verification. `src/compact/scenarios.py` and
the chained scenario definitions in `campaigns/historical_campaigns/controlled_n16_campaign/scenarios.py`
select the configured OpenSSL executable. Existing measurement code launches a
new `s_client` per sample and has no persistent Merkle-node cache.

`compact_client()` loads a CA X.509 certificate, obtains its public key, checks
CA status and validity, and verifies `MTR2` with `root_decode()`. The signed
88-byte MTR2 header contains magic[4], N[4], root[32], notBefore[8], notAfter[8],
authority SPKI digest[32], followed by signatureLength[2] and signature. The
root's validity must lie within the trusted authority certificate interval.

`install()` enables TLS 1.3, raw-public-key server Certificate type and disables
tickets and the session cache. In `add()`, warm ClientHello extension **0xffa6**
contains `02 00 || root[32]` (34 payload bytes; 38 including the TLS extension
header). Cold uses `02 01` and subsequently receives the signed root.

On the server, `compact_server()` loads/validates the credential's complete
proof and `parse()` verifies the offered root. `add()` returns MCB2 in
EncryptedExtensions: `MCB2[4] | credentialLength[2] | credential |
proofLength[2] | MTP1 | rootLength[2]=0`. Cold appends the signed root instead.

`bundle_decode()` decodes MTP1. Client `verify()` obtains the negotiated RPK
with `X509_STORE_CTX_get0_rpk()` and invokes `credential_verify()`, which checks
canonical DNS identity, credential/root/CA validity, serverAuth purpose,
supported key type and SHA-256 of DER SPKI, then `mt_proof_verify()` checks the
Merkle path against the trusted root. The RPK travels in the TLS Certificate
message. OpenSSL still verifies CertificateVerify's transcript signature using
that key and verifies Finished. Relevant upstream library paths are
`ssl/statem/statem_clnt.c`, `ssl/statem/statem_srvr.c`, `ssl/statem/statem_lib.c`
and `ssl/statem/extensions_cust.c`; no library patch is introduced by Stage B.
Those upstream paths describe the normal OpenSSL state machine; the repository
changes inspected directly are the app patch and Compact callbacks above.

## Separate PCMA registration and messages

Stage B uses private-use extension **0xffa7**, registered for ClientHello and
TLS-1.3 EncryptedExtensions. Existing extension 0xffa6 and its implementation
remain unchanged. PCMA and Compact warm are not simultaneously enabled.

ClientHello extension header is the ordinary TLS `type=u16(0xffa7), length=u16`
(big-endian). Its payload is **exactly Stage-A.2 ranges**:

```text
PCA2 [4] | version=1 [1] | encoding=ranges=4 [1] |
root [32] | U(N) | U(range_count) | { U(start), U(length) }*
```

U is minimal unsigned LEB128, bounded to 65535. Nodes are numbered level-major,
index-minor, excluding the root. Width starts at N and repeatedly rounds up
when halved. Ordinal `(level,index)` is `sum(previous level widths)+index`.
N is limited to 2..1024 natively, with powers 16/64/256/1024 exposed in campaign
configs. Bitmap ordinal 0 is leaf 0. Range intervals are half-open and maximal;
zero length, overlap, adjacency, unsorted descriptors, out-of-range coordinates,
unknown magic/version/mode, overlong integers and extra/truncated data fail.
There are no hashes in the advertisement. Possessing a range asserts each
individual coordinate, not merely possession of a subtree root.

The server expands the ranges to a bounded local availability array and selects
only the siblings in its existing **verified MTP1** for that credential. It does
not need another full-tree materialization: the existing per-credential proof
already contains every server-side hash it might transmit. Nonadvertised nodes
are always sent.

PCMA EncryptedExtensions payload:

```text
PCB1 [4] | credential_length u16 [2] | credential |
partial_proof_length u16 [2] | MTP2
```

PCB1 is v1; unknown magic fails. It omits MCB2's two-byte root-length field:
PCMA always requires a preverified signed root. This is the only bundle-format
change beyond replacing MTP1 with MTP2. Normal MTP1 remains unchanged.

MTP2 is **byte-identical to Stage A/A.2**:

```text
MTP2 [4] | N u32 [4] | leaf_index u32 [4] | root [32] |
depth u8 [1] | bitmap_length u8 [1] | bitmap | transmitted hashes [32 each]
```

The bitmap has `ceil(depth/8)` bytes; sibling level l is bit `7-l%8` in byte
`l//8`. One means transmitted; zero means required from local authenticated
state. Unused low padding bits must be zero. Exact length is
`46 + ceil(depth/8) + 32*transmitted_hashes`. Redundant root/N fields are retained
intentionally for exact A.2 compatibility and independent parser checks. They
are included in measured bytes, not silently removed as a TLS-context shortcut.

## Verification and transaction boundary

`pc_reconstruct()` checks root, N, leaf, depth, bitmap, lengths and availability,
then constructs an MTProof using received and local hashes. Reconstruction is
**not** acceptance. `pc_verify()` invokes the original Compact
`credential_verify()` with the RPK. It stages a copy of the cache and calls
`pc_learn()` to verify and derive authenticated nodes. No file is written there.
Only `pcma_finish()`, called by the native client after successful `SSL_connect`,
peer verification, group/cipher/version/key checks and nonresumption checks,
atomically persists the pending cache. At that point native OpenSSL has verified
CertificateVerify and server Finished and sent client Finished. This does not
mean the server has acknowledged application data; no such claim is made.

Any failed client handshake discards pending state. Cache-learning metrics on
failure expose the committed occupancy, not the discarded candidate occupancy.
The runner aborts a failed campaign and retains its failure row and logs; it
never retries silently. A server-side failure after client completion can still
make the campaign fail even if the client legitimately committed state; the raw
client/server statuses and before/after file hashes remain distinct.

Logical accounting is unchanged: `floor(budget/69)` nodes. Nodes retain
root/tree, coordinate and actual SHA-256 value. Native storage factors the common
root out of the record but still charges 69 logical bytes. Array order represents
Stage-A insertion/LRU order. Hits are accounted in proof-sibling order; verified
nodes are inserted in leaf/sibling/path order; upper-level eviction removes the
lowest level first and breaks ties by retained order. Eviction occurs after the
whole authenticated path update. The trusted root is excluded.

Private disk format PCS1 is **not a network advertisement**:

```text
PCS1[4] | N u32[4] | root[32] | budget u32[4] | policy u8[1] |
count u32[4] | { ordinal u32[4], hash[32] } in LRU/insertion order
```

Policy 0=LRU, 1=upper-level. Files are owner-only 0600, written to a new temporary
file, fsynced and renamed. Load rejects symlinks, wrong owner/permissions,
root/N/budget/policy mismatch, duplicates and invalid sizes/coordinates. Local
values never become independent trust anchors: wrong hashes still fail the
Merkle-root verification. The parent directory and same-UID writers are trusted;
concurrent writers, rollback resistance and crash durability of directory rename
are not solved. The runner uses a fresh cache path per campaign/budget and runs
its accesses sequentially. Cache I/O/setup is outside the timed handshake.

## Failure and downgrade contract

Missing cached state, incorrect coordinates/hashes, malformed/truncated/extra
proofs, wrong/stale roots, invalid ranges and unsupported versions/encodings
fail. There is **no fallback**. Cache hits/misses in a valid proof are different:
a nonadvertised sibling is explicitly transmitted and is a normal successful
cache miss. An advertised but unavailable required node is fatal.

A PCMA client receiving normal Compact warm/cold does not have a successful
PCMA verification callback and fails. A PCMA server missing the advertisement
fails its final PCMA completion check. There is no path which skips
credential/SPKI/root, CertificateVerify or Finished requirements. To compare a
performance downgrade, the operator explicitly starts the separate warm/cold
scenario; negotiation cannot silently change the authentication contract.

## Privacy gate and remaining exposure

The driver requires an explicitly selected authority, verified root, expected
DNS hostname and cache path before offering PCMA. The campaign runner obtains
that mapping from a local fixture roster and checks proof/root identity before
any connection. It uses exact SNI and hostname verification for each credential,
including `member-i.lab`; it does not advertise based on an arbitrary network
peer's unsolicited claim or automatically enable PCMA on generic connections.

This is an **operator-provisioned trust-domain association**, not a discovery
protocol. Before ServerHello, the network endpoint is not authenticated. A
misdirected connection, compromised DNS or an on-path observer can see the
ClientHello state. This prototype does not offer ECH, private set intersection,
anti-probing or unlinkability. Exact node ranges reveal occupancy and potentially
history, locality, stable fingerprints, cross-service correlation and linkability;
repeated observations enable cache probing. Knowing a leaf hash does not prove
that credential was visited because sibling hashes are also learned.

## Accounting differences from A.2

`advertisement_bytes` and `proof_bytes` match A.2 exactly. Preserve its metric:
`net_authentication_bytes = advertisement_bytes + partial_proof_bytes`;
`net_authentication_saving = normal_MTP1_bytes - net_authentication_bytes`.
This is an explicitly labelled proof/advertisement payload comparison.

For matched Compact warm versus PCMA plaintext handshake messages, the expected
saving is **A.2 net saving + 36 bytes**: warm already sent a 34-byte root offer,
and PCB1 removes the two-byte MCB2 root-length field. TLS extension headers are
four bytes in each direction for both protocols and cancel. Audit checks this
exact equation against observed message-callback counts. TLS record overhead,
fragmentation and transport effects are separately measured and need not equal
that plaintext difference. PQ X.509 does not have this proof-only metric.

Timing instrumentation is diagnostic and versioned. Native pending learning
performs a defensive second Merkle verification, whereas A.2 verifies MTP2 once.
`credential_verify_ms` includes the original identity/SPKI/first Merkle check;
`verification_ms` measures the second pure Merkle check. These are different
windows. Lookup is a subset of reconstruction; range lookup is a subset of
partial construction. Do not sum overlapping timers. Cache persistence and
root/certificate/key setup are outside the handshake window. No TLS latency
or CPU result is claimed until campaigns are manually executed.
