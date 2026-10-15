# Implemented-subset field map and decoder specification

Target: local `src/mtc/reference/draft-ietf-plants-merkle-tree-certs-07.txt`.
This is preparation, not a result or a full IETF compliance claim. Checks without observed evidence remain **NOT_EXECUTED**. Source mappings alone
do not establish a runtime PASS.
The table maps the actual initial-issuance prototype, including its restrictions.

Notation: U8/U16/U32/U48/U64 are unsigned big-endian integers of 1/2/4/6/8 bytes.
V8/V16/V24 are a byte length of that width followed by exactly that many bytes.
DER tags/lengths use definite, minimal DER encoding. `H` is SHA-256 (32 bytes).
M = mandatory, O = optional. Table order follows outer-to-inner decoding, with
separate blocks for derived and out-of-band data; it is not one concatenated object.

| implementation_field | source_file | wire_encoding | draft_section | draft_field_or_concept | validation_rule | implemented | notes |
|---|---|---|---|---|---|---|---|
| Certificate | src/mtc/core.py:certificate | M DER SEQUENCE(TBS, AlgorithmIdentifier, BIT STRING) | 6.2 | X.509 envelope | Consume exactly all input, canonical reserialization | yes | Local limit 65536 bytes |
| version | core.py:mtc_tbs | M [0] EXPLICIT INTEGER 2 | 5.2.1, 6.2 | certificate version | v3 only | yes | Copied from issuance certificate |
| serialNumber | core.py:mtc_tbs | M positive minimal DER INTEGER, <=64 bits | 6.2, 7.2 | log/index | `(log << 48) OR index`, log=1, index<N | yes | Not a separate leaf-index field |
| TBS.signature / signatureAlgorithm | core.py:ALG | M SEQUENCE(OID), absent parameters | 6.2 | id-alg-mtcProof | Both exactly 1.3.6.1.5.5.7.6.67 | yes | MTC-07 assigned OID; parameters omitted |
| issuer | core.py:name | M Name/SET/SEQUENCE(OID 1.3.6.1.5.5.7.25.3, RELATIVE-OID CA ID) | 5.1, 6.2 | CA distinguished name | Exactly one RDN/attribute; configured CA ID | yes | MTC-07 assigned id-rdna-trustAnchorID and binary RELATIVE-OID encoding |
| validity, subject | core.py:mtc_tbs | M original DER fields after issuer | 5.2.1, 6.2 | validity and identity | Bound into reconstructed entry; native TLS checks dates/hostname | yes | Offline proof validity alone is not current PKIX validity |
| subjectPublicKeyInfo | core.py:mtc_tbs | M DER SEQUENCE(algorithm, BIT STRING) | 6.2, 7.2 | actual leaf public key | OpenSSL parse, canonical DER, configured algorithm/curve | yes | Real leaf key; not a profile label in the certificate |
| unique IDs, extensions | core.py:mtc_tbs | O original context-tagged DER fields after SPKI | 5.2.1, 6.2 | certificate constraints | Covered by entry; original authorityKeyIdentifier removed at issuance | partial | General PKIX extension semantics not independently reimplemented |
| signatureValue | core.py:certificate | M BIT STRING: unused-bits byte 0 then raw MTCProof | 6.2, 7.2 | MTC proof | No extra ASN.1 wrapper/trailing bytes | yes | Not a conventional X.509 signature |
| MTCProof.extensions | core.py:proof | M V16 | 5.2.1, 6.2 | entry extensions | Preserve exact bytes; require strictly increasing types without duplicates | yes | Unknown well-formed extensions remain opaque |
| MTCProof.start/end | core.py:proof | M U48 start then U48 end | 4.1, 6.2 | half-open subtree range | Valid aligned subtree, start<=index<end, initial cover(0,N) | yes | Proof uses selected covering subtree, not always whole tree |
| inclusion_proof | core.py:proof | M V16 containing consecutive 32-byte hashes | 4.3.2, 6.2 | sibling path | Length multiple of32; exact fold exhaustion | yes | N16/index0 initial cover selects [0,8): 3 hashes, not log2(16) |
| signatures | core.py:signatures | M V24 concatenating SubtreeSignature records | 6.2 | cosignatures | Complete parse; strictly increasing (ID length, ID bytes) | yes | Landmark permits canonical unknown GREASE records, including empty signature bytes; standalone requires both configured signatures |
| cosigner_id | core.py:relid/signatures | M V8 canonical base-128 component encoding | 6.2, 5.3 | binary TrustAnchorID | Nonempty, canonical, no duplicate/out-of-order IDs | yes | Unknown IDs ignored for trust; two known signers still required |
| signature | core.py:signatures | M V16 opaque signature bytes | 5.3.1, 5.3.3, 6.2 | algorithm-specific signature | OpenSSL verify, no fixed signature-length assumption | yes | EC digest by curve; PQ without external digest |
| MTCLogEntry | core.py:entry | Derived V16 extensions + U16 type=1 + DER field concatenation | 5.2.1, 7.2 | tbs_cert_entry | Reconstruct; optionally compare log/*.entry | yes | No outer TBSCertificateLogEntry SEQUENCE wrapper |
| entry SPKI binding | core.py:entry | Derived algorithm DER + OCTET STRING(H(full SPKI DER)) | 5.2.1, 7.2 | subjectPublicKeyAlgorithm/InfoHash | SPKI hash enters authenticated leaf | yes | Entry omits serial/signature/SPKI itself |
| leaf / internal hash | core.py:root/evaluate | Derived H(00||entry); H(01||left||right) | 4.3.2, 7.2 (RFC9162) | domain-separated Merkle hash | Report every fold and compare core.evaluate | yes | No primitive cryptography reimplementation |
| CosignedSubtree | core.py:message | Derived label[12], V8 signer name, U64 timestamp, V8 log origin, U64 start/end, hash[32] | 5.3.1 | signature input | Exact domain `subtree/v1\n\0`; IDs prefixed `oid/1.3.6.1.4.1.`; log CA.0.1 | yes | Signature range widths are 64 bits, unlike proof range's48 |
| subtree signature timestamp | core.py:message | Derived U64 zero (not sent in MTCProof) | 6.2, 7.2 | certificate cosignature timestamp | Verify over zero | yes | Checkpoint uses its nonzero issuance timestamp |
| authority.bin | prepare.py:authority_config_v2 / mtc.c:mtc_load_authority_config_v2 | OOB `MCA2`: V8 CA, U16 signer count, repeated(V8 signer,V24 SPKI), U16 log, U64 min,max | UNRESOLVED_MAPPING | local authority serialization | Exact EOF, canonical identities and serial interval | local only | Draft7.1 configuration concept; **not** a draft wire structure |
| trust.bin | prepare.py:trust_config_v2 / mtc.c:mtc_load_trust_config_v2 | OOB `MTB2`: V32 canonical MCA2, V32 canonical MCP2, U8 signaling kind and optional U48 landmark | UNRESOLVED_MAPPING | atomic local authority/checkpoint/signaling storage | Strict nested codecs; checkpoint authentication; explicit signaling identity | local only | Concepts5.3.1/6.4/7.4; bytes are local formats, not a draft checkpoint format |
| snapshot.mcp2 | snapshots.py / check_snapshot.c | OOB `MCP2`: U48 N,U64 timestamp,hash[32],V24 signatures, exactly two covering subtree records | UNRESOLVED_MAPPING | authenticated checkpoint storage | cover(0,N), reconstruct root, verify configured signatures | local only | Checkpoint concepts5.3.1/6.4/7.4; no landmark signaling identity |
| landmark identifier | mtc.c:mtc_load / tls.c | TLS selection CA.1.log.landmark, normal advertisement CA.2.1.1, base128 IDs | 8.2 | individual landmark trust anchor | For local log1/landmark1 require CA.1.1.1 | yes | **Absent from MTCProof**; only configuration/transport names it |
| tree size / root / signer keys | prepare.py / mtc.c | OOB only; root also derived from proof | 6.3, 6.4, 7.1–7.4 | trusted state | Trust supplied explicitly; bind via signatures | yes | No N, root or issuer SPKI embedded as separate MTCProof fields |
| TLS Certificate | src/mtc/patch.py, tls.c | Standard TLS1.3 type11,U24 body,V8 context,V24 list; entry V24 DER,V16 extensions | 8 (RFC8446 framing) | certificate transport | Extract exact DER from decrypted/reassembled packet bytes | yes | Payload MTC is experimental; TLS framing remains native |
| 0xca34 CH/EE | src/mtc/tls.c:add/parse | Provisional extension U16 type,U16 length; V16 list of V8 IDs | TA-04 3, 4.1–4.3; MTC-07 8.1/8.2 | initial single-log group / exact individual-ID subset | CH CA.2.1.1 or exact CA.1.1.1; EE CA.1.1.1, canonical encoded bytes | local only | Complete trust_anchors draft protocol not validated; not a final IANA codepoint assignment |
| 0xca34 CertificateEntry | src/mtc/tls.c:add/parse | U16 type=0xca34,U16 length=0 | TA-04 4.1/4.2 | first-entry selection confirmation | Required on entry0 only, after matching EE | local only | Prototype-specific additional negotiation gate |
| CertificateVerify / Finished | native OpenSSL via patch.py | Standard TLS1.3 type15/type20 | 8 (RFC8446) | possession/transcript authentication | Endpoint success + decrypted message order; actual CV scheme recorded | yes | Optional exact-byte offline verifier; separate endpoint and independent results |

## Checklist classification

Runtime reports classify checked rules PASS/FAIL only after execution.
`NOT_IMPLEMENTED`: general entry extensions, null entries, evolving logs/landmarks,
general landmark groups, consistency monitoring, revocation database, public cosigner
operations, general MTC PKIX path building. These are not failures of this scoped
prototype. `NOT_APPLICABLE`: TLS checks in an offline-only object report.
`UNRESOLVED`: independent evidence
for the checkpoint signer's actual signing time/largest observed tree. MCA2,
MCP2, and MTB2 remain local storage formats, not a claim about a draft wire
encoding. Current-clock
checkpoint policy is LOCAL_POLICY, not an unresolved maximum-age draft rule. Operational CA identity persistence across
independent fixture roots is outside a one-object check; preserve each trust root.

A successful object check means the configured keys authenticate the reconstructed
entry. It does not establish that those keys are trusted by a public ecosystem.
The offline validator is intentionally stricter about the initial cover than the
general C standalone verifier; this is a workflow scope restriction, not a draft
requirement. Runtime reports retain unresolved mappings even when checked rules pass.

## Pinned specification review (2026-09-13)

Only the preserved `draft-ietf-plants-merkle-tree-certs-05.txt` and
`draft-ietf-tls-trust-anchor-ids-04.txt` in `src/mtc/reference/` were used for
MTC/trust-anchor requirements. No newer draft was substituted.

| Source sections | Interpretation and evidence boundary |
| --- | --- |
| TA-04 §3 | Binary ID is the DER RELATIVE-OID contents, without tag/length. Decode minimal base-128 components, not a hard-coded byte match. |
| TA-04 §4.1 | The actual type names are RequestedTrustAnchorList (CH, unordered, may be empty) and AvailableTrustAnchorList (EE, nonempty, server preference order). No lexical ordering requirement applies to these lists. |
| TA-04 §4.2 | Matching candidate selection is acknowledged by an empty extension on the first CertificateEntry only. MTC subset has exactly one entry. Length and payload are both checked. |
| TA-04 §4.3 | General retry and candidate enumeration are not implemented. A singleton EE list has trivial preference order. Native code rejects an empty CH list, although the draft permits it. |
| TA-04 §11.1 | ExtensionType is TBD. 0xffa7 is private/experimental, never an IANA assignment. |
| MTC-07 §8.1, §8.2 | Standalone uses CA ID. Individual landmark uses CA.1.log.landmark. |
| MTC-07 §8.2.1 | Recommended group is CA.2.log.landmark. Normal native advertisement is CA.2.1.1, selecting member CA.1.1.1. Exact individual selection remains supported. Only initial log 1 / landmark 1 membership is implemented; automatic retry is not. |
| MTC-07 §6.2, §7.2 | MTCProof cosignature input timestamp must be uint64 zero, already cryptographically verified this way. Landmark mode does not require trusted cosignatures; canonical unknown GREASE records are permitted. |
| MTC-07 §5.3.1, §5.3.2 | Nonzero timestamp states POSIX signing time, start=0, and end=largest tree observed by the signer. Encoding and signed range are checked; actual signing time and signer history are not independently observable from a single certificate/checkpoint. |

The local MCP2 checkpoint records uint64 timestamp, uint48 size and root. Offline validation
verifies its signatures over start=0/end=configured size. The native loader enforces
`timestamp > 0 && timestamp <= time(NULL)`. There is **no maximum-age threshold**.
Neither this source inspection nor an offline signature check proves that the native
clock check was executed for a new run. Reports retain `execution_status=NOT_EXECUTED`
for this local-policy layer. The offline decoder's nonzero checkpoint requirement is
also a local storage restriction: MTC-05 generally allows zero subtree timestamps.

`PASS_EXPERIMENTAL_CODEPOINT` applies only when observed CH, EE and CertificateEntry
bytes pass structure checks and match the configured individual anchor. An observed initial-group negotiation additionally reports §8.2.1 recommendation PASS and group_membership_valid=true. This does not prove complete trust_anchors behavior.
For the inspected alternative capture, CA=32473.112, log=1, landmark=1 gives
individual 32473.112.1.1.1 and recommended group 32473.112.2.1.1. Landmark number 1
comes from this prototype's fixed native configuration, not from MTCProof; log is
also decoded from the certificate serial. Historical PQ uses its own CA ID.

Independent TLS input follows RFC 8446 §§4.4.1, 4.4.3, 4.4.4 and 7.1. The transcript
contains exact handshake headers and bodies, never record headers, JSON rendering,
PDML reconstruction or fixture bytes. The current verifier accepts only the seven
messages CH, SH, EE, Certificate, CV, server Finished, client Finished in a single
IPv4 flow with correct directions, AES-256-GCM/SHA384, no HRR/PSK/client auth/tickets.
Other shapes report missing exact supported transcript evidence rather than inventing
bytes. CV uses wire SPKI and an explicit scheme/OID mapping (ML-DSA 0x0904–0x0906;
ECDSA 0x0403/0x0503/0x0603); unsupported schemes remain NOT_IMPLEMENTED.

Normal landmark clients advertise `32473.112.2.1.1`; the individual
`32473.112.1.1.1` remains available for exact selection/retry by callers.
Automatic retry and standalone-CA fallback from a group are not implemented.
The active provisional `0xca34` is aligned with Chromium/BoringSSL, not final IANA: this is implemented-subset
conformance, not full MTC-07 conformance. Historical captures retain their observed IDs.

## Wire codepoint migration

The active laboratory uses provisional `0xca34`, matching native Chromium/BoringSSL
`trust_anchors`. Earlier experimental runs used private `0xffa7`; their artifacts
remain unchanged. Neither value is described here as a final IANA assignment.
The pinned Trust Anchor IDs -04 text says ExtensionType TBD; changing the codepoint
does not establish full draft compliance or update the pinned specification.
Both values occupy a uint16: this migration alone changes no size-model numbers.
Active extractors accept only the current codepoint; historical captures require
the matching historical tools, not relabeling or regeneration in place.
