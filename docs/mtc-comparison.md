# Conceptual comparison and scientific scope

MTC is based on `draft-ietf-plants-merkle-tree-certs-05`. This repository
measures an **MTC-experimental** profile, with deviations documented in
[mtc-protocol.md](mtc-protocol.md). The measurements do not constitute
conformance validation or a complete deployment of the IETF draft.

| Scheme | Implemented X.509 semantics | SPKI | Merkle proof | CA signature in TLS, apart from CertificateVerify | Shared trust | Status |
|---|---|---|---|---|---|---|
| Traditional X.509 | Native validation for the scenario, without CT | Inside X.509 | No | Individual leaf signature | X.509 CA | Standard mechanism |
| Pinned RPK | Local identity-to-key association | RPK | No | No | Key pinned out of band | RFC RPK; experimental local control |
| Compact warm | Minimal DNS, validity, and `serverAuth` | RPK, with hash in custom credential | Yes, earlier format | No | CA and signed root preloaded | Repository-specific experiment |
| Compact cold | Same as warm | Same as warm | Yes | Shared-root signature | CA preloaded; root transmitted | Repository-specific experiment |
| MTC-experimental standalone | X.509 leaf fields, limited path validation | Inside X.509 | Inclusion of `TBSCertificateLogEntry` | CA subtree signature and one local cosigner | CA/cosigner keys and policy | Internet-Draft -05 profile; no complete conformance |
| MTC-experimental landmark | Same as standalone | Inside X.509 | Inclusion relative to landmark subtree | None in `MTCProof` | Keys/policy and authenticated landmark out of band | Same experimental profile |

`CertificateVerify` and `Finished` remain in every scenario. No row removes
proof of possession of the TLS private key.

## Separating the effects

1. X.509 versus RPK measures the combined effect of the container and trust
   model; the PKI properties are not equivalent.
2. RPK versus Compact adds a minimal credential and proof. Published profiling
   sizes remain available, but their timing samples are not mixed with the MTC
   campaign as if they were paired.
3. X.509 versus MTC retains the X.509 container, changes CA authentication, and
   adds a proof. Standalone also requires an additional cosignature; the X.509
   baseline carries no SCTs. A larger standalone representation does not show
   that the IETF design is inefficient in a PKI with equivalent transparency.
4. Standalone versus landmark moves signatures to shared state outside TLS.
   Prior distribution and validation, issuance delay, updates, and storage must
   be accounted for even though they are not represented by the handshake.
5. Compact versus MTC compares architectures. MTC retains richer X.509
   attributes and extensions. Compact omits general chain validation, policies,
   name constraints, and extensible PKI mechanisms. This MTC profile also lacks
   general path machinery and is not credited with the capabilities of a full
   IETF/PKIX implementation.

CPU differences include parsing, the cryptographic provider, and the OpenSSL
integration. Measurements alone do not isolate the abstract cost of a Merkle
tree. Size measurements distinguish DER, proofs, signatures, messages, and
records. The study does not treat P-256 and ML-DSA-65 as identical nominal
security levels.

## Amortization

A theoretical threshold can be calculated as
`ceil(D / (B_standalone - B_landmark))`, where D is the material distributed
once and B is the byte count per handshake. Both complete D and incremental D
relative to common keys/policy are reported. A real policy must also account for
renewal, refresh, failures, and distribution of multiple landmarks. Each sample
here creates a process and reloads and verifies the file, so **persistent cache
reuse and real temporal amortization are not observed**.

The [results](mtc-results.md) report the measured profile, distinguish the main
campaign from exploratory scaling, and state the remaining limitations.
