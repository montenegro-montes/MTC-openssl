# Paper-1 MTC profiles: manual functional gate

Preparation for an **experimental implementation targeting
 draft-ietf-plants-merkle-tree-certs-05**, without a claim of full IETF compliance.
The registry is `src/mtc/crypto_profiles.py`. All nine named profiles use their
actual algorithm for issuance, both MTC signers and the leaf TLS key. The issuance
CA and MTC signers have distinct keys. ECDSA uses P-256/SHA-256,
P-384/SHA-384 or P-521/SHA-512; PQ signatures use no external digest.
The Merkle hash remains SHA-256. Reported levels describe the signature profile,
not the security of the entire construction.

`classic` remains P-256 and `pq` remains ML-DSA-65, with their original IDs and
scenario names. This workflow creates a separate population; it does not depend
on original scaling campaign steps 20–22. `landmark` is the primary comparison;
`standalone` is secondary. No performance matrix is prepared here.

## Exact manual sequence

Run from the repository root. These commands are for the operator; none were
executed during implementation. Keep this source version fixed across the gate.
Use the current OpenSSL 3.4.7 / liboqs 0.16.0 / oqs-provider stack; the build below
rebuilds only MTC on the existing profile image, without changing dependency pins.

```sh
bin/original_campaigns/mt-containers build mtc
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
MTC16="artifacts/paper1-mtc/n16-$STAMP"
MTC_VALID="artifacts/results/paper1-mtc-n16-$STAMP"
python3 campaigns/cryptographic_scaling/mtc_profile_scaling/workflow.py generate --output "$MTC16" --execute
python3 campaigns/cryptographic_scaling/mtc_profile_scaling/workflow.py validate --fixtures "$MTC16" --output "$MTC_VALID" --execute
```

Stop at any failure. Generation defaults to **only N=16, all nine profiles,
both modes**. Validation first parses all certificates, loads signer and leaf
public keys and checks profile/curve, verifies checkpoint and inclusion signatures
for leaves 0 and 15, and independently signs/verifies with both signer keys.
It then runs one landmark connection for each profile, followed by one standalone
connection for each: **18 handshakes total**, no warmups or retries. It requires
MTC verification, native TLS CertificateVerify/Finished, HTTP success and both
processes completing successfully. This is server authentication, not mutual TLS.
TLS uses 1.3, X25519 and TLS_AES_256_GCM_SHA384, without tickets or resumption.
Connections are container-local loopback under `--network none`; these are
functional checks, not observations from the bridge-based performance campaign.

Only a complete successful `validation.json` authorizes other N values. A partial
selection (`--profile NAME`, `--mode landmark` or `--mode standalone`) cannot pass
that gate. `cert_chain_scaling/run_mtc.py` forwards to this validator by default.
Its explicit `--legacy` option retains the original two-profile measurement CLI.
Omitting `--execute` prints the selection without invoking Docker.

After all 18 cells pass, create a new complete fixture set. This copies the
validated population and signer keys, preserving the original directory:

```sh
MTC_ALL="artifacts/paper1-mtc/all-$STAMP"
python3 campaigns/cryptographic_scaling/mtc_profile_scaling/workflow.py generate --sizes 1 4 16 64 256 1024 --seed-fixtures "$MTC16" --validated-n16 "$MTC_VALID/validation.json" --output "$MTC_ALL" --execute
```

The gate requires identical source hashes, image ID and N=16 fixture hashes.
A changed implementation/image requires a fresh N=16 validation. Certificates
expire after 30 days; use fresh paths when regeneration is necessary.
Afterward, with `CHAIN_FIXTURES` pointing to the separately validated nine-profile
X.509 certificate-chain fixtures, run the static comparison manually:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/size_analysis.py "$CHAIN_FIXTURES" --mtc-fixtures "$MTC_ALL" --output "artifacts/results/paper1-crossover-$STAMP"
```

Analysis compares identical algorithm names and verifies the MTC profile metadata
and hash manifests. Larger powers of two remain serialization models, not measured
TLS results. Fixture hash files prove consistency, not independent authentication;
the successful functional gate supplies the cryptographic validation evidence.

Future fixture manifests and validation reports record profile, standard and
implementation names, signature level, N, modes, target draft, Git commit and dirty
status, OpenSSL/liboqs versions, oqs-provider commit, image ID and source/fixture
hashes. Validation stores commands and separate server/client logs per cell.
Never reuse output directories. Private keys and observations stay in `artifacts/`.

## Later packet inspection: fields only

Do not install or run capture tools as part of preparation. For later representative
`pq-mtc-experimental-landmark` and `pq-mtc-experimental-standalone` captures, keep
those historical labels and their ML-DSA-65 identities. New Paper-1 ML-DSA-65
uses `mldsa65` and IDs 32473.112 / 32473.212 instead; do not relabel old captures.

Check these fields against `src/mtc/core.py`, `mtc.c` and `tls.c`:

- ClientHello and EncryptedExtensions: experimental extension 0xffa7, uint16
  list length, uint8 individual lengths, canonical base-128 trust-anchor ID and
  matching selection. Landmark signaling includes the `.1.1.1` suffix;
  standalone uses the authority ID. This is a local extension, not an assigned
  IANA code point; keep captures separate from other experimental protocols.
- Certificate: one leaf; TLS uint24 certificate length and uint16 extensions
  length; empty 0xffa7 CertificateEntry extension confirming negotiation.
- DER: v3 certificate; inner and outer proof algorithm OID
  `1.3.6.1.4.1.44363.47.0` with no parameters; issuer attribute OID
  `1.3.6.1.4.1.44363.47.1`; serial `(log_id << 48) | leaf_index`; actual
  ML-DSA-65 SPKI, subject/SAN, validity and leaf constraints.
- signatureValue: zero unused BIT STRING bits, MTCProof range, inclusion vector
  lengths and 32-byte hashes. Reconstruct the entry and SHA-256 path with the
  existing leaf/node domain separation; validate the range and index.
- Landmark: no on-wire subtree signatures; match the root to the separately
  authenticated checkpoint/trust material. `MCF1` is a local file format and
  must not appear as a transmitted certificate or be counted as TLS bytes.
- Standalone: two actual signatures, canonical ordered signer IDs and uint16
  signature lengths; verify the existing `subtree/v1` domain, signer/log IDs,
  timestamp, range and root encoding. Require both signatures.
- CertificateVerify: negotiated signature scheme must match the actual leaf key;
  Finished and successful application response must authenticate the transcript.
  Check TLS 1.3, X25519, cipher selection and absence of resumption/0-RTT.

TLS 1.3 encrypts the certificate flight. A later capture requires a deliberately
recorded session-key log for decryption; keep it private alongside capture hashes,
commands, exact source/image provenance and the matching out-of-band trust files.
Compare the implemented subset to the target draft; record deviations rather than
claiming full compliance.

Remaining manual risks: provider algorithm/curve aliases and TLS scheme support,
compilation against the actual image, and large SLH-DSA standalone proofs. In
particular, two SLH-DSA-SHA2-256s signatures approach the 65536-byte local bound;
the gate must validate their actual serialized lengths and successful processing.
