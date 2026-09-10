# Compact binary inspection tools

`inspect_compact_bin.py` is a read-only inspector for the repository-specific
Compact formats. It does not modify fixtures or require the patched OpenSSL
image. All output and errors are in English.

Supported formats:

| Magic | Typical file | Validation |
|---|---|---|
| `MTC2` | `credential-0000.bin` | Exact lengths, ASCII DNS name, dates, SPKI hash, and purpose |
| `MTP1` | `proof-0000.bin` | Exact lengths, leaf range, root, depth, and sibling hashes |
| `MCB2` | `bundle-0000.bin` | Nested credential/proof parsing and credential inclusion |
| `MTR2` | `root.signed` | Exact lengths, root metadata, authority hash, and signature size |

Inspect one proof structurally:

```sh
python3 tools/binary_inspection/inspect_compact_bin.py \
  artifacts/compact/batch16/pq/proof-0000.bin
```

Verify that a credential is included in that proof:

```sh
python3 tools/binary_inspection/inspect_compact_bin.py \
  --credential artifacts/compact/batch16/pq/credential-0000.bin \
  artifacts/compact/batch16/pq/proof-0000.bin
```

Inspect the persisted bundle. This also verifies inclusion automatically:

```sh
python3 tools/binary_inspection/inspect_compact_bin.py \
  artifacts/compact/batch16/pq/bundle-0000.bin
```

Inspect several files or a complete file family:

```sh
python3 tools/binary_inspection/inspect_compact_bin.py \
  artifacts/compact/batch16/pq/credential-0000.bin \
  artifacts/compact/batch16/pq/proof-0000.bin \
  artifacts/compact/batch16/pq/bundle-0000.bin \
  artifacts/compact/batch16/pq/root.signed

python3 tools/binary_inspection/inspect_compact_bin.py \
  artifacts/compact/batch16/pq/proof-*.bin
```

Exit status is zero only when every requested file passes the implemented
structural checks. `MTR2` inspection reports signature metadata but does not
cryptographically verify the signature; that operation requires the authority
public key and remains part of the laboratory verification suite.

These parsers apply to the Compact experiment. MTC-experimental uses an X.509
DER certificate with `MTCProof` in `signatureValue` and separate `MCF1`
authority/trust files; those are different formats.
