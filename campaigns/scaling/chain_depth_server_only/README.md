# Server-only chain-depth sensitivity

This block is independent from mutual-auth and trust-anchor retry.

## Goal

Compare X.509 and MTC-experimental server authentication while varying
server certificate-chain depth.

Fixed TLS settings:

- TLS 1.3
- X25519
- TLS_AES_256_GCM_SHA384
- no tickets
- no resumption
- server-only authentication
- tree size N=16 for MTC-experimental fixtures

## Chain profiles

Do not use L1/L2/L3 names in scripts, paths, CSV, JSON, or reports.

| chain_profile | depth_including_root | chain_depth | transmitted_certificates |
|---|---:|---:|---:|
| direct-server | 1 | 1 | 1 |
| ca-server | 2 | 1 | 1 |
| root-intermediate-server | 3 | 2 | 2 |

Definitions:

- `depth_including_root`: conceptual certificate path length from trust anchor to server certificate.
- `chain_depth`: number of certificates transmitted by the TLS server.
- `transmitted_certificates`: explicit synonym for on-wire certificate count.

## Reuse

This campaign should reuse logic from:

- `campaigns/scaling/cert_chain_scaling/fixture_builder.py`
- `campaigns/scaling/cert_chain_scaling/server.py`
- `campaigns/scaling/cert_chain_scaling/measure.py`
- `src/mtc/prepare.py`
- `src/mtc/prepare.py`

The existing `cert_chain_scaling` campaign already supports the equivalent
of `ca-server` and `root-intermediate-server` through `depth-2` and `depth-3`.

The missing case is `direct-server`, because the existing fixture builder
only accepts depths 2..5.

## Initial implementation plan

1. Add a new fixture builder for these three semantic chain profiles.
2. Keep `server.py` behavior: add `-cert_chain` only when intermediates exist.
3. Emit `chain_profile`, `depth_including_root`, `chain_depth`, and
   `transmitted_certificates` in every CSV/JSON row.
4. Keep mutual-auth code untouched.
5. Keep retry code untouched.

## Smoke validation

A first smoke validation was executed for `ecdsa-p256` with 1 warmup and 2 measured handshakes per profile.

Observed first-row Certificate message sizes:

| chain_profile | depth_including_root | chain_depth | certificate_message_bytes |
|---|---:|---:|---:|
| direct-server | 1 | 1 | 410 |
| ca-server | 2 | 1 | 458 |
| root-intermediate-server | 3 | 2 | 874 |

All smoke handshakes succeeded with:

- TLS 1.3
- X25519
- TLS_AES_256_GCM_SHA384
- no tickets
- no resumption
- server-only authentication
- OpenSSL verification return code 0

The increase from `ca-server` to `root-intermediate-server` confirms that the server transmits the intermediate certificate only for the third profile.
