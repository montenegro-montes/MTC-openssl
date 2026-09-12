# Phase 2: Compact Merkle authentication and TLS comparison

This phase extends the initial laboratory. It preserves the base Docker image,
Compose definition, received code, integration, scripts, executables, and prior
results. See the [root README](../README.md) for initial setup.

The Compact variant sends an RPK and a Merkle credential containing identity,
validity, and key data instead of an X.509 chain. TLS 1.3,
`CertificateVerify`, and `Finished` remain present. The authority signs one
root per batch. The experiment evaluates a predistributed root and a signed root
sent during each handshake. This is an experimental laboratory protocol, not an
MTC standard implementation or a replacement for every X.509 PKI function.

## Build and prepare

```sh
# Preserved base image and original fixtures:
docker compose -f docker/original_campaigns/compose.yaml build
docker compose -f docker/original_campaigns/compose.yaml run --rm setup

# Independent Compact image and a new N=16 batch:
docker compose -f docker/original_campaigns/compose.compact.yaml build
docker compose -f docker/original_campaigns/compose.compact.yaml run --rm setup
```

The final command creates `artifacts/compact/batch16/` with 16 valid
certificates per family and independent keys for the 15 additional identities.
Leaf zero uses the original server certificate and key. The X.509 and Compact
trees use the same population. Original two-leaf trees remain unchanged.

Create a different size in a new directory:

```sh
docker compose -f docker/original_campaigns/compose.compact.yaml run --rm setup \
  python3 /opt/compact/prepare.py --both --leaves 64 \
  --output /work/compact/batch64
```

Supported sizes range from 1 to 1024 leaves. Private keys remain under ignored
`artifacts/`. Existing batches and certificates are never replaced.

## Run the comparison

```sh
docker compose -f docker/original_campaigns/compose.compact.yaml up -d --wait server
docker compose -f docker/original_campaigns/compose.compact.yaml run --rm client
docker compose -f docker/original_campaigns/compose.compact.yaml down
```

The server launches eight `s_server` processes. After three warmups, the client
measures 30 connections per scenario with reproducibly randomized round order.

| Scenario | Authentication | Merkle root |
|---|---|---|
| `classic` | X.509 ECDSA P-256 | Not applicable |
| `pq` | X.509 ML-DSA-65 | Not applicable |
| `classic-mt`, `pq-mt` | X.509 plus phase-1 Merkle proof | Predistributed |
| `*-compact-warm` | RPK plus Compact credential | Predistributed and validated before TLS |
| `*-compact-cold` | RPK plus Compact credential | Signed root sent and validated in TLS |

All scenarios use the same instrumented executable and libraries, TLS 1.3,
X25519, `TLS_AES_256_GCM_SHA384`, and no resumption. The PKI has a direct root
CA whose certificate is not sent in TLS.

Select another batch consistently on both endpoints:

```sh
COMPACT_BATCH=/work/compact/batch64 \
  docker compose -f docker/original_campaigns/compose.compact.yaml up -d --force-recreate --wait server
COMPACT_BATCH=/work/compact/batch64 \
  docker compose -f docker/original_campaigns/compose.compact.yaml run --rm client \
  python3 /opt/compact/benchmark.py --runs 60 --warmup 5 --seed 123
docker compose -f docker/original_campaigns/compose.compact.yaml down
```

Each run creates a new `artifacts/results/compact-<timestamp>/` directory with
samples, summaries, paired comparisons, metadata, logs, and a report. An
authentication failure aborts the run without creating a success summary; prior
valid logs and samples remain available for diagnosis.

## Tests

```sh
docker compose -f docker/original_campaigns/compose.compact.yaml run --rm client \
  /opt/compact/test_parser /work/compact/batch16/pq/bundle-0000.bin
docker compose -f docker/original_campaigns/compose.compact.yaml run --rm client \
  python3 /opt/compact/test_tls.py
docker compose -f docker/original_campaigns/compose.compact.yaml run --rm client \
  python3 /opt/mt/tests/test_tls.py
```

Tests start temporary local servers inside the container. The comparative run
uses separate client and server containers.

See the [protocol](../docs/compact-protocol.md),
[methodology](../docs/compact-methodology.md), and
[initial results](../docs/compact-results.md).
