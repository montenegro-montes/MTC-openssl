# TLS profiling phase and RPK control

This phase adds the independent `mt-tls-profile:local` image and instrumented
libraries while preserving the initial and Compact phases.

It compares the previous eight scenarios and two pinned-key RPK controls:
`classic-rpk` and `pq-rpk`. The client locally pins
`server -> SHA256(SPKI)` through OpenSSL TLSA/DANE handling without a DNS
query. This control does not reproduce complete PKI, credential-expiration, or
Compact authorization semantics. `CertificateVerify` remains active.

## Run

The Compact image, original certificates, and N=16 batch must already exist.
This phase never regenerates or overwrites them.

```sh
docker compose -f docker/compose.profile.yaml build

PROFILE_DETAIL=1 docker compose -f docker/compose.profile.yaml run --rm --no-deps client \
  python3 /opt/profiling/test_tls.py
docker compose -f docker/compose.profile.yaml run --rm --no-deps client \
  sh /opt/profiling/test_timer.sh

PROFILE_DETAIL=0 docker compose -f docker/compose.profile.yaml \
  up -d --force-recreate --wait server
PROFILE_DETAIL=0 docker compose -f docker/compose.profile.yaml run --rm client \
  python3 /opt/profiling/benchmark.py --runs 30

PROFILE_DETAIL=1 docker compose -f docker/compose.profile.yaml \
  up -d --force-recreate --wait server
PROFILE_DETAIL=1 docker compose -f docker/compose.profile.yaml run --rm client \
  python3 /opt/profiling/benchmark.py --runs 30

docker compose -f docker/compose.profile.yaml down
```

Both endpoints must use the same `PROFILE_DETAIL` value. Every run creates a
new directory under `artifacts/results/`. The launcher
`/opt/profiling/openssl.sh` selects instrumented libraries only for its process.

## Measurements and interpretation

- Client and server handshake wall/process CPU time. Summed CPU covers both
  endpoints and is not elapsed time.
- Correlation through the public ClientHello random without extra TLS bytes.
- TLS BIO transport bytes during the handshake, excluding Ethernet/IP/TCP
  headers and retransmissions.
- Inclusive timers for certificate/RPK processing, peer authentication,
  `CertificateVerify`, certificate construction, identity validation, SPKI,
  Merkle proofs, and root signatures. Nested categories must not be added.
- Warm root-signature verification before TLS, recorded separately. Each sample
  starts a new client and does not model a persistent cache.
- Three warmup rounds and 30 measured rounds with reproducible random order,
  sample/component CSVs, medians, and round-bootstrap comparisons.

`PROFILE_DETAIL=0` retains aggregate measurements and disables component
timers. Comparing both series can reveal instrumentation disturbance, but
successive Docker Desktop blocks do not isolate that cost causally. These are
local exploratory results without latency or bandwidth emulation.

See the [profiling results](../docs/profile-results.md).
