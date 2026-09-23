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
docker compose -f docker/historical_campaigns/compose.profile.yaml build

PROFILE_DETAIL=1 docker compose -f docker/historical_campaigns/compose.profile.yaml run --rm --no-deps client \
  python3 /opt/profiling/test_tls.py
docker compose -f docker/historical_campaigns/compose.profile.yaml run --rm --no-deps client \
  sh /opt/profiling/test_timer.sh

PROFILE_DETAIL=0 docker compose -f docker/historical_campaigns/compose.profile.yaml \
  up -d --force-recreate --wait server
PROFILE_DETAIL=0 docker compose -f docker/historical_campaigns/compose.profile.yaml run --rm client \
  python3 /opt/profiling/benchmark.py --runs 30

PROFILE_DETAIL=1 docker compose -f docker/historical_campaigns/compose.profile.yaml \
  up -d --force-recreate --wait server
PROFILE_DETAIL=1 docker compose -f docker/historical_campaigns/compose.profile.yaml run --rm client \
  python3 /opt/profiling/benchmark.py --runs 30

docker compose -f docker/historical_campaigns/compose.profile.yaml down
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

See the [profiling results](../../docs/profile-results.md).

## Native connection timing (Stage 6C)

`tcp_connect_wall_ms_native` measures native connection entry to successful
return. The current OpenSSL `s_client` uses `init_client`, which performs
resolver/address selection and socket connection. Versions using
`BIO_do_connect` are instrumented around that call instead. This boundary is
not identical to the packet-based PCAP `tcp_connect_wall_ms`.

`connection_establishment_wall_ms_native` measures the original native connect
entry through the existing `SSL_CB_HANDSHAKE_DONE` timestamp. It includes any
application gap before TLS starts; it is not calculated by adding TCP and TLS
durations. Both timestamps use `CLOCK_MONOTONIC` and belong to the individual
SSL connection, with state reset before each connection attempt.

`handshake_wall_ms` retains its existing `SSL_CB_HANDSHAKE_START` to
`SSL_CB_HANDSHAKE_DONE` interval. PCAP extraction is independent: diagnostic
pairs are native TCP versus `tcp_connect_wall_ms`, TLS versus
`tls_from_pcap_wall_ms`, and full establishment versus
`connection_handshake_wall_ms`. Equality is not required.

Successful handshakes include both native values in `PROFILE_METRICS`.
`NATIVE_CONNECTION_METRICS` is also emitted when the SSL object is freed:
failed connections have both values `null`; successful connections followed
by incomplete TLS retain numeric TCP timing and `null` full timing. Failed
attempts do not acquire a fabricated successful campaign observation.
Forced process termination may prevent this final diagnostic record.

The small offline test `python3 src/profiling/test_native_timing.py` compiles
against host OpenSSL headers/libraries (`OPENSSL_PREFIX` overrides the prefix)
and checks boundaries, a deterministic application gap, connection isolation,
and numeric/null JSON. It opens no network connections.
