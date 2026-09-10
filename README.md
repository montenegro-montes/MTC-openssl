# TLS 1.3 with post-quantum authentication and Merkle trees

This reproducible laboratory studies the time and size costs of different TLS
1.3 server-authentication representations. It compares X.509 certificates,
post-quantum certificates, raw public keys, Compact Merkle credentials, and an
experimental implementation of Merkle Tree Certificates (MTC).

The scientific objective is to determine whether Compact Merkle and MTC reduce
post-quantum authentication bytes and how their connection times change under
latency, bandwidth constraints, packet loss, and combined network conditions.

## Evaluated variants

The controlled configuration fixes TLS 1.3, X25519,
`TLS_AES_256_GCM_SHA384`, server-only authentication, disabled tickets, and no
resumption. Classic certificates use ECDSA P-256. Post-quantum certificates use
ML-DSA-65. The CA and server use the corresponding signature algorithm.

| Cryptographic element | Configuration | Role |
|---|---|---|
| Classic certificate signature | ECDSA P-256 | Root CA, server certificate, and classic `CertificateVerify` |
| Post-quantum certificate signature | ML-DSA-65 | Root CA, server certificate, and post-quantum `CertificateVerify` |
| TLS key exchange | X25519 | Ephemeral connection key agreement |
| TLS 1.3 cipher suite | `TLS_AES_256_GCM_SHA384` | Symmetric encryption and channel integrity |

X25519 is not a certificate-signature algorithm. It remains fixed so that the
experiments isolate authentication representation rather than changing key
exchange at the same time.

| Family | Scenario | Purpose |
|---|---|---|
| X.509 | `classic`, `pq` | Classic and post-quantum references |
| RPK | `pq-rpk` | Control for representing only the public key |
| Compact Merkle | `pq-compact-warm`, `pq-compact-cold` | Compact credential and Merkle proof with predistributed or in-handshake trust |
| MTC | `pq-mtc-experimental-landmark`, `pq-mtc-experimental-standalone` | Experimental Merkle Tree Certificate implementation |

MTC is always identified as **MTC-experimental** and targets
`draft-ietf-plants-merkle-tree-certs-05`. X.509, Compact, and MTC comparisons
are architectural; their trust and transparency models are not equivalent.

## Experimental status

| Phase | Status | Purpose |
|---|---|---|
| Initial TLS/X.509/PQ/Merkle laboratory | Implemented and validated | Functional OpenSSL `s_client` and `s_server` integration |
| Controlled N=16 comparison | Completed | Size, wall time, CPU, and trust costs |
| Merkle population scaling | Completed | Tree sizes 1, 4, 16, 64, 256, and 1024 |
| Controlled latency | Completed | Additional RTT from 0 to 200 ms |
| Bandwidth constrained | Infrastructure prepared | Independent manual campaign |
| Packet loss | Completed | Six loss levels at 50 ms RTT; latency, reliability, and TCP retransmission activity |
| Combined network conditions | Completed | Baseline, WAN, constrained, and adverse profiles; 3,600 validated measurements |

Generated data live under `artifacts/results/` and are excluded from Git by
default. Selected validated summaries, metadata, and figures may be committed
without raw logs, private keys, or large local sample directories.
Campaigns record the commit, Git state, image, environment, hashes, effective
configuration, and validation evidence.

### Completed packet-loss campaign

The packet-loss-only experiment completed 30 independent campaigns across
per-egress loss settings 0%, 0.1%, 0.5%, 1%, 2%, and 5%, with a fixed additional
50 ms RTT. It contains 5,400 measured TLS handshakes and 900 warmups over the six
post-quantum X.509, RPK, Compact, and MTC scenarios. All 5,400 measured attempts
completed successfully; the zero observed TLS-failure rate is specific to these
controlled runs and must not be generalized to other networks or timeout
policies.

The experiment records successful-handshake wall time and CPU, TLS BIO bytes,
configured and observed loss, qdisc evidence, campaign-level TCP counters,
paired round effects, and campaign-level bootstrap intervals. TCP
retransmissions cannot be assigned reliably to individual handshakes, and TLS
BIO bytes are not network-wire bytes.

- Execution and reproduction: [packet-loss campaign](campaigns/packet_loss_campaign/README.md)
- Validated experiment commit: `d6b98c7faf728e7627c6b7292a198548c38f9de4`
- Postprocessing idempotency fix: `795c553d1d877b6f6d55b1131255592183b7e6a4`
- Local result directory: `artifacts/results/network-loss-20260910-212643/`

### Completed combined-network campaign

The representative combined experiment completed 20 independent campaigns:
five repetitions of baseline, WAN, constrained, and adverse profiles. Each
campaign measured 30 randomized rounds across six PQ authentication scenarios,
for **3,600 measured TLS handshakes and 600 warmups**. Every measured handshake
completed successfully under the experiment's 30-second timeout.

The profiles jointly apply symmetric per-egress delay, bandwidth limiting, and
random loss. Additional RTT ranges from 10 to 100 ms, configured bandwidth from
unlimited to 1 Mbit/s, and per-egress loss from 0% to 2%. These variables
interact; isolated latency, bandwidth, and loss effects must not be added to
predict the combined profiles.

PQ X.509 used 9,572 TLS authentication bytes, Compact warm 6,281 bytes, and MTC
landmark 6,382 bytes in every profile. Median-of-campaign-median handshake wall
times for X.509 / Compact warm / MTC landmark were 12.58 / 13.53 / 12.45 ms at
baseline and 175.30 / 148.72 / 148.98 ms under the adverse 100 ms RTT, 1 Mbit/s,
2% per-egress-loss profile. These controlled Docker observations do not imply
universal performance or loss-resilience properties.

- Execution and reproduction: [combined-network campaign](campaigns/combined_network_campaign/README.md)
- Measurement-source commit: `4a5cf75ea674095f52c7ee759c8b43c0080a1096`
- Results commit: `6fa2a626f417db5fc7f31f26f2cff9096a6176fb`
- Published summaries and figures: [`artifacts/results/combined-network-20260911-001540/`](artifacts/results/combined-network-20260911-001540/)

## Repository layout

```text
.
├── campaigns/       campaign runners, analysis, validation, and instructions
├── docker/          Dockerfiles, Compose definitions, and OpenSSL configuration
├── artifacts/       local certificates, keys, fixtures, and results
├── compact/         Compact Merkle credential implementation
├── mtc/             MTC-experimental implementation
├── integration/     Merkle wire format and OpenSSL integration
├── profiling/       detailed timing instrumentation
├── codigoOriginal/  received C, Bash, and MTC prototype sources
├── tests/           TLS integration tests
├── scripts/         shared laboratory automation
└── docs/            protocol, methodology, validation, and result documents
```

See [campaigns](campaigns/README.md) for experiment entry points,
[Docker](docker/README.md) for images and services, and
[the initial laboratory guide](docs/tls-merkle-laboratory.md) for the first
implementation. `codigoOriginal/` remains separate to preserve provenance.

## Requirements

- Git and Python 3 on the host.
- Docker Desktop or Docker Engine with Compose v2.
- Internet access during the initial build.
- Enough storage for compiled image stages.
- Container `NET_ADMIN` capability for network campaigns.

```sh
git status --short
git rev-parse HEAD
python3 --version
docker version
docker compose version
docker info
```

## Initial setup

### Step 1 — clone the repository

```sh
git clone https://github.com/montenegro-montes/MTC-openssl.git
cd MTC-openssl
mkdir -p artifacts/results
```

Run every following command from the repository root. `artifacts/` contains
private keys and local evidence and must remain outside Git.

### Step 2 — build the base image

```sh
docker compose -f docker/compose.yaml build
docker image inspect mt-tls-lab:local --format '{{.Id}}'
```

This stage builds OpenSSL 3.5.8, liboqs 0.14.0, oqs-provider 0.10.0, received C
tests, and the initial Merkle integration for `s_client` and `s_server`.

### Step 3 — generate the original certificates and Merkle fixtures

```sh
docker compose -f docker/compose.yaml run --rm setup
find artifacts/certs artifacts/merkle -maxdepth 2 -type f -print
```

The generator uses `umask 077` and preserves existing directories. Use a new
artifact tree for scientific regeneration; never mix regenerated fixtures with
earlier results.

To create an additional signature profile:

```sh
docker compose -f docker/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh \
  --profile mldsa44 --algorithm ML-DSA-44

docker compose -f docker/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh \
  --profile ecdsa-p384 --algorithm EC \
  --pkeyopt ec_paramgen_curve:P-384 --digest sha384
```

`--pkeyopt` and `--sigopt` are repeatable. `--digest` and `--days` are
optional. Each profile contains a self-signed root CA, a CA-signed server
certificate, DER output, generation metadata, and a matching Merkle fixture.

```sh
docker compose -f docker/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh --help
```

Algorithm availability depends on the image and can be inspected with
`openssl list -signature-algorithms`. Generating a profile does not add it to
`scenario.sh` or to frozen campaigns; use a new campaign for new algorithms.

### Step 4 — validate the original scenarios

```sh
for SCENARIO in classic pq classic-mt pq-mt; do
  export SCENARIO
  docker compose -f docker/compose.yaml up -d --force-recreate server
  sleep 2
  docker compose -f docker/compose.yaml run --rm client
  docker compose -f docker/compose.yaml down
done
unset SCENARIO
```

Each client must complete TLS 1.3 and verify the server. The `*-mt` scenarios
must also report successful Merkle verification.

### Step 5 — build Compact, profiling, and MTC

```sh
docker compose -f docker/compose.compact.yaml build
docker compose -f docker/compose.compact.yaml run --rm setup
docker compose -f docker/compose.profile.yaml build
docker compose -f docker/compose.mtc.yaml build
docker compose -f docker/compose.mtc.yaml run --rm setup
test -f artifacts/compact/batch16/classic/manifest.json
test -f artifacts/compact/batch16/pq/manifest.json
test -d artifacts/mtc/batch16-v2
```

### Step 6 — build and validate the controlled measurement image

```sh
docker build -f docker/Dockerfile.paper \
  --build-arg BASE_IMAGE=mt-tls-mtc:local \
  -t mt-tls-paper:local .

docker run --rm --network none \
  -v "$PWD/artifacts:/work:ro" \
  mt-tls-paper:local sh /opt/paper/tests.sh
```

Do not continue unless the output ends with:

```text
ALL REGRESSION AND NEGATIVE TESTS PASS
```

### Step 7 — build the network image

```sh
docker build -f docker/Dockerfile.network -t mt-tls-network:latency .
docker run --rm --network none mt-tls-network:latency sh -c \
  'command -v tc && command -v ping && command -v nstat && command -v iperf3'
```

The network image adds network tools and does not rebuild OpenSSL.

### Step 8 — choose a campaign

Follow [the campaign index](campaigns/README.md) and the package-specific README.
Always use a new timestamped result directory and run the package tests and
preflight before its full campaign.

## Image chain

```text
mt-tls-lab:local
  └── mt-tls-compact:local
      └── mt-tls-profile:local
          └── mt-tls-mtc:local
              └── mt-tls-paper:local
                  └── mt-tls-network:latency
```

Never combine results produced by different commits or images without recording
that distinction. Smoke data remain separate from primary inference.

## Measurement interpretation

Campaigns distinguish TLS BIO bytes, serialized credential/trust sizes,
handshake and process wall time, client/server/setup CPU, campaign medians,
paired-round effects, failures, timeouts, and campaign-level TCP counters.

TLS BIO bytes are not Ethernet/IP/TCP bytes. Retransmissions are attributed only
at campaign level when per-connection attribution is unavailable. Final
bootstrap inference uses independent campaigns and retains outliers.

## Documentation

- [Certificate and credential format comparison](docs/certificate-formats-comparison.md)
- [Initial TLS-Merkle laboratory](docs/tls-merkle-laboratory.md)
- [TLS-MT protocol](docs/tls-mt.md)
- [Compact Merkle protocol](docs/compact-protocol.md)
- [MTC methodology](docs/mtc-methodology.md)
- [MTC results](docs/mtc-results.md)
- [MTC comparison](docs/mtc-comparison.md)
- [Validation](docs/validation.md)

This repository is a research laboratory. Never publish or commit private keys
or local cryptographic artifacts.
