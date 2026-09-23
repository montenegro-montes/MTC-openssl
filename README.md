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
| PCMA Stage A | Completed | Proof/cache simulation over actual Compact fixtures |
| PCMA Stage A.2 | Completed and audited | Compact cache-state encodings; 720,000 observations and GO decision |
| PCMA Stage B.1 | Completed and audited | End-to-end TLS validation; 12,600 handshakes across 90 campaigns |
| Controlled latency | Completed | Additional RTT from 0 to 200 ms |
| Bandwidth constrained | Completed | 75 controlled campaigns across 3 RTT and 5 bandwidth levels |
| Packet loss | Completed | Six loss levels at 50 ms RTT; latency, reliability, and TCP retransmission activity |
| Combined network conditions | Completed | Baseline, WAN, constrained, and adverse profiles; 3,600 validated measurements |
| Certificate-chain and MTC proof scaling | Prepared; not executed | Separate ideal-network infrastructure for ECDSA, ML-DSA, SLH-DSA, PKI depth, MTC size, and crossover analysis |

The [certificate-chain and MTC proof-scaling experiment](campaigns/scaling/cert_chain_scaling/README.md)
is isolated from the validated baselines. It prepares immutable multi-depth
X.509 fixtures, exact DER/TLS size accounting, MTC crossover models, and
filtered manual TLS measurements. No result or conclusion is claimed before
the manual campaigns are completed.

Generated data live temporarily under `artifacts/results/` and are excluded
from Git. After a complete battery, selected validated summaries and metadata
are archived in a checksummed [publication snapshot](results/campaign-snapshot-20260911T193547Z-662ce7edb956/); raw logs, private keys and large local sample directories are omitted.
Campaigns record the commit, Git state, image, environment, hashes, effective
configuration, and validation evidence.

### Completed bandwidth-constrained campaign

The bandwidth experiment completed 75 independent campaigns: five repetitions
at every combination of 10, 50, and 100 ms RTT with symmetric per-egress rates
of 100, 20, 10, 5, and 1 Mbit/s. It contains **13,500 measured handshakes and
2,250 warmups** across the six post-quantum authentication scenarios. Every
accepted campaign passed the RTT, bidirectional goodput, retransmission, and
qdisc-drop gates.

Compact warm became faster than PQ X.509 at the observed 5 and 1 Mbit/s points
for every RTT; the neighboring observed sign change lies between 5 and
10 Mbit/s. At 1 Mbit/s its paired median advantage over PQ X.509 was 27.887 ms
at 10 ms RTT, 28.620 ms at 50 ms RTT, and 27.349 ms at 100 ms RTT. These are
observed points rather than an interpolated break-even threshold.

- Execution and reproduction: [bandwidth campaign](campaigns/historical_campaigns/network_bandwidth/README.md)
- Measurement-source commit: `796282369f003e86621f61bd20466583fd64e75d`
- Archived results: [network-bandwidth](results/campaign-snapshot-20260911T193547Z-662ce7edb956/campaigns/network-bandwidth/)

### Completed PCMA campaigns

PCMA Stage A.2 evaluated five exact cache-state advertisement encodings in 720
configurations and **720,000 deterministic observations**. Its structural and
paired audit passes, and all five predeclared decision criteria pass, producing
a `GO` decision for TLS integration. The result includes the advertisement in
net authentication bytes; it does not count proof reduction alone as a saving.

PCMA Stage B.1 then completed **12,600 end-to-end TLS handshakes in 90
campaigns**. Its audit and analytical-model comparison both pass; 6,300 PCMA
measurements agree with the Stage A.2 byte model. All 18 tested
size/workload/budget cells transferred fewer bytes than Compact warm. Five
cells also had a bootstrap latency interval entirely below zero; the other 13
intervals included zero and therefore do not establish timing equivalence.

The A.2 manifest records base commit `7962823`, and the B.1 manifest records
base commit `ff88aa4`. Their campaign implementations were still untracked at
execution time. The manifests retain per-source hashes, so the outputs remain
auditable, but those base hashes must not be described as commits containing
the PCMA implementations.

- Stage A and A.2: [PCMA simulation](campaigns/historical_campaigns/pcma/README.md) and [compact advertisement evaluation](campaigns/historical_campaigns/pcma_stage_a2/README.md)
- Stage B.1: [end-to-end PCMA TLS campaign](campaigns/historical_campaigns/pcma_stage_b/README.md)
- Audited A.2 results: [PCMA Stage A.2](results/campaign-snapshot-20260911T193547Z-662ce7edb956/campaigns/pcma-stage-a2/)
- Audited B.1 results: [PCMA Stage B.1](results/campaign-snapshot-20260911T193547Z-662ce7edb956/campaigns/pcma-stage-b1/)

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

- Execution and reproduction: [packet-loss campaign](campaigns/historical_campaigns/packet_loss_campaign/README.md)
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

- Execution and reproduction: [combined-network campaign](campaigns/historical_campaigns/combined_network_campaign/README.md)
- Measurement-source commit: `4a5cf75ea674095f52c7ee759c8b43c0080a1096`
- Results commit: `6fa2a626f417db5fc7f31f26f2cff9096a6176fb`
- Published summaries: [combined network](results/campaign-snapshot-20260911T193547Z-662ce7edb956/campaigns/combined-network/)

## Project management commands

Two shell entry points centralize routine operation from the repository root:

```sh
# Docker images, Compose projects, services, logs and cleanup
bin/containers/mt-containers doctor
bin/containers/mt-containers menu

# Persistent, step-by-step experiment battery
bin/historical_campaigns/mt-campaigns init
bin/historical_campaigns/mt-campaigns status
bin/historical_campaigns/mt-campaigns next
```

The campaign manager records every step as `pending`, `running`, `completed`,
`failed`, or `skipped` under the ignored `.mt-state/` directory. It also saves
all timestamped output paths, so closing the terminal or continuing another day
does not lose the current position. Use `show STEP` before a long operation and
`run STEP` to execute only that operation. See [campaign management](campaigns/README.md)
and [Docker management](docker/README.md) for the full command reference.

## Repository layout

```text
.
├── campaigns/
│   ├── base/                   reusable MTC/X.509 campaign components
│   ├── historical_campaigns/     historical Compact, network, scaling, and PCMA studies
│   ├── cryptographic_scaling/  algorithm, key, chain, and proof-size studies
│   └── common/                 shared campaign helpers
├── docker/
│   ├── base/                   active base, MTC, and capture images
│   ├── historical_campaigns/     historical Compact, measurement, network and scaling definitions
│   ├── cryptographic_scaling/  Compose definitions for the second study group
│   └── README.md               Docker category and operation index
├── artifacts/       local certificates, keys, fixtures, and results
├── bin/
│   └── historical_campaigns/  management and publication commands
├── src/             implementation grouped by component
│   ├── integration/ Merkle wire format and OpenSSL integration
│   ├── compact/     Compact Merkle credentials
│   ├── mtc/         MTC-experimental
│   └── profiling/   timing instrumentation
├── codigoOriginal/  received C, Bash, and MTC prototype sources
├── tests/           TLS integration tests
├── scripts/         shared laboratory automation
└── docs/            protocol, methodology, validation, and result documents
```

Start with the [architecture and review guide](docs/architecture.md) for code responsibilities, dependencies, and migrated commands.

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
docker compose -f docker/historical_campaigns/compose.yaml build
docker image inspect mt-tls-lab:local --format '{{.Id}}'
```

This stage builds OpenSSL 3.5.8, liboqs 0.14.0, oqs-provider 0.10.0, received C
tests, and the initial Merkle integration for `s_client` and `s_server`.

### Step 3 — generate the original certificates and Merkle fixtures

```sh
docker compose -f docker/historical_campaigns/compose.yaml run --rm setup
find artifacts/certs artifacts/merkle -maxdepth 2 -type f -print
```

The generator uses `umask 077` and preserves existing directories. Use a new
artifact tree for scientific regeneration; never mix regenerated fixtures with
earlier results.

To create an additional signature profile:

```sh
docker compose -f docker/historical_campaigns/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh \
  --profile mldsa44 --algorithm ML-DSA-44

docker compose -f docker/historical_campaigns/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh \
  --profile ecdsa-p384 --algorithm EC \
  --pkeyopt ec_paramgen_curve:P-384 --digest sha384
```

`--pkeyopt` and `--sigopt` are repeatable. `--digest` and `--days` are
optional. Each profile contains a self-signed root CA, a CA-signed server
certificate, DER output, generation metadata, and a matching Merkle fixture.

```sh
docker compose -f docker/historical_campaigns/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh --help
```

Algorithm availability depends on the image and can be inspected with
`openssl list -signature-algorithms`. Generating a profile does not add it to
`scenario.sh` or to frozen campaigns; use a new campaign for new algorithms.

### Step 4 — validate the original scenarios

```sh
for SCENARIO in classic pq classic-mt pq-mt; do
  export SCENARIO
  docker compose -f docker/historical_campaigns/compose.yaml up -d --force-recreate server
  sleep 2
  docker compose -f docker/historical_campaigns/compose.yaml run --rm client
  docker compose -f docker/historical_campaigns/compose.yaml down
done
unset SCENARIO
```

Each client must complete TLS 1.3 and verify the server. The `*-mt` scenarios
must also report successful Merkle verification.

### Step 5 — build Compact, profiling, and MTC

```sh
docker compose -f docker/historical_campaigns/compose.compact.yaml build
test -f artifacts/compact/batch16/classic/manifest.json \
  -a -f artifacts/compact/batch16/pq/manifest.json \
  || docker compose -f docker/historical_campaigns/compose.compact.yaml run --rm setup
docker compose -f docker/historical_campaigns/compose.profile.yaml build
docker compose -f docker/historical_campaigns/compose.mtc.yaml build
test -f artifacts/mtc/batch16-v2/classic/manifest.json \
  -a -f artifacts/mtc/batch16-v2/pq/manifest.json \
  || docker compose -f docker/historical_campaigns/compose.mtc.yaml run --rm setup
test -f artifacts/compact/batch16/classic/manifest.json
test -f artifacts/compact/batch16/pq/manifest.json
test -f artifacts/mtc/batch16-v2/classic/manifest.json
test -f artifacts/mtc/batch16-v2/pq/manifest.json
```

Both setup programs create immutable fixture directories and refuse to overwrite
an existing output. The conditional commands reuse a complete N=16 fixture set.
If a directory exists without both manifests, inspect or move it aside and use a
new output name; do not merge a partial set with newly generated files.

### Step 6 — build and validate the controlled measurement image

```sh
docker build -f docker/historical_campaigns/Dockerfile.measurement \
  --build-arg BASE_IMAGE=mt-tls-mtc:local \
  -t mt-tls-measurement:local .

docker run --rm --network none \
  -v "$PWD/artifacts:/work:ro" \
  mt-tls-measurement:local sh /opt/measurement/tests.sh
```

Do not continue unless the output ends with:

```text
ALL REGRESSION AND NEGATIVE TESTS PASS
```

For new campaigns, the complete local image chain can be checked and restored
recursively without regenerating certificate fixtures:

```sh
python3 -m campaigns.common.image_chain network
```

Campaign regression gates perform this resolution automatically and record the
resulting immutable IDs and any rebuilds before allowing measurements.

### Step 7 — build the network image

```sh
docker build -f docker/historical_campaigns/Dockerfile.network -t mt-tls-network:latency .
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
              └── mt-tls-measurement:local
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
- [PCMA Stage-A laboratory](campaigns/historical_campaigns/pcma/README.md)
- [Experiment artifact publication policy](docs/artifact-publication-policy.md)
- [MTC methodology](docs/mtc-methodology.md)
- [MTC results](docs/mtc-results.md)
- [MTC comparison](docs/mtc-comparison.md)
- [Validation](docs/validation.md)

This repository is a research laboratory. Never publish or commit private keys
or local cryptographic artifacts.
