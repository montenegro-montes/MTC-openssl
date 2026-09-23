# Experimental MTC/TLS laboratory

This repository evaluates the experimental **Merkle Tree Certificates (MTC)**
draft alongside conventional **X.509** in TLS 1.3. The active study covers
protocol correctness, handshake performance, certificate scaling, crossover
points and controlled network conditions. It includes server-only and mutual
authentication, MTC landmark and standalone credentials, and Trust Anchor Retry.

The active branch contains only the current X.509 and experimental MTC
implementation. The former historical campaign tree and the earlier Compact
prototype are not runtime dependencies and are not part of the current battery.

## Current experiment surface

The same nine cryptographic profiles are used where a campaign supports the full
matrix:

- ECDSA P-256, P-384 and P-521
- Ed25519 and Ed448
- ML-DSA-44, ML-DSA-65 and ML-DSA-87
- SLH-DSA-SHA2-128s

The main authentication representations are:

| Authentication | Cases |
|---|---|
| Server-only | X.509, MTC landmark, MTC standalone |
| Mutual | X.509/X.509, MTC landmark/MTC landmark, MTC standalone/MTC standalone |
| Trust Anchor Retry | MTC server authentication with one retry on a fresh TCP/TLS connection |

Handshake-performance configurations select key establishment independently
from authentication: `X25519`, `X25519+ML-KEM512`, or `ML-KEM-512`.
The selection is included in artifact/report directory names and report metadata.

MTC fixture and crossover work uses explicit tree sizes. The primary fixture set
is **N=16**; advanced crossover analysis covers **N=1, 4, 16, 64 and 256**.
Certificate-chain TLS scaling covers depths **D=2–5**.

## Main commands

Run every command from the repository root. Invoking a launcher without a
subcommand opens its interactive menu when available.

| Command | Responsibility |
|---|---|
| `bin/base/mt-prepare` | Prepare the base, MTC and capture images; initialize launcher paths; generate and functionally validate the shared N=16 fixtures |
| `bin/base/mt-protocol-validation` | Validate draft vectors, MTC objects, captured TLS transcripts, negative cases, mutual authentication and Trust Anchor Retry |
| `bin/performance/mt-handshake-performance` | Measure native and PCAP timing and transmitted sizes for server-only, mutual and retry cases |
| `bin/cryptographic_scaling/mt-cert-scaling` | Generate/validate fixtures and run N=16, advanced, boundary and mutual-authentication crossover studies plus D=2–5 TLS scaling |
| `bin/network/mt-network` | Run latency, bandwidth, loss and combined-network studies in `single` or `mutual` mode |
| `bin/containers/mt-install` | Build or inspect the three shared base images without running campaigns |
| `bin/containers/mt-containers` | Manage the current network Compose targets and network image chain |
| `bin/artifacts/mt-report` | Inspect generated result/report directories |

Each launcher supports `help`, or prints its accepted commands when called with
an invalid command. Detailed launcher documentation is available in
[`bin/base/README.md`](bin/base/README.md),
[`bin/performance/README.md`](bin/performance/README.md),
[`bin/cryptographic_scaling/README.md`](bin/cryptographic_scaling/README.md) and
[`bin/network/README.md`](bin/network/README.md).

## Recommended workflow

### 1. Prepare shared prerequisites

```sh
bin/base/mt-prepare status
bin/base/mt-prepare run ALL
```

`run ALL` prepares or reuses this image chain:

```text
mt-tls-lab:local
    └── mt-tls-mtc:local
        ├── mt-tls-capture:local
        └── mt-tls-network-measurement:local
            └── mt-tls-network:local
```

The first three images are managed directly by `mt-prepare`. The network images
are prepared when network or Native/PCAP validation needs them. `run ALL` also
initializes missing scaling/protocol paths and ensures that the N=16 fixtures
have functional TLS validation evidence. Existing images and output directories
are reused only through their corresponding gates; their presence alone does not
prove a successful experiment.

### 2. Validate the protocol

```sh
bin/base/mt-protocol-validation
```

The protocol launcher can run one stage, all pending stages for one selected
profile/leaf, or the full **9 profiles × 16 leaves** matrix. Its staged pipeline
covers:

- pinned draft core vectors;
- offline landmark and standalone object validation;
- TLS packet capture and extraction;
- independent transcript, CertificateVerify and Finished verification;
- invalid-input stress cases;
- mutual-authentication functional cases;
- Trust Anchor Retry preflight.

The selected profile and leaf are recorded in the report. Long matrix runs show
progress, elapsed time and an estimated remaining time.

### 3. Measure handshake performance

```sh
bin/performance/mt-handshake-performance
```

Native and PCAP populations can be run independently or together, and can be
split into server-only and mutual-authentication phases. Measurements include:

- native TCP connection time;
- native TLS handshake time;
- native complete connection-establishment time;
- process wall time;
- OpenSSL handshake bytes;
- PCAP TCP, TLS and complete connection timing;
- captured frame, IP and TCP payload bytes;
- sample count, mean, sample standard deviation, median and 95% confidence
  interval where repeated measurements make those statistics meaningful.

Trust Anchor Retry is measured separately across all nine profiles and receives
its own English HTML report. Retry uses a fresh socket and TLS state for the
second attempt.

### 4. Run scaling and crossover studies

```sh
bin/cryptographic_scaling/mt-cert-scaling
```

The default N=16 workflow prepares X.509 and MTC fixtures, validates them,
computes the initial crossover, renders plots/HTML and performs its audit.
Optional stages add:

- advanced crossover at N=1, 4, 16, 64 and 256;
- boundary audits near small byte differences;
- mutual-authentication crossover for all nine profiles;
- D=2–5 TLS chain-depth validation, analysis, plots and HTML.

Use `status`, `list`, `show STAGE` and `run STAGE` to inspect or resume a pending
stage without restarting completed work.

### 5. Evaluate network conditions

```sh
bin/network/mt-network status
bin/network/mt-network prepare latency single
bin/network/mt-network run latency single
```

Available campaign families are `latency`, `bandwidth`, `loss` and `combined`.
Every family supports `single` and `mutual` modes across the nine profiles and
keeps X.509, MTC landmark and MTC standalone results separate. Mutual mode uses
the fixtures generated by the mutual-authentication crossover stage.

## Repository layout

| Path | Purpose |
|---|---|
| `bin/base/` | Preparation and protocol-validation launchers |
| `bin/performance/` | Handshake-performance launcher |
| `bin/cryptographic_scaling/` | Scaling and crossover launcher |
| `bin/network/` | Network campaign launcher |
| `bin/containers/` | Image and Compose management |
| `bin/renders/` | Central English HTML report renderers |
| `campaigns/validation/` | Protocol validation and Native/PCAP instrumentation validation |
| `campaigns/performance/` | Mutual-authentication performance implementation |
| `campaigns/scaling/` | Profile, chain-depth, crossover and mutual-crossover studies |
| `campaigns/network/` | Latency, bandwidth, loss and combined implementations |
| `campaigns/common/` | Shared PCAP, image-chain and reporting helpers |
| `campaigns/future_implementation/` | Work intentionally excluded from the current experiment |
| `docker/base/` | Base, MTC and capture image definitions |
| `docker/network/` | Network measurement images and Compose definitions |
| `docker/validation/` | Scaling-validation Compose definitions |
| `src/mtc/` | Experimental MTC implementation, retry peer and draft checks |
| `src/profiling/` | Native TCP/TLS timing instrumentation used by the MTC image |
| `docs/` | Protocol, validation, authentication and publication notes |

## State, evidence and reports

| Location | Contents |
|---|---|
| `.mt-state/` | Launcher configuration, stage markers and execution logs |
| `artifacts/results/` | Raw and derived campaign results |
| `artifacts/reports/` | Human-readable English HTML reports |
| `artifacts/protocol-validation/` | Protocol captures and validation reports |
| `artifacts/protocol-review/` | Independent transcript-review evidence |
| `artifacts/mtc/` | Generated MTC fixture populations |
| `results/` | Tracked publication snapshots preserved independently from local runs |

New scientific executions use fresh timestamped output directories. A
`completed` stage marker or an existing JSON file is not, by itself, proof that
the scientific validation passed; consult the corresponding status gates and
final report.

## Resetting the local laboratory

```sh
bin/base/mt-prepare reset-all
```

This guarded action requires typing `RESET ALL`. It removes `artifacts/`,
`.mt-state/`, laboratory Docker resources and local `mt-tls-*` image tags without
creating a backup. It preserves tracked source files and `results/`.

## Scope boundary

`campaigns/future_implementation/browser_mtc/` is retained as future work and is
not included in the active batteries. Experiment execution remains explicit:
status, planning and initialization commands do not silently run full campaigns.
