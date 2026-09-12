# Docker images and Compose definitions

Run every command from the repository root and always pass the Compose file
explicitly. Compose resolves the build context and bind mounts relative to the
Compose file, while the documented commands assume the repository root.

The project-level helper wraps the explicit Compose files while preserving the
same target separation:

```sh
bin/original_campaigns/mt-containers list
bin/original_campaigns/mt-containers doctor
bin/original_campaigns/mt-containers ps all
bin/original_campaigns/mt-containers menu
```

It can build, start, stop, inspect, enter and clean individual project targets.
It never deletes campaign artifacts; result cleanup remains guarded by
`bin/original_campaigns/mt-archive --clean-artifacts`.

`down` and `clean` locate containers and networks through Docker Compose project
labels. They therefore work after an interrupted campaign even when required
measurement variables such as `MEASUREMENT_RUN_ROOT`, `SCALING_FIXTURES`, or
`CAPTURE_ROOT` are no longer exported in the current shell.

## Prerequisites

```sh
docker version
docker compose version
docker info
mkdir -p artifacts/results
```

The first build needs Internet access. Generated certificates and keys are
written below `artifacts/`, which must remain outside Git.

Compose definitions for studies that vary algorithms, security levels, key or
certificate sizes, chain depth, or proof length are grouped separately under
[`docker/cryptographic_scaling/`](cryptographic_scaling/README.md). The
established baseline and network definitions are grouped under
[`docker/original_campaigns/`](original_campaigns/README.md).

## Image dependency chain

```text
docker/original_campaigns/Dockerfile          -> mt-tls-lab:local
docker/original_campaigns/Dockerfile.compact  -> mt-tls-compact:local
docker/original_campaigns/Dockerfile.profile  -> mt-tls-profile:local
docker/original_campaigns/Dockerfile.mtc      -> mt-tls-mtc:local
docker/original_campaigns/Dockerfile.measurement    -> mt-tls-measurement:local
docker/original_campaigns/Dockerfile.network  -> mt-tls-network:latency
```

Build in this order because every stage uses the preceding local tag as its
`FROM` image.

## Step 1 — build the base OpenSSL/PQ/Merkle image

```sh
docker compose -f docker/original_campaigns/compose.yaml build
docker compose -f docker/original_campaigns/compose.yaml run --rm setup
```

The setup service creates classic and ML-DSA-65 certificates plus the initial
Merkle fixtures in `artifacts/certs/` and `artifacts/merkle/`.

## Step 2 — test an initial TLS scenario

```sh
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml up -d --force-recreate server
sleep 2
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml run --rm client
docker compose -f docker/original_campaigns/compose.yaml down
```

Supported values are `classic`, `pq`, `classic-mt` and `pq-mt`. Always
stop the `mt` project after the check.

## Step 3 — build Compact and generate its N=16 fixtures

```sh
docker compose -f docker/original_campaigns/compose.compact.yaml build
test -f artifacts/compact/batch16/classic/manifest.json \
  -a -f artifacts/compact/batch16/pq/manifest.json \
  || docker compose -f docker/original_campaigns/compose.compact.yaml run --rm setup
```

The setup command is skipped when both immutable fixture manifests already
exist. `prepare.py` intentionally refuses to overwrite that directory.

## Step 4 — build profiling and MTC

```sh
docker compose -f docker/original_campaigns/compose.profile.yaml build
docker compose -f docker/original_campaigns/compose.mtc.yaml build
test -f artifacts/mtc/batch16-v2/classic/manifest.json \
  -a -f artifacts/mtc/batch16-v2/pq/manifest.json \
  || docker compose -f docker/original_campaigns/compose.mtc.yaml run --rm setup
```

The MTC setup creates `artifacts/mtc/batch16-v2/`. If both manifests are
already present, reuse that immutable fixture set. If only part of the output
exists, inspect it and choose a new directory instead of combining generations.

## Step 5 — build and test the study image

```sh
docker build -f docker/original_campaigns/Dockerfile.measurement \
  --build-arg BASE_IMAGE=mt-tls-mtc:local \
  -t mt-tls-measurement:local .

docker run --rm --network none \
  -v "$PWD/artifacts:/work:ro" \
  mt-tls-measurement:local sh /opt/measurement/tests.sh
```

Do not use the image for measurements unless the output contains
`ALL REGRESSION AND NEGATIVE TESTS PASS`.

## Step 6 — build and inspect the network image

```sh
docker build -f docker/original_campaigns/Dockerfile.network -t mt-tls-network:latency .
docker run --rm --network none mt-tls-network:latency sh -c \
  'command -v tc && command -v ping && command -v nstat && command -v iperf3'
```

The network stage only installs `iproute2`, `iputils-ping` and `iperf3`.
It retains the OpenSSL binary from `mt-tls-measurement:local`.

## Compose inventory

The image dependency graph can be checked and repaired automatically:

```sh
python3 -m campaigns.common.image_chain network
```

It rebuilds a missing image or a child whose parent changed. Network campaign
regression gates run the same resolver before testing and record all image IDs.

| Compose file | Project | Purpose |
|---|---|---|
| `original_campaigns/compose.yaml` | `mt` | Initial classic/PQ and Merkle TLS laboratory |
| `original_campaigns/compose.compact.yaml` | `mtcompact` | Compact Merkle fixtures and benchmark |
| `original_campaigns/compose.profile.yaml` | `mtprofile` | Detailed timing instrumentation |
| `original_campaigns/compose.mtc.yaml` | `mtclab` | Experimental MTC implementation |
| `original_campaigns/compose.measurement.yaml` | `controlledn16` | Controlled N=16 measurements |
| `original_campaigns/compose.scaling.yaml` | `mtscaling` | Tree-population scaling |
| `original_campaigns/compose.network-latency.yaml` | `mtlatency` | Latency-only campaign |
| `original_campaigns/compose.network-bandwidth.yaml` | `mtbandwidth` | Bandwidth-limited campaign |
| `original_campaigns/compose.network-loss.yaml` | `mtloss` | Packet-loss campaign |
| `original_campaigns/compose.network-combined.yaml` | `mtcombined` | Combined network profiles |
| `cryptographic_scaling/compose.cert-chain-scaling.yaml` | `certchainscaling` | Ideal-network algorithm and certificate-chain scaling |

The campaign Compose definitions are execution infrastructure. Launch them
through their package runners under `campaigns/original_campaigns/` or
`campaigns/cryptographic_scaling/`, because those runners record
metadata, validate qdiscs and protect against overwrites.

## Inspection and cleanup

```sh
docker compose -f docker/original_campaigns/compose.yaml ps
docker compose -f docker/original_campaigns/compose.yaml logs server
docker compose -f docker/original_campaigns/compose.yaml down
docker image ls 'mt-tls-*'
```

Packet-loss and combined-network packages provide a campaign-specific
`cleanup.sh` for interruptions. Those scripts stop only their own Compose
project and preserve results. For latency and bandwidth, use the exact Compose
file shown in their runner/README with `down`. Do not use
`docker system prune` as part of the reproducibility workflow.

The obsolete `archive/` directory has been removed. Maintained definitions are
grouped under `original_campaigns/` and `cryptographic_scaling/`.
