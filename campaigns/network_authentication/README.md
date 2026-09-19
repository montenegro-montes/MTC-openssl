# Network authentication v1

New, isolated comparison of X.509 and MTC landmark with server-only and mutual
TLS authentication. Compact remains in `campaigns/original_campaigns` as historical
evidence. This package neither imports historical measurements nor changes those
campaigns, their scenarios, fixtures, or analysis.

**Preparation status: implementation and offline checks only. No image build,
fixture issuance, Docker/network operation, or TLS experiment has been performed
for this package. Manual preflight is a mandatory empirical gate, including PQ
support and missing-client-certificate rejection.**

## Question and fixed design

How does the effect of credential representation on handshake latency and bytes
change when both peers authenticate, under different path conditions?

`protocol.json` is the versioned protocol. Defaults are frozen before new
measurements; changing them requires a new version and a new result directory.
The same image, server key, server credential, and trust configuration are used
when switching from server-only to mutual authentication within a credential
family/profile/N. Mutual authentication adds the client credential. X.509 uses
CA-issued leaves, with roots trusted locally and not transmitted. MTC is prepared
from those same leaf populations, with dedicated MTC signer keys and leaf index
zero; server and client populations and signing keys remain separate. MTC trust
files are distributed before the handshake. Both peers use the same profile and,
for mutual MTC, the same N. X.509 is measured once per profile/authentication mode,
not duplicated for each MTC N.

| Profile | X.509 | MTC landmark populations | Modes | Cases |
|---|---|---|---|---:|
| ECDSA P-256 | CA/leaf | N=8,16 | server-only, mutual | 6 |
| ML-DSA-65 | CA/leaf | N=16 | server-only, mutual | 4 |

The P-256 populations bracket a region of interest in the historical CA-baseline
results. Newly issued fixtures can shift byte boundaries: this experiment does
not assume that the historical crossover will reproduce exactly. ML-DSA-65 is a
representative PQ extension, not a claim about every PQ algorithm. Standalone,
Compact, RPK, mixed-family authentication, and larger chain matrices are excluded
from v1. No automatic fallback to another algorithm or auth mode is allowed.

| Condition | Added RTT (ms) | Rate per egress (Mbit/s) | Loss per egress (%) |
|---|---:|---:|---:|
| local | 0 | unlimited | 0 |
| rtt50 | 50 | unlimited | 0 |
| rtt100 | 100 | unlimited | 0 |
| bw5 | 50 | 5 | 0 |
| bw1 | 50 | 1 | 0 |
| loss1 | 50 | unlimited | 1 |
| loss5 | 50 | unlimited | 5 |
| combined | 100 | 5 | 1 |

Each full condition has five campaign repetitions, five warmup rounds and 30
measured rounds. A round includes all ten cases, randomly ordered. Campaign
blocks are also randomly ordered with a frozen seed. Total: **40 blocks, 12,000
measured attempts and 2,000 warmups**. Netem random loss is not replayed with the
ordering seed; that seed controls the schedule and bootstrap only.

TLS controls: TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, no tickets, no session
resumption, no 0-RTT. All connections are new processes with native instrumentation;
container startup and Docker exec time are not the handshake metric. Both roles
use the same image and a fixed 2-CPU/1-GiB container limit. Shared-host scheduling
and Docker virtualization remain limitations.

## Manual workflow

Run from the repository root. The commands below are instructions for the
operator, not commands executed during package preparation.

1. Inspect the design and run the offline tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli plan
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest campaigns.network_authentication.test_offline -v
```

2. Build the dedicated network image manually from the existing mutual-metrics
image. Pin the parent image ID rather than allowing its tag to change silently:

```sh
BASE_IMAGE_ID=$(docker image inspect mt-tls-mtc-mutual:local --format '{{.Id}}')
docker build --build-arg BASE_IMAGE="$BASE_IMAGE_ID" \
  -t mt-tls-network-authentication:v1 docker/network_authentication
NETWORK_AUTH_IMAGE=$(docker image inspect mt-tls-network-authentication:v1 --format '{{.Id}}')
```

This requires the existing directional-instrumentation image prepared by
`campaigns/validation/mutual_auth_crossover/Dockerfile.mutual_metrics`. The new
image adds tc, ping, iperf3 and procps. It does not rebuild or repatch OpenSSL.
Missing instrumentation, provider support, or kernel netem support blocks the
manual preflight; do not substitute a historical image or fabricate a PASS.

3. Create new isolated fixtures, outside all historical fixture roots:

```sh
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FIXTURES="artifacts/network-authentication/fixtures-$STAMP"
ROOT="artifacts/results/network-authentication-v1-$STAMP"
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.fixtures \
  --image "$NETWORK_AUTH_IMAGE" --output "$FIXTURES"
# The preceding command only prints a plan. Issue credentials explicitly:
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.fixtures \
  --image "$NETWORK_AUTH_IMAGE" --output "$FIXTURES" --execute
```

Fixture issuance runs in a container with `--network none`, starts no TLS, and
creates CA/leaf and MTC material for both roles. Reusing or overwriting an output
is forbidden, including after a partial failure. Generated private keys stay
under ignored `artifacts/`; never publish or copy them into the source snapshot.
The generator records the source hashes, Git state and actual immutable image ID.

4. Freeze the experiment offline, before the first TLS handshake:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli freeze \
  --fixtures "$FIXTURES" --image "$NETWORK_AUTH_IMAGE" --output "$ROOT"
```

Freeze records protocol, case matrix, source snapshot, Git identity/status,
fixture inventory (hashes, not copies of keys), and image ID. The fixture-generation
source inventory must still match. Each stage verifies these inventories before
and after execution. Existing output directories and stage outputs are never
reused or overwritten. If a stage fails, preserve it, resolve the cause, and use
a fresh preparation/freeze as necessary. There is no automatic retry, resume,
retuning of thresholds, or deletion of other Docker projects.

5. Run one stage at a time, inspecting each result before continuing:

```sh
# Omit --execute to inspect the planned stage without invoking Docker.
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli preflight "$ROOT" --execute
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli smoke "$ROOT" --execute
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli full "$ROOT" --execute
```

Preflight: 10 positive local handshakes plus five missing-client-certificate
negative controls (one per mutual case). Smoke: 80 positive attempts, one round
per condition. Both must pass before full measurement. A negative control passes
only on an explicit server certificate-required rejection, not a timeout.

Only new uniquely named `mtnetauth-*` containers/networks are created, and cleanup
addresses only resources created by that invocation. No Docker build occurs in
the runner. Container networks are internal and do not publish host ports.

6. Audit and analyze offline, writing derived output outside the sealed root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli audit "$ROOT"
PYTHONDONTWRITEBYTECODE=1 python3 -m campaigns.network_authentication.cli analyze "$ROOT" \
  --output "artifacts/reports/network-authentication-v1-$STAMP"
```

The audit rechecks scheduled order/counts, endpoint/raw metrics, client_random
uniqueness across stages, missing-client controls and integrity inventories.
A gate verifies that its evidence belongs to the same frozen manifest. Analysis
requires a successful complete offline audit, not merely a completion marker.

## Measurement and acceptance

The primary performance outcome is native client handshake wall time, paired
within the same campaign round. Native connection-establishment time is separate.
Record client/server CPU and handshake times separately; certificate and
CertificateVerify bytes separately by direction; aggregate TLS handshake/BIO
bytes separately; and attempts, failures and timeouts with their denominators.
MTC setup/verification timings remain endpoint-specific. The configured timeout
is 30 seconds. Failure rows have no invented timing or byte values.

For each profile/N and auth mode, the basic effect is MTC minus X.509. The central
interaction is `(MTC_mutual - X509_mutual) - (MTC_server - X509_server)` within the
same round. Summarize within campaigns first, then bootstrap campaign medians
with 10,000 resamples. All successful outliers remain included. Report available
pairs and failure rates; do not silently drop failures or replace missing pairs.
If an entire campaign has no valid pairs, no bootstrap interval is emitted.
Intervals with only five campaigns are descriptive, with no multiplicity
correction; timings conditional on success are not unconditional reliability
claims. Raw observation medians and medians of paired campaign effects are
explicitly separate outputs.

RTT is split across endpoint egress; loss is independently applied per egress and
is not end-to-end failure probability. Rate is implemented using TBF with a
10-ms rate-sized burst (minimum 1,600 bytes), queue latency bound 1,000 ms, and
child netem. Keep the exact qdisc dumps and command logs. Twenty ping probes
check median RTT within max(10 ms,15% of configured RTT). Rate-only probes require
80--105% received goodput in both directions after four omitted seconds and four
measured seconds, with no probe retransmissions or qdisc drops. Lossy-path
iperf goodput is diagnostic, not subject to that rate-only threshold. Small ping
samples do not validate a precise loss probability; configured qdisc loss is the
condition. Lossless measurement blocks must have no qdisc drops.

A full lossy block retains TLS failures/timeouts and continues; a failed positive
preflight/smoke, lossless failure, startup failure, or instrumentation/identity
mismatch invalidates the stage. Namespace TCP snapshots include probes and are
not attributed to individual handshakes. TLS BIO bytes exclude retransmitted
wire traffic. No PCAP instrumentation is mixed into this performance population.

This is the local experimental MTC implementation with pre-distributed trust,
not full IETF draft compliance or deployment security equivalence. X.509 checks
the server hostname through s_client; MTC follows the implementation's trust
verification path with the same source server identity fixture. Independent
identity-policy equivalence is outside these performance gates. The recorded
MTC trust-file size is an external storage/input quantity, not a measured
trust-distribution protocol cost. The repeated same-leaf design is a controlled
network comparison, not a multi-client cache or population-diversity experiment.

## Files

- `protocol.json`: frozen-design inputs; `common.py`: pure matrix/schedule and hashes.
- `fixtures.py`: opt-in generation using existing MTC preparation primitives.
- `cli.py`: plan, freeze, stage gates, audit and analysis entrypoint.
- `runner.py`: isolated Docker execution and network probes.
- `metrics.py`: endpoint invariants; `audit.py`: offline evidence checks.
- `analyze.py`: failure-aware paired effects and authentication interaction.
- `test_offline.py`: synthetic and mocked regression tests, never real TLS.
