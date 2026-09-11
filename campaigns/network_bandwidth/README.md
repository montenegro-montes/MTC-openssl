# Bandwidth-limited network experiment

This directory defines the second network experiment. It is intentionally
separate from `campaigns/network_latency` and must be run only after the latency experiment
has completed, passed its audit, and been committed.

It uses the same N=16 TLS implementation and the `mt-tls-network:latency` image.
That image changes no OpenSSL code; it only adds `tc`, `ping` and `iperf3`.

## Network model

Each endpoint gets an independent egress TBF at the target rate. Therefore the
rate is **per direction**, not aggregate. A child netem adds exactly RTT/2 on
each endpoint egress. No loss or jitter is configured. The queue latency bound
is 1000 ms. Burst is selected before execution as:

```text
max(1600 bytes, rate_bits_per_second / 8 / 500)
```

This supplies two milliseconds of tokens at high rates and at least one packet
at low rates. A pre-campaign diagnostic showed that one millisecond caused TBF
drops at 100 Mbit/s under Docker/GSO, while two milliseconds produced zero drops
and retransmissions. The value is recorded per campaign. TBF necessarily has a
token burst; do not interpret the analytical byte/rate value as the exact
measured delay of a short TLS flight.

Before each campaign, twenty pings and forward/reverse four-second iperf3 probes
validate the new namespaces. TCP payload goodput in both directions must be
80%–105% of the configured TBF rate. This accounts for protocol overhead and
short-flow dynamics while still rejecting a materially incorrect limiter. The
configured TBF rate defines the condition; measured goodput is recorded as
validation evidence and a covariate. Any ping loss, iperf retransmission or
qdisc drop stops the run and marks that campaign invalid. There is no automatic
retry.

Client and server qdisc counters are captured immediately after each iperf
probe. Any drop on either endpoint invalidates the condition before TLS
measurements begin.

This acceptance interval was frozen before the definitive experiment after
excluded smoke diagnostics showed that valid 5 Mbit/s TCP goodput could fall
just below the former symmetric 15% boundary. Those failed smoke directories
remain excluded and are never pooled with results produced under this protocol.

## Step 1 — inspect the environment

First finish and commit the latency experiment. Confirm a clean worktree, the
saved image and the required fixtures:

```sh
git status --short
git rev-parse HEAD
docker image inspect mt-tls-network:latency --format '{{.Id}}' 2>/dev/null || echo 'missing; the tests stage will rebuild it'
docker ps
test -d artifacts/compact/batch16
test -d artifacts/mtc/batch16-v2
test -d artifacts/certs
```

## Step 2 — initialize a new result directory

```sh
BANDWIDTH_ROOT="artifacts/results/network-bandwidth-$(date +%Y%m%d-%H%M%S)"
echo "$BANDWIDTH_ROOT"
python3 campaigns/network_bandwidth/control.py init "$BANDWIDTH_ROOT"
```

Initialization refuses existing paths. Reuse this variable in all later commands.

## Step 3 — build the image if necessary

```sh
docker build -f docker/Dockerfile.network -t mt-tls-network:latency .
```

This manual build is optional. The regression gate automatically rebuilds any
missing image in the dependency chain and rebuilds a child when its parent has
changed.
The regression gate resolves the current `mt-tls-measurement:local` image,
records its immutable ID, and verifies that its filesystem layers are the base
of `mt-tls-network:latency`. It does not depend on an obsolete local image ID.

## Step 4 — run the regression gate

```sh
python3 campaigns/network_bandwidth/control.py tests "$BANDWIDTH_ROOT"
cat "$BANDWIDTH_ROOT/tests-status.json"
```

Do not continue unless `passed` is true.

If an older runner failed after writing a misleading `passed: true` status,
discard that unstarted result directory and initialize a new timestamped path.
The source inventory in the old directory belongs to the earlier commit and
must not be silently updated.

The gate also verifies that the bind-mounted `client.sh` is executable. Probe
stdout and stderr are always saved to the condition's `network-validation.log`
before a nonzero exit aborts the smoke run.

Forward and reverse iperf sessions are delimited separately. A fixed two-second
settling interval between them exceeds the configured one-second TBF queue
latency, preventing the second control connection from racing queued teardown
traffic. Any iperf JSON error is reported verbatim in the campaign status.

The driver uses one deterministic random stream: warmup shuffles consume the
first values and measured rounds continue from that state. Validation recreates
that sequence independently for each CSV.

## Step 5 — run and inspect the smoke test

```sh
python3 campaigns/network_bandwidth/run.py "$BANDWIDTH_ROOT" --smoke
```

Inspect the smoke status, RTT/throughput validation, qdisc statistics and drops:

```sh
cat "$BANDWIDTH_ROOT/smoke-status.json"
find "$BANDWIDTH_ROOT/smoke" -name validation.json -exec cat {} \;
find "$BANDWIDTH_ROOT/smoke" -name '*qdisc*' -type f -print
```

Only if all three smoke conditions pass (`RTT=50`, rates 20, 5 and 1 Mbps),
continue.

## Step 6 — run the full experiment

```sh
python3 campaigns/network_bandwidth/run.py "$BANDWIDTH_ROOT"
```

The full run contains 75 campaigns and refuses overwrites or automatic retries.

## Step 7 — monitor from a second terminal

```sh
docker ps --filter label=com.docker.compose.project=mtbandwidth
cat "$BANDWIDTH_ROOT/campaign-status.json"
find "$BANDWIDTH_ROOT/campaigns" -name driver.log -exec tail -n 3 {} \;
du -sh "$BANDWIDTH_ROOT"
```

## Step 8 — analyze, plot and audit

```sh
python3 campaigns/network_bandwidth/analyze.py "$BANDWIDTH_ROOT"
```

Generate plots using the same temporary plotting environment created for the
scaling experiment, or install its pinned requirements in a new venv:

```sh
/tmp/mt-scaling-plots-venv/bin/python campaigns/network_bandwidth/plots.py "$BANDWIDTH_ROOT"
python3 campaigns/network_bandwidth/control.py audit "$BANDWIDTH_ROOT"
```

The full experiment runs 75 campaigns: three RTTs × five rates × five campaigns.
Each campaign has five warmup and thirty measured randomized rounds over six PQ
scenarios. Expected totals are 13,500 measurements and 2,250 warmups. The smoke
adds 90 measurements and 54 warmups and is excluded from inference.

## Step 9 — inspect outputs and interpretation

The result directory contains all requested raw/aggregate CSVs, qdisc evidence,
validation, serialization references, break-even observations, amortization,
models, report and plots. `1/BW` is used only in a transparent descriptive model
because serialization delay is proportional to bytes/rate. It is not a causal
decomposition.

Warm trust amortization is an analytical byte model and is not mixed into measured
handshake latency. Compact/MTC comparisons remain architectural, and MTC standalone
includes a local cosigner absent from ordinary X.509.

## Step 10 — finish and record the experiment

After audit, commit only these scripts/configuration and update the ignored result
`metadata.json` and `report.md` with the resulting commit hash. Suggested commit:

```sh
git add docker/compose.network-bandwidth.yaml campaigns/network_bandwidth
git commit -m "experiment: add controlled bandwidth-limited TLS measurements"
python3 campaigns/network_bandwidth/record_commit.py "$BANDWIDTH_ROOT"
```

Do not add `artifacts/`, private keys, Docker logs or transient output to Git.
