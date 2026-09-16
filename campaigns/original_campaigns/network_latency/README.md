# Latency-only network experiment

This campaign uses the frozen N=16 implementation and measurement driver.
`docker/original_campaigns/Dockerfile.network` derives from `mt-tls-measurement:local` and adds only the
network tools; it does not rebuild OpenSSL.

The client and server independently apply `netem delay RTT/2` to `eth0` egress.
There is no bandwidth limit, loss, jitter, reordering, duplication or corruption.
The design uses RTT targets 0, 10, 20, 50, 100 and 200 ms, five campaigns per
target, five warmups and thirty measured randomized rounds over six PQ scenarios.

PCAP capture is an explicit diagnostic option for a fresh run:

```sh
python3 campaigns/original_campaigns/network_latency/run.py --pcap "$LATENCY_ROOT"
```

It preserves the six scenarios, RTT/qdisc setup, probes, warmups and measurement
CSV files. Only measured observations request a per-observation tcpdump capture;
warmups remain uncaptured. The capture sidecar shares the server namespace and
observes server `eth0`, so it is not a dual-endpoint trace. Derived results use
the common `pcap-metrics.jsonl` schema and the Stage-1 extractor; failures remain
`null` and do not rewrite successful OpenSSL measurements. Captured runs are
marked `performance_comparable_to_uncaptured: false` and must not be pooled with
historical uncaptured latency results. The primary metric remains
`handshake_wall_ms`; PCAP timing and byte fields are secondary diagnostics.

Run every command from the repository root. Choose one new path and keep the same
shell variable through all steps.

## Step 1 — inspect the environment

```sh
git status --short
git rev-parse HEAD
docker image inspect mt-tls-measurement:local --format '{{.Id}}' 2>/dev/null || echo 'missing; the tests stage will rebuild it'
docker ps
test -d artifacts/compact/batch16
test -d artifacts/mtc/batch16-v2
test -d artifacts/certs
```

Do not start while another network campaign is running. Finish and commit source
changes from the preceding experiment before initializing this one.

## Step 2 — choose and initialize the result directory

```sh
LATENCY_ROOT="artifacts/results/network-latency-$(date +%Y%m%d-%H%M%S)"
echo "$LATENCY_ROOT"
python3 campaigns/original_campaigns/network_latency/control.py init "$LATENCY_ROOT"
```

Initialization refuses an existing path and records the Git state, source and
fixture hashes. Never reuse a failed or completed result directory.

## Step 3 — build the network image if necessary

```sh
docker build -f docker/original_campaigns/Dockerfile.network -t mt-tls-network:latency .
docker image inspect mt-tls-network:latency --format '{{.Id}}' 2>/dev/null || echo 'missing; the tests stage will rebuild it'
```

This manual build is optional. `control.py tests` resolves the complete image
chain and rebuilds missing images before running the regression gate.

If the image already exists and matches the intended validated base, skip the
build and only inspect its ID.

## Step 4 — run the regression gate

```sh
python3 campaigns/original_campaigns/network_latency/control.py tests "$LATENCY_ROOT"
cat "$LATENCY_ROOT/tests-status.json"
```

Confirm that `passed` is true and inspect `tests.log`. A failed gate invalidates
the directory; do not run measurements from it.

## Step 5 — run and inspect the smoke test

```sh
python3 campaigns/original_campaigns/network_latency/run.py "$LATENCY_ROOT" --smoke
cat "$LATENCY_ROOT/smoke-status.json"
find "$LATENCY_ROOT/smoke" -name validation.json -exec cat {} \;
find "$LATENCY_ROOT/smoke" -name '*qdisc*' -type f -print
```

Smoke output is stored separately and excluded from final inference. Confirm the
expected RTT, zero packet loss, absence of rate-limiting qdiscs, successful TLS
controls and clean Compose shutdown before continuing.

## Step 6 — run the full experiment

```sh
python3 campaigns/original_campaigns/network_latency/run.py "$LATENCY_ROOT"
```

The full experiment creates 30 campaigns. Each campaign uses a fresh server
container and a newly configured client namespace. The runner refuses to
overwrite or retry a campaign.

## Step 7 — monitor from a second terminal

```sh
docker ps --filter label=com.docker.compose.project=mtlatency
cat "$LATENCY_ROOT/campaign-status.json"
find "$LATENCY_ROOT/campaigns" -name driver.log -exec tail -n 3 {} \;
du -sh "$LATENCY_ROOT"
```

Do not alter qdiscs or restart Docker while the experiment is running.

## Step 8 — analyze, plot and audit

```sh
python3 campaigns/original_campaigns/network_latency/analyze.py "$LATENCY_ROOT"
python3 campaigns/original_campaigns/network_latency/plots.py "$LATENCY_ROOT"
python3 campaigns/original_campaigns/network_latency/control.py audit "$LATENCY_ROOT"
```

If the plotting environment does not exist, create a separate virtual
environment using `campaigns/original_campaigns/scaling_campaign/requirements-plots.txt`.
Final bootstrap inference resamples the five campaign effects at each fixed RTT
10,000 times; smoke observations are not included.

## Step 9 — inspect the publication outputs

Inspect at least:

```sh
cat "$LATENCY_ROOT/report.md"
ls -lh "$LATENCY_ROOT"/*.csv
find "$LATENCY_ROOT" -name validation.json -print
find "$LATENCY_ROOT" -name '*qdisc*' -type f -print
```

Keep raw results, Docker logs and fixture keys under the ignored `artifacts/`
tree. Do not add them to Git.

## Step 10 — finish the experiment

Run the audit again after all generated analysis is present:

```sh
python3 campaigns/original_campaigns/network_latency/control.py audit "$LATENCY_ROOT"
git status --short
git rev-parse HEAD
```

Commit this completed experiment separately from later bandwidth, loss or
combined-network work. Record the resulting commit hash in the experiment's
`metadata.json` and `report.md` according to the repository experiment policy.
