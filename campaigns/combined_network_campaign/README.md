# Representative combined-network TLS campaign

This directory prepares the final controlled N=16 campaign combining RTT, bandwidth and independent symmetric per-egress random loss. It does not change the authentication implementations. MTC remains **MTC-experimental**, targeting `draft-ietf-plants-merkle-tree-certs-05`.

Preparation commit: `9b7ec5a3ed7bd5a8f406d95cd7b9d69f85e4832a`

## Frozen design

| Profile | Additional RTT | Per-egress delay | Bandwidth | Per-egress loss |
|---|---:|---:|---:|---:|
| baseline | 10 ms | 5 ms | unconstrained | 0% |
| wan | 50 ms | 25 ms | 20 Mbit/s | 0.5% |
| constrained | 100 ms | 50 ms | 5 Mbit/s | 1% |
| adverse | 100 ms | 50 ms | 1 Mbit/s | 2% |

Both client and server receive the same egress configuration. The two half delays form the configured additional RTT. Loss is sampled independently on each direction, so the configured percentage is not an end-to-end failure probability. There is no jitter, reordering, duplication or corruption.

For `wan`, `constrained`, and `adverse`, a root TBF applies the rate before a child netem applies delay and loss. The burst is `max(1600, rate_bit_s / 8 / 1000)` bytes and the TBF queue latency is 1000 ms, matching the bandwidth-only policy. `baseline` has only a root netem and therefore no artificial rate cap. `tc qdisc replace` removes a stale root hierarchy before each namespace is used.

The six scenarios are `pq`, `pq-rpk`, `pq-compact-warm`, `pq-compact-cold`, `pq-mtc-experimental-landmark`, and `pq-mtc-experimental-standalone`. The primary paper comparison is PQ X.509 versus Compact warm versus MTC landmark. TLS 1.3, X25519, `TLS_AES_256_GCM_SHA384`, server-only authentication, disabled tickets/resumption, fixtures, keys, trust material, OpenSSL images and the Docker bridge remain fixed.

The full design contains 4 profiles × 5 campaigns × 30 rounds × 6 scenarios = **3,600 measured attempts**, plus **600 warmups**. Seeds are `400000 + profile_code*1000 + campaign`, with codes baseline=0, wan=1, constrained=2 and adverse=3. The default scenario order is shuffled reproducibly by the frozen measurement driver. No automatic retry occurs; timeouts and TLS errors are observations.

## Step 1 — inspect the environment

Run from the repository root. Use a new result path and keep it unchanged throughout the experiment:

```sh
git status --short
git rev-parse HEAD
docker image inspect mt-tls-network:latency --format '{{.Id}}'
docker ps
test -d artifacts/compact/batch16
test -d artifacts/mtc/batch16-v2
test -d artifacts/certs
```

Finish and commit each isolated network experiment before starting this combined
campaign.

## Step 2 — inspect the plan and initialize

```sh
COMBINED_ROOT="artifacts/results/combined-network-$(date +%Y%m%d-%H%M%S)"
echo "$COMBINED_ROOT"
python3 campaigns/combined_network_campaign/run.py --root "$COMBINED_ROOT" --dry-run
python3 campaigns/combined_network_campaign/control.py init "$COMBINED_ROOT"
```

`init` records `git rev-parse HEAD` and `git status --short` in `metadata.json`, hashes all tracked source plus N=16 fixtures, and refuses to overwrite a directory. Inspect the dry-run JSON: full mode must show 20 campaigns, 3,600 measured attempts and 600 warmups. Optional `--scenarios ...` filtering is intended for diagnosis; filtered output is not the final paper design.

## Step 3 — build the image if necessary

The Docker image must already exist. If needed, build it manually using the same network image recipe used by the earlier experiments:

```sh
docker build -f docker/Dockerfile.network -t mt-tls-network:latency .
```

## Step 4 — run the regression gate

Run the frozen regression gate and verify the saved image ID and required `tc`, `ping`, `nstat`, and `iperf3` tools:

```sh
python3 campaigns/combined_network_campaign/control.py tests "$COMBINED_ROOT"
cat "$COMBINED_ROOT/tests-status.json"
```

## Step 5 — run the preflight

These commands generate network traffic and are intentionally **not run during preparation**.

```sh
# Baseline, 2 rounds, 1 warmup, six scenarios.
python3 campaigns/combined_network_campaign/run.py --root "$COMBINED_ROOT" --preflight
```

Inspect `preflight-status.json`, network validation, qdiscs and driver logs.

## Step 6 — run and inspect smoke

```sh
python3 campaigns/combined_network_campaign/run.py --root "$COMBINED_ROOT" --smoke
cat "$COMBINED_ROOT/smoke-status.json"
find "$COMBINED_ROOT/smoke" -name validation.json -exec cat {} \;
find "$COMBINED_ROOT/smoke" -name '*qdisc*' -type f -print
```

Smoke covers baseline, constrained and adverse with 90 measurements and 54
warmups.

## Step 7 — run the full campaign

```sh
python3 campaigns/combined_network_campaign/run.py --root "$COMBINED_ROOT"
```

Each campaign starts a fresh server container, applies the declared hierarchy to both endpoints, captures `tc -s qdisc`, pings with 200 packets for preflight/smoke or 2,000 for full runs, and measures forward and reverse iperf throughput. The operational RTT gate is configured RTT ±10 ms. Throughput must be positive and limited profiles must not exceed the configured cap by more than 15%. A lower TCP throughput is valid under combined RTT and loss and is retained as descriptive telemetry. The validated TBF qdisc is authoritative for the bandwidth cap, just as the qdisc configuration is authoritative for low loss because a finite probe need not observe the exact random percentage. Linux includes child netem drops in the parent TBF drop total, so TBF-own drops are derived as `max(tbf - netem, 0)` and must be zero; the raw counters and derived values are retained in `validation.json`.

Do not continue after a failed gate. Inspect the status JSON, `network-validation.log`, qdisc snapshots, failures and shutdown log. Fixing source after data collection requires a new commit and new result directory; never combine results generated from different source commits without recording that distinction.

## Step 8 — monitor from a second terminal

```sh
docker ps --filter label=com.docker.compose.project=mtcombined
cat "$COMBINED_ROOT/campaign-status.json"
find "$COMBINED_ROOT/campaigns" -name driver.log -exec tail -n 3 {} \;
du -sh "$COMBINED_ROOT"
```

## Step 9 — analyze, plot and audit

```sh
python3 campaigns/combined_network_campaign/analyze.py "$COMBINED_ROOT"
python3 campaigns/combined_network_campaign/plots.py "$COMBINED_ROOT"
python3 campaigns/combined_network_campaign/validate.py "$COMBINED_ROOT"
python3 campaigns/combined_network_campaign/control.py audit "$COMBINED_ROOT"
```

Install plotting dependencies only if absent:

```sh
python3 -m pip install -r campaigns/combined_network_campaign/requirements-plots.txt
```

The analysis writes `main-table.csv`, `scenario-summary.csv`, campaign summaries, common-success-round paired comparisons, 10,000-resample campaign bootstrap intervals, network telemetry, failure accounting, campaign-level TCP counters and four plots for wall time, CPU, TLS BIO bytes and failure rate. TCP retransmissions cannot be attributed reliably to individual handshakes. TLS BIO bytes are not wire bytes. Results describe these controlled Docker profiles and must not be generalized as all real networks.

Prior isolated summaries may be attached for a descriptive side-by-side appendix:

```sh
python3 campaigns/combined_network_campaign/analyze.py "$COMBINED_ROOT" \
  --isolated-latency path/to/latency-summary.csv \
  --isolated-bandwidth path/to/bandwidth-summary.csv \
  --isolated-loss path/to/loss-summary.csv
```

The resulting `isolated-comparison.csv` preserves source rows and labels them descriptive. RTT, bandwidth and loss effects interact; never add isolated effects to predict a combined profile.

## Step 10 — finish, record and clean up

After audit, create the experiment's own commit according to the repository policy, then record that resulting hash in both ignored result files:

```sh
python3 campaigns/combined_network_campaign/record_commit.py "$COMBINED_ROOT"
sh campaigns/combined_network_campaign/cleanup.sh
git status --short
```

Use `campaigns/combined_network_campaign/cleanup.sh` only to stop this Compose project. It does not delete result directories. No Git tag is created in this preparation phase.
