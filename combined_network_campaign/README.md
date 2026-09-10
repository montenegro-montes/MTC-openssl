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

## Prepare and inspect

Run from the repository root. Use a new result path and keep it unchanged throughout the experiment:

```sh
RESULT=artifacts/results/combined-network-YYYYMMDD
python3 combined_network_campaign/run.py --root "$RESULT" --dry-run
python3 combined_network_campaign/control.py init "$RESULT"
```

`init` records `git rev-parse HEAD` and `git status --short` in `metadata.json`, hashes all tracked source plus N=16 fixtures, and refuses to overwrite a directory. Inspect the dry-run JSON: full mode must show 20 campaigns, 3,600 measured attempts and 600 warmups. Optional `--scenarios ...` filtering is intended for diagnosis; filtered output is not the final paper design.

The Docker image must already exist. If needed, build it manually using the same network image recipe used by the earlier experiments:

```sh
docker build -f Dockerfile.network -t mt-tls-network:latency .
```

Run the frozen regression gate and verify the saved image ID and required `tc`, `ping`, `nstat`, and `iperf3` tools:

```sh
python3 combined_network_campaign/control.py tests "$RESULT"
```

## Manual execution gates

These commands generate network traffic and are intentionally **not run during preparation**.

```sh
# Small functional gate: baseline, 2 rounds, 1 warmup, six scenarios.
python3 combined_network_campaign/run.py --root "$RESULT" --preflight

# Required smoke: baseline, constrained and adverse; 5 rounds + 3 warmups.
# Totals: 90 measured attempts and 54 warmups.
python3 combined_network_campaign/run.py --root "$RESULT" --smoke

# Full campaign: baseline, wan, constrained and adverse.
python3 combined_network_campaign/run.py --root "$RESULT"
```

Each campaign starts a fresh server container, applies the declared hierarchy to both endpoints, captures `tc -s qdisc`, pings with 200 packets for preflight/smoke or 2,000 for full runs, and measures forward and reverse iperf throughput. The operational RTT gate is configured RTT ±10 ms. Limited-profile throughput must be within ±15%; baseline throughput is descriptive and has no target. The qdisc configuration is authoritative for low loss because a finite probe need not observe the exact random percentage. TBF drops must be zero; netem drops are expected when loss is configured and are reported separately.

Do not continue after a failed gate. Inspect the status JSON, `network-validation.log`, qdisc snapshots, failures and shutdown log. Fixing source after data collection requires a new commit and new result directory; never combine results generated from different source commits without recording that distinction.

## Analysis and audit

```sh
python3 combined_network_campaign/analyze.py "$RESULT"
python3 combined_network_campaign/plots.py "$RESULT"
python3 combined_network_campaign/validate.py "$RESULT"
python3 combined_network_campaign/control.py audit "$RESULT"
```

Install plotting dependencies only if absent:

```sh
python3 -m pip install -r combined_network_campaign/requirements-plots.txt
```

The analysis writes `main-table.csv`, `scenario-summary.csv`, campaign summaries, common-success-round paired comparisons, 10,000-resample campaign bootstrap intervals, network telemetry, failure accounting, campaign-level TCP counters and four plots for wall time, CPU, TLS BIO bytes and failure rate. TCP retransmissions cannot be attributed reliably to individual handshakes. TLS BIO bytes are not wire bytes. Results describe these controlled Docker profiles and must not be generalized as all real networks.

Prior isolated summaries may be attached for a descriptive side-by-side appendix:

```sh
python3 combined_network_campaign/analyze.py "$RESULT" \
  --isolated-latency path/to/latency-summary.csv \
  --isolated-bandwidth path/to/bandwidth-summary.csv \
  --isolated-loss path/to/loss-summary.csv
```

The resulting `isolated-comparison.csv` preserves source rows and labels them descriptive. RTT, bandwidth and loss effects interact; never add isolated effects to predict a combined profile.

After audit, create the experiment's own commit according to the repository policy, then record that resulting hash in both ignored result files:

```sh
python3 combined_network_campaign/record_commit.py "$RESULT"
```

Use `combined_network_campaign/cleanup.sh` only to stop this Compose project. It does not delete result directories. No Git tag is created in this preparation phase.
