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
max(1600 bytes, rate_bits_per_second / 8 / 1000)
```

This supplies roughly one scheduler-millisecond of tokens at high rates and at
least one packet at low rates. It is recorded per campaign. TBF necessarily has
a token burst; do not interpret the analytical byte/rate value as the exact
measured delay of a short TLS flight.

Before each campaign, twenty pings and forward/reverse four-second iperf3 probes
validate the new namespaces. Both directions must be within the predeclared
±15% tolerance. Any ping loss, iperf retransmission or qdisc drop stops the run
and marks that campaign invalid. There is no automatic retry.

## Manual execution

First finish and commit the latency experiment. Confirm a clean worktree, then
create a unique result directory; substitute one timestamp consistently:

```sh
git status --short
git rev-parse HEAD
python3 campaigns/network_bandwidth/control.py init artifacts/results/network-bandwidth-NEW
python3 campaigns/network_bandwidth/control.py tests artifacts/results/network-bandwidth-NEW
python3 campaigns/network_bandwidth/run.py artifacts/results/network-bandwidth-NEW --smoke
```

Inspect the smoke status, RTT/throughput validation, qdisc statistics and drops:

```sh
cat artifacts/results/network-bandwidth-NEW/smoke-status.json
find artifacts/results/network-bandwidth-NEW/smoke -name validation.json -exec cat {} \;
find artifacts/results/network-bandwidth-NEW/smoke -name '*qdisc*' -type f -print
```

Only if all three smoke conditions pass (`RTT=50`, rates 20, 5 and 1 Mbps), run:

```sh
python3 campaigns/network_bandwidth/run.py artifacts/results/network-bandwidth-NEW
python3 campaigns/network_bandwidth/analyze.py artifacts/results/network-bandwidth-NEW
```

Generate plots using the same temporary plotting environment created for the
scaling experiment, or install its pinned requirements in a new venv:

```sh
/tmp/mt-scaling-plots-venv/bin/python campaigns/network_bandwidth/plots.py artifacts/results/network-bandwidth-NEW
python3 campaigns/network_bandwidth/control.py audit artifacts/results/network-bandwidth-NEW
```

The full experiment runs 75 campaigns: three RTTs × five rates × five campaigns.
Each campaign has five warmup and thirty measured randomized rounds over six PQ
scenarios. Expected totals are 13,500 measurements and 2,250 warmups. The smoke
adds 90 measurements and 54 warmups and is excluded from inference.

## Outputs and interpretation

The result directory contains all requested raw/aggregate CSVs, qdisc evidence,
validation, serialization references, break-even observations, amortization,
models, report and plots. `1/BW` is used only in a transparent descriptive model
because serialization delay is proportional to bytes/rate. It is not a causal
decomposition.

Warm trust amortization is an analytical byte model and is not mixed into measured
handshake latency. Compact/MTC comparisons remain architectural, and MTC standalone
includes a local cosigner absent from ordinary X.509.

After audit, commit only these scripts/configuration and update the ignored result
`metadata.json` and `report.md` with the resulting commit hash. Suggested commit:

```sh
git add docker/compose.network-bandwidth.yaml campaigns/network_bandwidth
git commit -m "experiment: add controlled bandwidth-limited TLS measurements"
python3 campaigns/network_bandwidth/record_commit.py artifacts/results/network-bandwidth-NEW
```

Do not add `artifacts/`, private keys, Docker logs or transient output to Git.
