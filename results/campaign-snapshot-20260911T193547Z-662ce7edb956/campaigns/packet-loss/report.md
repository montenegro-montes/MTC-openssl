# Controlled packet-loss TLS experiment

Six symmetric per-egress netem loss settings at a fixed additional 50 ms RTT. Thirty campaigns contain 5,400 measured attempts plus 900 warmups. Successful-handshake latency and failure rate are reported together. Failed connections are retained in reliability accounting.

Loss is independently applied to client and server egress; the target percentage is not an end-to-end connection loss probability. The qdisc value is authoritative, especially for 0.1% where finite probes may observe zero events. No bandwidth, jitter, reordering, duplication or corruption is configured.

| Loss % | scenario | TLS bytes | wall median ms | client CPU ms | server CPU ms | total CPU ms | failures / 150 | failure rate |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | pq | 9572.000 | 59.262 | 2.379 | 2.280 | 4.668 | 0 | 0.0000 |
| 0 | pq-rpk | 5994.000 | 64.279 | 6.835 | 2.077 | 9.065 | 0 | 0.0000 |
| 0 | pq-compact-warm | 6281.000 | 60.840 | 3.879 | 2.016 | 6.153 | 0 | 0.0000 |
| 0 | pq-compact-cold | 9648.000 | 61.122 | 4.488 | 1.969 | 6.698 | 0 | 0.0000 |
| 0 | pq-mtc-experimental-landmark | 6382.000 | 58.459 | 1.837 | 2.154 | 4.122 | 0 | 0.0000 |
| 0 | pq-mtc-experimental-standalone | 13010.000 | 58.996 | 2.830 | 2.221 | 5.312 | 0 | 0.0000 |
| 0.1 | pq | 9572.000 | 62.869 | 2.539 | 2.380 | 5.078 | 0 | 0.0000 |
| 0.1 | pq-rpk | 5994.000 | 67.980 | 7.277 | 2.205 | 9.823 | 0 | 0.0000 |
| 0.1 | pq-compact-warm | 6281.000 | 64.439 | 4.173 | 2.068 | 6.398 | 0 | 0.0000 |
| 0.1 | pq-compact-cold | 9648.000 | 64.711 | 4.556 | 2.259 | 7.242 | 0 | 0.0000 |
| 0.1 | pq-mtc-experimental-landmark | 6382.000 | 62.678 | 1.875 | 2.173 | 4.063 | 0 | 0.0000 |
| 0.1 | pq-mtc-experimental-standalone | 13010.000 | 61.718 | 3.033 | 2.640 | 5.643 | 0 | 0.0000 |
| 0.5 | pq | 9572.000 | 62.467 | 2.531 | 2.400 | 5.113 | 0 | 0.0000 |
| 0.5 | pq-rpk | 5994.000 | 68.960 | 7.009 | 2.209 | 9.404 | 0 | 0.0000 |
| 0.5 | pq-compact-warm | 6281.000 | 65.491 | 4.254 | 2.170 | 6.852 | 0 | 0.0000 |
| 0.5 | pq-compact-cold | 9648.000 | 65.363 | 4.695 | 2.557 | 7.532 | 0 | 0.0000 |
| 0.5 | pq-mtc-experimental-landmark | 6382.000 | 63.543 | 1.877 | 2.227 | 4.071 | 0 | 0.0000 |
| 0.5 | pq-mtc-experimental-standalone | 13010.000 | 64.077 | 2.939 | 2.620 | 5.735 | 0 | 0.0000 |
| 1 | pq | 9572.000 | 62.671 | 2.527 | 2.502 | 5.269 | 0 | 0.0000 |
| 1 | pq-rpk | 5994.000 | 69.050 | 7.148 | 2.246 | 9.887 | 0 | 0.0000 |
| 1 | pq-compact-warm | 6281.000 | 65.838 | 4.096 | 2.514 | 6.619 | 0 | 0.0000 |
| 1 | pq-compact-cold | 9648.000 | 64.870 | 4.570 | 2.462 | 7.413 | 0 | 0.0000 |
| 1 | pq-mtc-experimental-landmark | 6382.000 | 62.736 | 1.908 | 2.641 | 4.699 | 0 | 0.0000 |
| 1 | pq-mtc-experimental-standalone | 13010.000 | 63.652 | 3.040 | 2.270 | 5.437 | 0 | 0.0000 |
| 2 | pq | 9572.000 | 63.897 | 2.575 | 2.180 | 4.947 | 0 | 0.0000 |
| 2 | pq-rpk | 5994.000 | 70.249 | 7.198 | 2.445 | 9.848 | 0 | 0.0000 |
| 2 | pq-compact-warm | 6281.000 | 64.694 | 4.051 | 2.187 | 6.450 | 0 | 0.0000 |
| 2 | pq-compact-cold | 9648.000 | 65.303 | 4.665 | 2.183 | 7.038 | 0 | 0.0000 |
| 2 | pq-mtc-experimental-landmark | 6382.000 | 62.378 | 1.879 | 2.565 | 4.625 | 0 | 0.0000 |
| 2 | pq-mtc-experimental-standalone | 13010.000 | 63.852 | 3.131 | 2.280 | 6.101 | 0 | 0.0000 |
| 5 | pq | 9572.000 | 62.691 | 2.676 | 2.381 | 5.138 | 0 | 0.0000 |
| 5 | pq-rpk | 5994.000 | 69.317 | 7.196 | 2.692 | 9.639 | 0 | 0.0000 |
| 5 | pq-compact-warm | 6281.000 | 62.574 | 4.145 | 2.360 | 6.539 | 0 | 0.0000 |
| 5 | pq-compact-cold | 9648.000 | 64.441 | 4.872 | 2.570 | 7.506 | 0 | 0.0000 |
| 5 | pq-mtc-experimental-landmark | 6382.000 | 64.854 | 1.903 | 2.446 | 4.464 | 0 | 0.0000 |
| 5 | pq-mtc-experimental-standalone | 13010.000 | 63.546 | 3.152 | 2.414 | 6.281 | 0 | 0.0000 |

Primary paper table is available as `scenario-summary.csv`; filter scenarios `pq`, `pq-compact-warm`, and `pq-mtc-experimental-landmark`. Paired effects and campaign bootstrap intervals are in `bootstrap-comparisons.csv`. If loss prevents a paired round or an entire campaign effect, counts are explicit and unavailable values are not invented.

TCP counters are campaign/container-namespace deltas. They include probes only where stated by the runner and cannot be attributed reliably to individual handshakes or scenarios. Retransmitted bytes are unavailable. Therefore the default figures include campaign retransmission counts versus configured loss, but do not generate handshake latency versus per-connection retransmissions. TLS BIO bytes are not wire bytes.

Compact and MTC do not modify TCP. Any difference is associated with their transmitted authentication representation under this Docker/TCP configuration; it does not establish inherent packet-loss resilience. Credential size, TCP segments, random loss events, retransmission behavior, local processing and trust setup remain distinct. Compact/MTC comparisons are architectural and MTC standalone includes a local cosigner.

All failures, timeouts and TLS errors are in `failures.csv`. All Tukey outliers remain included. No linear loss model is forced. Five campaigns per condition, finite low-loss probes, campaign-level retransmission attribution and one Docker host limit interpretation.

Plots are under `plots/`. Network/qdisc evidence is in `network-validation.csv`, `qdisc-config.txt`, and `qdisc-statistics.txt`.

Experiment commit: `d6b98c7faf728e7627c6b7292a198548c38f9de4`
