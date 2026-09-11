# Controlled latency-only TLS experiment

Thirty successful campaigns: five per additional RTT target 0, 10, 20, 50, 100 and 200 ms. Each campaign contains five warmup and thirty measured paired rounds over six PQ scenarios: 5,400 measured handshakes and 900 warmups. Smoke observations are separate and excluded. No packet loss, jitter or bandwidth qdisc was configured.

TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only authentication, no tickets/resumption and N=16 remain fixed. `netem delay RTT/2` is applied to client and server eth0 egress. A 20-probe ping before every campaign measures effective RTT.

Final inference uses medians within campaign, round-paired campaign effects, then 10,000 bootstrap resamples of five campaigns at each RTT. Individual handshakes are not bootstrap units. All Tukey outliers are retained.

| RTT target | measured RTT median | X.509 wall ms | Compact warm wall ms | MTC landmark wall ms | Compact−X.509 paired ms | MTC−X.509 paired ms |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0.099 | 1.463 | 2.259 | 1.414 | 0.852 [0.657, 0.947] | -0.054 [-0.195, 0.055] |
| 10 | 11.500 | 12.614 | 13.538 | 12.363 | 0.941 [0.455, 1.060] | -0.196 [-0.313, -0.118] |
| 20 | 22.350 | 24.720 | 25.918 | 24.598 | 1.259 [0.680, 1.688] | -0.428 [-0.653, 0.373] |
| 50 | 53.750 | 62.788 | 62.870 | 62.071 | 0.391 [-0.872, 3.863] | -0.103 [-1.878, 1.334] |
| 100 | 103.000 | 112.208 | 114.628 | 111.695 | 1.465 [0.968, 3.094] | -0.862 [-3.066, 0.889] |
| 200 | 204.500 | 210.803 | 214.325 | 210.923 | 2.285 [0.941, 2.956] | -0.364 [-1.191, 0.988] |

## RTT slopes

| Scenario | intercept ms | slope ms/ms RTT | R² | residual range ms |
|---|---:|---:|---:|---:|
| pq | 3.0224 | 1.02850 | 0.99853 | -2.548…4.484 |
| pq-rpk | 5.7667 | 1.05124 | 0.99725 | -3.545…6.404 |
| pq-compact-warm | 3.5824 | 1.04262 | 0.99886 | -2.474…3.656 |
| pq-compact-cold | 3.6132 | 1.03629 | 0.99881 | -2.494…3.626 |
| pq-mtc-experimental-landmark | 2.7040 | 1.02946 | 0.99879 | -2.305…4.034 |
| pq-mtc-experimental-standalone | 3.0171 | 1.02443 | 0.99849 | -2.602…4.503 |

## Scientific interpretation

All three primary schemes have similar descriptive RTT slopes; their slope spread is 0.01412 ms per ms of measured RTT. This is consistent with broadly equal TLS 1.3 flight structure. The paired tables show whether Compact/X.509 and MTC/X.509 gaps remain stable at each RTT; an interval including zero is reported as uncertain.

The byte counts do not change with RTT. This latency-only experiment does not establish that the approximately 34% PQ handshake-byte reduction itself improves latency under unconstrained bandwidth. Credential representation, local processing, RTT and out-of-band trust setup remain separate costs.

Total CPU campaign medians by RTT span: pq: 1.587–8.256 ms; pq-compact-warm: 2.329–10.198 ms; pq-mtc-experimental-landmark: 1.481–7.114 ms. CPU should not scale mechanically with artificial delay; any variation is treated as host/process noise and checked through campaign ranges rather than attributed to RTT.

Scenario timing order at every RTT is available in latency-summary.csv. Compact/MTC comparisons are architectural: MTC landmark retains different X.509/MTC and trust/transparency semantics; MTC standalone carries a local cosigner absent from X.509. Warm trust validation remains outside the timed handshake and repeats in every new client process.

RTT accuracy: median absolute target error 2.350 ms; maximum 8.000 ms. All 30 probes report zero loss. `qdisc-config.txt` and `qdisc-statistics.txt` contain the active configurations/statistics copied from every campaign.

1029 Tukey diagnostic rows are retained. Five campaigns per condition yield coarse intervals and the experiment covers one Docker host. No loss/jitter/bandwidth limitation was intentionally configured; qdisc evidence is recorded, but host scheduling and Docker overhead remain. Slopes are descriptive and must not be presented as a protocol complexity proof.

Plots are in plots/. Machine-readable values are in latency-summary.csv, latency-slopes.csv, paired-comparisons.csv, bootstrap-comparisons.csv and network-validation.csv.

Experiment commit: `b18ed919977d9456a6d9156b223d6bfc36a8a770`

After the audit, only `network_latency/README.md` changed: its reproduction commands now reuse one timestamped `FINAL` variable. The executable, protocol, measurement and analysis sources match the audited snapshot; exact README hashes are recorded in `metadata.json`.
