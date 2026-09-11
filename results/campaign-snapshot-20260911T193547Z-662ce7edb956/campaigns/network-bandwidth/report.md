# Controlled bandwidth-limited TLS experiment

Seventy-five campaigns: five per 3 RTT × 5 per-direction rate conditions. Each contains five warmup and thirty measured paired rounds over six PQ scenarios: 13,500 measured handshakes and 2,250 warmups. Smoke data are separate. This report is generated only after all throughput, RTT, retransmission and qdisc-drop gates pass.

TBF rate is configured independently on client and server egress, with a burst equal to max(1600 bytes, ten milliseconds of configured rate) and a 1000 ms queue latency bound. This conservative rate/HZ sizing uses HZ=100. A child netem adds RTT/2 deterministic delay in each direction. No loss or jitter option is configured. Validation uses twenty pings and forward/reverse iperf3 probes before each campaign. Each probe preconditions TCP for four omitted seconds and then measures receiver payload goodput for four seconds; both directions must be 80%–105% of the configured TBF rate. Any retransmit or qdisc drop invalidates and stops the campaign. The configured TBF rate defines the experimental condition, while observed receiver goodput is retained as validation evidence and a covariate.

| RTT | rate | measured Mbps | X.509 wall ms | Compact warm wall ms | MTC landmark wall ms | Compact−X.509 paired ms | MTC−X.509 paired ms |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 100 | 95.629 | 12.493 | 13.397 | 12.492 | 0.882 [0.733, 1.079] | -0.100 [-0.266, 0.413] |
| 10 | 20 | 19.125 | 12.416 | 13.537 | 12.358 | 1.104 [0.667, 1.305] | -0.115 [-0.339, 0.040] |
| 10 | 10 | 9.542 | 12.340 | 13.479 | 12.388 | 1.062 [0.833, 1.111] | -0.130 [-0.390, 0.479] |
| 10 | 5 | 4.758 | 17.271 | 13.448 | 12.536 | -3.676 [-3.987, -3.479] | -4.823 [-5.222, -4.593] |
| 10 | 1 | 0.898 | 78.831 | 51.056 | 52.200 | -27.887 [-28.148, -27.310] | -26.597 [-26.875, -26.257] |
| 50 | 100 | 95.622 | 58.734 | 60.409 | 58.410 | 2.401 [1.613, 2.574] | -0.267 [-1.344, 0.466] |
| 50 | 20 | 19.124 | 60.952 | 63.111 | 60.381 | 1.882 [-0.882, 3.123] | -0.655 [-2.058, 2.249] |
| 50 | 10 | 9.562 | 61.001 | 63.191 | 61.528 | 1.805 [-1.118, 4.306] | -0.907 [-3.255, -0.291] |
| 50 | 5 | 4.775 | 65.865 | 63.781 | 61.772 | -1.369 [-4.302, 0.180] | -3.816 [-4.568, 1.277] |
| 50 | 1 | 0.831 | 124.832 | 97.629 | 99.436 | -28.620 [-31.993, -27.334] | -27.223 [-29.285, -26.044] |
| 100 | 100 | 95.628 | 109.370 | 111.247 | 109.241 | 2.354 [0.871, 3.017] | -0.422 [-2.033, 0.766] |
| 100 | 20 | 19.126 | 102.227 | 103.467 | 102.454 | 0.765 [0.596, 1.836] | -0.002 [-0.238, 0.572] |
| 100 | 10 | 9.513 | 102.129 | 103.239 | 102.176 | 1.077 [0.535, 1.419] | -0.016 [-0.272, 0.111] |
| 100 | 5 | 4.753 | 106.827 | 103.248 | 102.317 | -3.458 [-3.829, -3.292] | -4.718 [-4.898, -4.070] |
| 100 | 1 | 0.935 | 166.437 | 139.098 | 139.774 | -27.349 [-27.718, -27.123] | -26.688 [-26.842, -26.338] |

## Break-even observations

- RTT 10 ms, pq-compact-warm: observed faster points [5, 1]; neighboring sign-change intervals ["5-10 Mbps"]. No exact break-even is inferred.
- RTT 10 ms, pq-mtc-experimental-landmark: observed faster points [100, 20, 10, 5, 1]; neighboring sign-change intervals []. No exact break-even is inferred.
- RTT 50 ms, pq-compact-warm: observed faster points [5, 1]; neighboring sign-change intervals ["5-10 Mbps"]. No exact break-even is inferred.
- RTT 50 ms, pq-mtc-experimental-landmark: observed faster points [100, 20, 10, 5, 1]; neighboring sign-change intervals []. No exact break-even is inferred.
- RTT 100 ms, pq-compact-warm: observed faster points [5, 1]; neighboring sign-change intervals ["5-10 Mbps"]. No exact break-even is inferred.
- RTT 100 ms, pq-mtc-experimental-landmark: observed faster points [100, 20, 10, 5, 1]; neighboring sign-change intervals []. No exact break-even is inferred.

## Descriptive RTT + inverse-bandwidth models

The `1/BW` term is used because simple serialization delay is proportional to bytes divided by rate. These fits are descriptive diagnostics, not causal decompositions.

| scenario | RTT coefficient | 1/BW coefficient | R² | residual range ms |
|---|---:|---:|---:|---:|
| pq | 1.02638 | 60.912 | 0.99217 | -6.953…6.741 |
| pq-rpk | 1.02509 | 29.595 | 0.98507 | -8.645…6.917 |
| pq-compact-warm | 1.02721 | 34.242 | 0.99015 | -7.769…6.049 |
| pq-compact-cold | 1.02698 | 60.949 | 0.99023 | -8.062…7.554 |
| pq-mtc-experimental-landmark | 1.02444 | 36.822 | 0.99134 | -7.414…5.846 |
| pq-mtc-experimental-standalone | 1.02085 | 89.331 | 0.99287 | -6.597…7.805 |

## Interpretation

Theoretical serialization values are retained separately in serialization-reference.csv. They are not equated with measured handshake time: TLS flights, framing, TCP segmentation, queueing and process scheduling remain. The measured-difference versus theoretical-difference plot is diagnostic only.

Warm Compact and MTC landmark move trust material out of the handshake. amortization.csv reports TLS bytes + incremental predistributed bytes/H for H=1,10,100,1000,10000. It is an analytical byte model, excludes a distribution protocol and persistent-cache behavior, and is never mixed into measured wall time.

Cold Compact and standalone MTC transmit more authentication material. Their comparison remains architectural; standalone MTC includes CA/cosigner semantics absent from Compact cold and ordinary X.509. Local setup CPU, client CPU, server CPU and total CPU remain separate from serialization.

Validation summary: maximum RTT target error 7.150 ms; maximum directional throughput error 18.08%; zero accepted ping loss, iperf retransmissions and qdisc drops. All 3577 Tukey diagnostic rows are retained. Five campaigns per condition and one Docker host limit generalization.

Machine-readable outputs include bandwidth-summary.csv, bootstrap-comparisons.csv, serialization-reference.csv, break-even-analysis.csv, amortization.csv, interaction-models.csv and network-validation.csv. Plots are under plots/.

Experiment commit: PENDING_COMMIT
