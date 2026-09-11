# Controlled Merkle population scaling

## Scope and validation

Evaluated N = 1, 4, 16, 64, 256, 1024. Thirty primary campaigns (five per N) plus thirty separate detail campaigns. Primary: 10,800 measured handshakes + 1,800 warmups; detail: 3,600 + 600. Separate preflight: 96 measured checks + 48 warmups, excluded from inference. No failed/repeated campaign or individual-sample exclusion. All outliers retained. Post-campaign regression status is recorded in tests-after-status.json; preservation status in preservation-after.json. Both gates passed; see the final-gates section.

TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only authentication, no tickets/resumption. PQ is ML-DSA-65 authentication, not a post-quantum key exchange. The exact N=16 image and native instrumentation are unchanged. New fixture metadata supplies actual server SPKI DER length. New host orchestration and a separate detail collector do not modify native authentication or encodings. The primary /opt/paper/measure.py is unchanged.

One 1,024-identity population per family, with prefix N. Identity zero retains the original server key/certificate, DNS name and validity. Additional identities share the server validity interval and fixed issuance policy; keys 1–15 are reused, other keys generated once. MTC CA and local cosigner keys are reused across all N. MTC log serial range changes with N; Compact root validity remains fixed. The surrounding N=16 population is newly issued under this controlled policy, so previous N=16 handshakes are not pooled with these campaigns.

## Statistical design

At each N, seeds are 1000+N, 2000+N, 3000+N, 4000+N, 5000+N. Each campaign has five randomized warmup rounds and thirty randomized measured rounds. X.509 and RPK are remeasured within each campaign to retain round pairing, although their credential inputs do not depend on N. Both classic and PQ families have six primary scenarios; detail campaigns have the four PQ Merkle scenarios. Servers are recreated between campaigns; all sixty campaigns retain the same Docker bridge and resources.

Scenario estimates are medians of five campaign medians. Effects are first the median of thirty round-paired differences within each campaign, then the median of five campaign effects. Percentile 95% intervals use 10,000 resamples of five campaigns at fixed N (seed 20260910). With only five campaigns, intervals are coarse and do not establish performance on other hosts. No handshake-level bootstrap is used for final inference. Per-campaign files inherited from the driver contain older within-campaign summaries; they are secondary and are not used for final inference. No bootstrap is used for bytes and no null-hypothesis tests are performed.

N values were executed in ascending order, followed by a separate detail phase. Time trends across N can include host/time drift; no causal CPU complexity claim or forced timing regression is made. PROFILE_DETAIL=1 activates existing nested timers and must not be pooled with PROFILE_DETAIL=0.

## Table 1 — PQ TLS handshake bytes

| N | X.509 | RPK | Compact warm | MTC landmark | Compact cold | MTC standalone |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 9572 | 5994 | 6153 | 6286 | 9520 | 12914 |
| 4 | 9572 | 5994 | 6217 | 6318 | 9584 | 12946 |
| 16 | 9572 | 5994 | 6281 | 6382 | 9648 | 13010 |
| 64 | 9572 | 5994 | 6345 | 6447 | 9712 | 13074 |
| 256 | 9572 | 5994 | 6409 | 6511 | 9776 | 13138 |
| 1024 | 9572 | 5994 | 6473 | 6576 | 9840 | 13202 |

PQ observed min/max and invariance are recorded in scaling-summary.csv. TLS bytes are BIO handshake bytes, excluding IP/TCP headers, HTTP and retransmissions.

## Table 2 — PQ overhead over RPK

| N | Compact − RPK (B) | MTC landmark − RPK (B) | Compact − MTC (B) | Compact − MTC (%) |
| --- | --- | --- | --- | --- |
| 1 | 159 | 292 | -133 | -2.116 |
| 4 | 223 | 324 | -101 | -1.599 |
| 16 | 287 | 388 | -101 | -1.583 |
| 64 | 351 | 453 | -102 | -1.582 |
| 256 | 415 | 517 | -102 | -1.567 |
| 1024 | 479 | 582 | -103 | -1.566 |

All requested X.509/RPK differences and percentages, including cold/standalone, are in byte-overhead.csv.

## Table 3 — primary PQ handshake wall time (ms)

| N | X.509 | RPK | Compact warm | MTC landmark | Compact cold | MTC standalone |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1.443 | 3.303 | 2.253 | 1.389 | 2.130 | 1.225 |
| 4 | 1.399 | 3.252 | 2.168 | 1.347 | 1.990 | 1.160 |
| 16 | 1.518 | 3.359 | 2.248 | 1.319 | 2.146 | 1.266 |
| 64 | 1.576 | 3.247 | 2.276 | 1.246 | 2.159 | 1.202 |
| 256 | 1.637 | 3.587 | 2.436 | 1.425 | 2.241 | 1.287 |
| 1024 | 1.444 | 3.309 | 2.311 | 1.481 | 2.197 | 1.181 |

Client/server/total CPU and full-process wall time are in timing-table.csv. All campaign medians and observed ranges are in campaign-summary.csv and scaling-summary.csv. Paired effects, ranges, intervals and sign stability are in bootstrap-comparisons.csv.

## Classic family — TLS median [observed min, max]

| N | X.509 | RPK | Compact warm | MTC landmark | Compact cold | MTC standalone |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1215 [1214, 1216] | 873 [872, 874] | 1032 [1030, 1033] | 1165 [1163, 1166] | 1161 [1160, 1162] | 1316 [1314, 1317] |
| 4 | 1215 [1214, 1216] | 873 [871, 874] | 1096 [1094, 1097] | 1197 [1195, 1198] | 1226 [1225, 1227] | 1346 [1345, 1347] |
| 16 | 1215 [1214, 1216] | 873 [872, 874] | 1160 [1159, 1161] | 1261 [1260, 1262] | 1290 [1288, 1291] | 1414 [1413, 1415] |
| 64 | 1215 [1213, 1216] | 873 [872, 874] | 1224 [1223, 1225] | 1326 [1324, 1327] | 1353 [1352, 1354] | 1477 [1475, 1478] |
| 256 | 1215 [1214, 1216] | 873 [872, 874] | 1288 [1286, 1289] | 1390 [1388, 1391] | 1417 [1416, 1418] | 1542 [1540, 1543] |
| 1024 | 1215 [1214, 1216] | 873 [872, 874] | 1352 [1351, 1353] | 1455 [1454, 1456] | 1482 [1481, 1483] | 1604 [1603, 1605] |

ECDSA CertificateVerify signatures vary in DER length per handshake. Root/cosigner signatures are serialized once per immutable fixture, so their lengths may vary across N; observed classic medians and min/max are retained.

## Explicit answers to the scientific questions

1. **Compact proof size:** actual MTP1 = 45 fixed bytes + 32 bytes per sibling. Observed lengths are N=1: 45 B, N=4: 109 B, N=16: 173 B, N=64: 237 B, N=256: 301 B, N=1024: 365 B. Each two-level N step adds 64 proof bytes. Its full credential also includes identity, validity, SPKI binding and framing.

2. **MTC landmark certificate size:** N=1: 2245 B, N=4: 2277 B, N=16: 2341 B, N=64: 2406 B, N=256: 2470 B, N=1024: 2535 B. MTCProof has 18 fixed bytes plus its path; the covering subtree has log2(N)−1 siblings for N≥4, versus zero for N=1. DER length-boundary changes affect the complete certificate.

3. **The N=16 difference is not universally constant:** Compact warm minus MTC landmark is -133 B at N=1, -101 B at N=4, -101 B at N=16, -102 B at N=64, -102 B at N=256, -103 B at N=1024.

4. **Tree-dependent coefficients:** both raw paths cost 32 B per additional level once N≥4. MTC uses one fewer level due to its covering-subtree structure; this changes an offset, not the per-level hash cost. Full DER/TLS increments can include length framing. size-increments.csv contains actual increments; size-slopes.csv provides descriptive slopes, intercepts, R² and residuals for all N and N≥4 separately. N=1 has no sibling hashes and only one covering subtree; retain it as a corner-case baseline.

5. **pq-compact-warm vs PQ X.509:** no evaluated N loses its byte advantage over PQ X.509. No precise unevaluated crossover is extrapolated.

6. **pq-mtc-experimental-landmark vs PQ X.509:** no evaluated N loses its byte advantage over PQ X.509. No precise unevaluated crossover is extrapolated.

7. **Classic family:** classic-compact-warm: first evaluated median crossover N=64; classic-mtc-experimental-landmark: first evaluated median crossover N=16. The table retains signature-size ranges; an evaluated crossing does not locate the exact threshold between sampled N.

8. **Predistributed material:** N=1: PQ Compact root 3399 B; MTC landmark file 10728 B (increment over authority 6729 B); N=4: PQ Compact root 3399 B; MTC landmark file 10772 B (increment over authority 6773 B); N=16: PQ Compact root 3399 B; MTC landmark file 10772 B (increment over authority 6773 B); N=64: PQ Compact root 3399 B; MTC landmark file 10772 B (increment over authority 6773 B); N=256: PQ Compact root 3399 B; MTC landmark file 10772 B (increment over authority 6773 B); N=1024: PQ Compact root 3399 B; MTC landmark file 10772 B (increment over authority 6773 B). Full setup CPU/wall and nested validation wall are measured for every new client process. MTC authority keys and checkpoint/subtrees are separately accounted in structural-sizes.csv.

9. **Amortization:** amortization.csv applies TLS + trust/H for H=1,10,100,1000,10000. The main stored-material model uses the Compact signed root versus the whole MTC landmark file (including its embedded authority keys); a second column subtracts the MTC authority base for an incremental-trust comparison. Compact CA provisioning is pre-existing. The model excludes distribution headers, retransmissions, storage, cache misses, updates, revocation, failed distribution and the act of trust-anchor provisioning. This is an analytical byte model, not measured persistent cache reuse. Setup/validation repeats per new process and is not divided by H as a measured timing result.

10. **pq-compact-warm proof CPU, separate detail phase:** N=1: 1.979 µs [1.792, 2.083], N=4: 2.562 µs [2.521, 2.917], N=16: 3.145 µs [3.105, 3.291], N=64: 3.667 µs [3.541, 4.000], N=256: 4.271 µs [4.229, 4.438], N=1024: 4.875 µs [4.771, 4.979]. These are campaign medians/ranges; no linear timing model is forced.

Observed endpoint change N=1→1024: 2.896 µs (146.3% of the N=1 proof CPU median). This is an absolute/relative descriptive effect, not a paired cross-N inference; see all intermediate campaign ranges before attributing it to depth.

10. **pq-compact-cold proof CPU, separate detail phase:** N=1: 2.021 µs [1.895, 2.250], N=4: 2.667 µs [2.583, 2.812], N=16: 3.145 µs [3.042, 3.271], N=64: 3.833 µs [3.771, 4.229], N=256: 4.438 µs [4.333, 4.500], N=1024: 4.979 µs [4.896, 5.062]. These are campaign medians/ranges; no linear timing model is forced.

Observed endpoint change N=1→1024: 2.958 µs (146.4% of the N=1 proof CPU median). This is an absolute/relative descriptive effect, not a paired cross-N inference; see all intermediate campaign ranges before attributing it to depth.

**MTC proof-only CPU is unavailable:** existing MTC diagnostics expose aggregate authentication wall time, while generic peer_auth is inclusive. There are no isolated MTC inclusion/subtree-signature/cosignature CPU timers in the frozen binary. Their missing values are not zeros, and no MTC proof-only CPU slope is claimed.

11. **SPKI versus Merkle:** N=1: SPKI encode 0.962 ms / proof 0.002 ms; N=4: SPKI encode 0.959 ms / proof 0.003 ms; N=16: SPKI encode 0.965 ms / proof 0.003 ms; N=64: SPKI encode 0.960 ms / proof 0.004 ms; N=256: SPKI encode 0.969 ms / proof 0.004 ms; N=1024: SPKI encode 0.968 ms / proof 0.005 ms. Compare these separate nested categories; do not sum them with inclusive credential_total or handshake CPU. component-scaling.csv retains spki_hash, credential_total and all other available categories.

SPKI encoding remains larger than Merkle verification at every evaluated N in the separate detail measurements.

12. **MTC landmark timing vs X.509:** N=1: paired -0.116 ms, 95% CI [-0.350, -0.091], direction supported in these campaigns; N=4: paired -0.142 ms, 95% CI [-0.180, -0.047], direction supported in these campaigns; N=16: paired -0.155 ms, 95% CI [-0.443, -0.071], direction supported in these campaigns; N=64: paired -0.221 ms, 95% CI [-0.393, -0.202], direction supported in these campaigns; N=256: paired -0.209 ms, 95% CI [-0.507, -0.152], direction supported in these campaigns; N=1024: paired -0.081 ms, 95% CI [-0.227, 0.140], uncertain: interval includes zero. Server CPU and full-process latency must be judged separately; lower timed wall does not automatically imply lower CPU.

13. **Measurements versus models:** serialized sizes, TLS traffic, setup and handshake timers are measurements. log2(N), 32·ceil(log2(N)), serialized-size fits and TLS+trust/H are reference calculations/descriptive analytical models. No exact unevaluated crossover, persistent reuse, CPU complexity proof or protocol-equivalent security saving is claimed.

## Architectural interpretation

Compact warm vs MTC landmark compares different designs. MTC retains DER TBSCertificate, richer X.509 fields/leaf validation, log entries, checkpoints and a CA plus local cosigner model. Compact binds SPKI, DNS and validity through its smaller credential and root. MTC landmark depends on authenticated out-of-band checkpoints/subtrees. MTC here is experimental draft-05, uses a private exact-ID TLS extension and limited direct-CA/leaf PKIX validation; there is no public transparency log or independent cosigner deployment. Smaller encoding alone does not establish superiority.

**Compact cold vs MTC standalone is an architectural comparison, not security-equivalent savings.** MTC standalone carries CA and cosigner subtree signatures. X.509 baseline has no SCTs. Their byte and timing differences cannot be attributed solely to Merkle algorithms.

## Timing stability and limitations

- handshake_wall_ms: 53/54 PQ contrasts have directionally supported campaign intervals; 1 are uncertain/unstable. Full details retain signs and ranges.
- handshake_client_cpu_ms: 54/54 PQ contrasts have directionally supported campaign intervals; 0 are uncertain/unstable. Full details retain signs and ranges.
- handshake_server_cpu_ms: 2/54 PQ contrasts have directionally supported campaign intervals; 52 are uncertain/unstable. Full details retain signs and ranges.
- handshake_total_cpu_ms: 48/54 PQ contrasts have directionally supported campaign intervals; 6 are uncertain/unstable. Full details retain signs and ranges.
- client_process_http_wall_ms: 46/54 PQ contrasts have directionally supported campaign intervals; 8 are uncertain/unstable. Full details retain signs and ranges.

All outliers remain in every summary. Host scheduling, process launch, CPU frequency and fixed N execution order limit attribution of timing trends. Five campaigns are a modest replication count. The unmeasured isolated MTC proof CPU prevents a complete answer to the requested two-scheme CPU-complexity comparison. Do not claim that part is validated.

## Figures and machine-readable data

plots/ contains five requested publication figures in PDF, SVG and PNG, plus proof-size and Compact proof-CPU figures. Timing figures show the five campaign medians as observations plus their median, without bootstrap error bars or fitted trend claims. MTC proof-only CPU is explicitly unavailable. Figure 2 uses TLS bytes minus RPK TLS bytes, not raw credential DER subtraction. All values come from saved CSV files.

Required tables: tls-bytes-table.csv, byte-overhead.csv, timing-table.csv. Reproducibility: metadata.json, environment.json, images-before.json, fixture inventories, generation.log, tests.log, tests-after.log, source snapshot and campaign endpoint logs. Private keys remain solely in protected fixture storage; result/source snapshots contain hashes, not private key contents.

## PQ warm trust and measured setup

| N | Compact root B | MTC landmark file B | Compact setup wall ms | MTC setup wall ms | Compact setup CPU ms | MTC setup CPU ms |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3399 | 10728 | 2.593 | 1.216 | 2.339 | 1.076 |
| 4 | 3399 | 10772 | 2.558 | 1.204 | 2.316 | 1.072 |
| 16 | 3399 | 10772 | 2.559 | 1.234 | 2.335 | 1.079 |
| 64 | 3399 | 10772 | 2.566 | 1.241 | 2.331 | 1.075 |
| 256 | 3399 | 10772 | 2.659 | 1.268 | 2.379 | 1.095 |
| 1024 | 3399 | 10772 | 2.587 | 1.238 | 2.334 | 1.099 |

Setup is outside the handshake window. Warm root/checkpoint validation is nested within it and repeated per process. Architectural paired setup effects and intervals are in bootstrap-comparisons.csv. root-signature-setup.csv also retains the original root signature wall/CPU diagnostics.

## Analytical PQ amortization — stored trust model

| N | Scheme | H=1 | H=10 | H=100 | H=1,000 | H=10,000 |
| --- | --- | --- | --- | --- | --- | --- |
| 16 | pq-compact-warm | 9680.000 | 6620.900 | 6314.990 | 6284.399 | 6281.340 |
| 16 | pq-mtc-experimental-landmark | 17154.000 | 7459.200 | 6489.720 | 6392.772 | 6383.077 |
| 256 | pq-compact-warm | 9808.000 | 6748.900 | 6442.990 | 6412.399 | 6409.340 |
| 256 | pq-mtc-experimental-landmark | 17283.000 | 7588.200 | 6618.720 | 6521.772 | 6512.077 |
| 1024 | pq-compact-warm | 9872.000 | 6812.900 | 6506.990 | 6476.399 | 6473.340 |
| 1024 | pq-mtc-experimental-landmark | 17348.000 | 7653.200 | 6683.720 | 6586.772 | 6577.077 |

All entries are bytes per connection from the analytical formula. The incremental model excluding MTC authority bytes is retained alongside this model in amortization.csv. No timing amortization is inferred.

## Serialized fixed/tree decomposition

fixed-and-tree-components.csv subtracts the actual sibling-hash payload from each actual serialized object. The remainder includes fixed fields, signatures and framing; it may change at DER boundaries or with ECDSA signature lengths. It is not assumed constant. size-increments.csv separately records raw-proof, complete-object and observed TLS increments for every N step.

## Post-hoc fixed-baseline timing diagnostic

The diagnostic identified 2 markedly slower primary campaigns. This diagnostic retains every observation and is not an exclusion rule. The unchanged RPK baseline also slows, which is evidence of a campaign/environment effect rather than an N-dependent Merkle cost. The cause was not instrumented; both wall and CPU rise, so this must not be attributed only to scheduling waits.

| Campaign | PQ RPK wall ms | PQ RPK client CPU ms | Wall / same-N median | Client CPU / same-N median |
| --- | --- | --- | --- | --- |
| primary-n256-c5 | 12.017 | 8.328 | 3.350 | 3.194 |
| primary-n1024-c1 | 9.782 | 7.687 | 2.956 | 3.110 |

baseline-diagnostics.csv contains all fixed-baseline campaign values, not just these observations (>2× same-N campaign median, a post-hoc descriptive flag). Paired effects and their campaign intervals remain reported with these campaigns included. Absolute handshake/CPU scaling curves are provisional for causal interpretation and should not support an algorithmic speedup or complexity claim in the paper. Serialized-size and traffic findings are unaffected by this timing variation.

At N=1024, the difference of scenario wall medians for MTC landmark versus X.509 is positive while the median round-paired campaign effect is negative with an interval crossing zero. They are different estimators; no directional improvement is established there.

## Final gates

The complete positive/negative/regression gate passed both before and after all campaigns. All recorded previous source/input/result hashes and new fixture hashes match. Authentication/control validation passed for every campaign; no campaigns were excluded. These gates validate execution and preservation, not the absent MTC proof-only CPU metric or the environmental attribution of noisy timing campaigns.
