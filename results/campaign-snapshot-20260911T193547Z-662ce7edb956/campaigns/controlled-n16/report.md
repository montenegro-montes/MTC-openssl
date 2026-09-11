# Controlled N=16 campaigns: MTC-experimental and existing TLS controls

**10/10 successful campaigns; 4200 measured handshakes and 700 warmups.** Each campaign recreated servers, used 5 warmup and 30 paired measurement rounds for 14 scenarios, and a distinct seed 42–51. All share one Docker Desktop session. No campaign failed or was repeated.

Baseline commit: `91fd70a7a8de81a9433f364c0f30ea105fcf071f`. MTC remains **MTC-experimental**, targeting draft-ietf-plants-merkle-tree-certs-05. No protocol behavior was changed. An isolated s_client adds setup wall/CPU measurements; source/fixture hashes and original libraries were preserved.

All regression and negative tests passed before campaigns. Two initial launcher failures (missing legacy demo arguments and its success exit code 1) were corrected and archived in preflight-attempts/. They were not protocol failures. The final measurement preflight had 28 handshakes and 14 warmups, excluded from the counts and analysis above.

## Table A — PQ authentication

Entries are **medians of ten campaign medians**, not medians of 300 pooled observations. Times are milliseconds. CPU total is formed per paired connection before campaign aggregation. Ranges, unrounded values and full classic results are retained in CSV.

| Scenario | TLS bytes | Handshake wall ms | Client CPU ms | Server CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|---:|
| pq | 9572 | 1.495750 | 0.767011 | 0.853615 | 1.616312 |
| pq-rpk | 5994 | 3.273760 | 2.474844 | 0.818896 | 3.353323 |
| pq-compact-warm | 6281 | 2.203240 | 1.418281 | 0.804572 | 2.285124 |
| pq-compact-cold | 9648 | 2.098135 | 1.633167 | 0.828834 | 2.492853 |
| pq-mtc-experimental-standalone | 13010 | 1.155875 | 0.897521 | 0.837198 | 1.765303 |
| pq-mtc-experimental-landmark | 6382 | 1.337468 | 0.521125 | 0.843708 | 1.394260 |

## Table B — PQ byte decomposition

Arrows mean **destination minus origin**; percentages use the origin as denominator. These are architectural byte differences, not equal-security substitutions. The four explicit quantities below additionally use the requested sign convention.

| Transition | Difference bytes | Difference % |
|---|---:|---:|
| X509 → RPK | -3578.000000 | -37.379858% |
| RPK → Compact warm | +287.000000 | +4.788121% |
| RPK → MTC landmark | +388.000000 | +6.473140% |
| X509 → Compact warm | -3291.000000 | -34.381529% |
| X509 → MTC landmark | -3190.000000 | -33.326369% |
| Compact warm → MTC landmark | +101.000000 | +1.608024% |

- `X509_overhead_removed = 3578` bytes.
- `compact_layer_overhead = 287` bytes.
- `mtc_landmark_layer_overhead = 388` bytes.
- `compact_vs_mtc_landmark_bytes = -101` bytes.

The X509→RPK contrast removes a certificate/container and changes trust semantics. Compact and MTC landmark add distinct layers. The net Compact/MTC difference combines credential fields, proof encoding and TLS signalling; it does not isolate only ASN.1 overhead.
MTC standalone carries CA authentication **plus one local cosigner**, while the X509 reference has no SCTs or equivalent cosigner. Its larger/smaller byte count must not be interpreted as an equivalent-security comparison.

## Table C — PQ trust distribution

OOB bytes are **local file sizes**, not transmitted TLS bytes: total trust material and (increment beyond common keys/policy). Compact uses a CA PEM plus a binary signed root; MTC uses binary configuration. Setup is before the timed handshake; it includes loading and validation. Validation is the nested signature-operation subset, so **do not add it to setup**.

| Mode | OOB total (increment) bytes | Setup wall / CPU ms | Prior signature validation ms | TLS bytes | Authentication object in TLS, excluding CertificateVerify | Reuse |
|---|---:|---:|---:|---:|---|---|
| pq-compact-warm | 10900 (3399) | 2.584604 / 2.325750 | 0.203104 | 6281 | credential 61; encoded proof 173; root absent | root/landmark validated every process |
| pq-compact-cold | 7501 (0) | 2.211844 / 2.083396 | — | 9648 | signed root payload 3399; credential/proof also sent | new process; signatures verified during TLS |
| pq-mtc-experimental-landmark | 10772 (6773) | 1.238260 / 1.081240 | 0.351083 | 6382 | MTCProof 114; no subtree signatures | root/landmark validated every process |
| pq-mtc-experimental-standalone | 3999 (0) | 0.842927 / 0.714958 | 0.000000 | 13010 | MTCProof 6746, including CA 3309 + cosigner 3309 signature bytes | new process; signatures verified during TLS |

For PQ Compact, the signed root payload is 3399 bytes. The cold–warm TLS difference is 3367 bytes because the warm ClientHello additionally carries a 32-byte root identifier. A file/payload size must not be substituted for the net transport difference.

No persistent cache was implemented or measured. Compact cold root validation is inside the handshake and not separately timed; the missing prior-validation value is not zero cost. MTC standalone configures trusted keys before TLS and checks subtree signatures inside TLS. Its prior checkpoint-validation value is zero because no checkpoint is used. All modes retain native TLS CertificateVerify and Finished.

## Table D — Independent campaign stability

Ranges are min/max of the ten **campaign medians**. CV is sample standard deviation divided by their mean, in percent. Rank is among the six primary PQ scenarios by campaign median wall time; ties receive average ranks.

| Scenario | Wall median range ms | Wall CV % | Client CPU median range ms | Total CPU CV % | Wall rank range |
|---|---:|---:|---:|---:|---:|
| pq | 1.372833–1.731771 | 6.585208 | 0.750293–0.791647 | 6.120195 | 2–3 |
| pq-rpk | 3.097459–3.580520 | 4.174538 | 2.438000–2.493709 | 4.266629 | 6–6 |
| pq-compact-warm | 2.079124–2.282208 | 2.907396 | 1.407313–1.449813 | 2.934510 | 4–5 |
| pq-compact-cold | 1.993604–2.183750 | 3.162491 | 1.624312–1.658083 | 2.828232 | 4–5 |
| pq-mtc-experimental-standalone | 1.107937–1.278896 | 4.504129 | 0.881625–0.905250 | 3.894027 | 1–1 |
| pq-mtc-experimental-landmark | 1.132166–1.489791 | 8.485148 | 0.510125–0.535146 | 8.226910 | 2–3 |

### Timing interpretation

For each contrast, the effect is first the median of round-paired differences within a campaign. The final estimate is the median of ten such effects. Confidence intervals resample these **ten campaign effects**, 10000 times (seed 20260910), using percentile intervals. No null-hypothesis tests were added. Within-campaign bootstrap files remain secondary.

A contrast is labelled sign-unstable when at least two campaigns are positive and at least two negative. An interval containing zero is uncertain even if fewer sign changes occur. The following primary PQ contrasts show the observed sign counts and campaign-level intervals; small differences are not promoted to universal speed claims.

- pq-rpk vs pq: paired effect +1.848688 ms; 95% interval [+1.791084, +1.893604]; negative/positive/zero campaigns 0/10/0; **direction supported within these campaigns**.
- pq-compact-warm vs pq: paired effect +0.789333 ms; 95% interval [+0.603229, +0.822990]; negative/positive/zero campaigns 0/10/0; **direction supported within these campaigns**.
- pq-compact-cold vs pq: paired effect +0.627385 ms; 95% interval [+0.541854, +0.706647]; negative/positive/zero campaigns 0/10/0; **direction supported within these campaigns**.
- pq-mtc-experimental-standalone vs pq: paired effect -0.222208 ms; 95% interval [-0.288011, -0.180864]; negative/positive/zero campaigns 10/0/0; **direction supported within these campaigns**.
- pq-mtc-experimental-landmark vs pq: paired effect -0.185885 ms; 95% interval [-0.251020, -0.124416]; negative/positive/zero campaigns 10/0/0; **direction supported within these campaigns**.
- pq-compact-warm vs pq-rpk: paired effect -1.084906 ms; 95% interval [-1.143604, -0.952792]; negative/positive/zero campaigns 10/0/0; **direction supported within these campaigns**.
- pq-mtc-experimental-landmark vs pq-rpk: paired effect -1.963271 ms; 95% interval [-2.027250, -1.870376]; negative/positive/zero campaigns 10/0/0; **direction supported within these campaigns**.
- pq-compact-warm vs pq-mtc-experimental-landmark: paired effect +0.895906 ms; 95% interval [+0.826948, +0.990104]; negative/positive/zero campaigns 0/10/0; **direction supported within these campaigns**.
- pq-compact-cold vs pq-mtc-experimental-standalone: paired effect +0.828021 ms; 95% interval [+0.785000, +0.874646]; negative/positive/zero campaigns 0/10/0; **direction supported within these campaigns**.

**Server CPU contrasts are not stable:** 9/9 primary PQ contrasts change sign frequently or have an interval containing zero. Do not claim server-CPU improvements from the Table A point estimates.
- Full client-process/HTTP latency, pq-mtc-experimental-standalone vs pq: -0.335302 ms, interval [-0.477542, -0.089021], signs negative/positive 8/2; **unstable: both signs in at least 2/10 campaigns**, even if the percentile interval is directional.
The ranking of separate campaign medians also changes for X509 versus MTC landmark and Compact warm versus cold (Table D). A median of round-paired differences is not the difference of two separate medians; those rank changes do not contradict the signs of the paired estimates.
Standalone MTC has lower timed-handshake wall values but higher client CPU than X509 in this experiment. These windows measure different aspects of scheduling, setup and verification; they do not establish an overall algorithmic speedup.

Outlier diagnostics use within-campaign Tukey 1.5-IQR fences and retain every observation. Descriptive correlations of campaign median wall time with client/total CPU are stored separately; wall time also includes waiting and is not interchangeable with CPU.
- pq: 13/300 wall observations flagged; largest wall observation 27.571416 ms; wall/total-CPU correlation across campaign medians 0.976458.
- pq-rpk: 18/300 wall observations flagged; largest wall observation 23.192458 ms; wall/total-CPU correlation across campaign medians 0.995511.
- pq-compact-warm: 15/300 wall observations flagged; largest wall observation 7.154458 ms; wall/total-CPU correlation across campaign medians 0.956222.
- pq-compact-cold: 24/300 wall observations flagged; largest wall observation 5.054584 ms; wall/total-CPU correlation across campaign medians 0.989001.
- pq-mtc-experimental-standalone: 23/300 wall observations flagged; largest wall observation 3.371125 ms; wall/total-CPU correlation across campaign medians 0.776028.
- pq-mtc-experimental-landmark: 15/300 wall observations flagged; largest wall observation 29.338333 ms; wall/total-CPU correlation across campaign medians 0.995740.

The previous component profile located most compact verifier cost in SPKI encoding, with much smaller Merkle-proof processing. This campaign does not reprofile components and does not attribute the entire Compact timing difference to Merkle.

### Decision about scaling

All primary PQ wall contrasts have a campaign-level directional interval in this run. Byte results support proceeding to a separate scaling study. However, server-CPU differences and standalone MTC full-process latency are not stable; any scaling study must retain campaign-level replication and avoid claims of those improvements. This is not evidence of portability to other machines/networks or a persistent-cache benefit.
**No tree-size scaling experiment was run in this task.** All ten campaigns used the original N=16 population. The shared Docker session, resource contention/thermal state not independently reset, local cosigner, non-equivalent trust models and new-client-per-sample design limit generalization.

### Files and reproduction

- `all-samples.csv`: 4200 observations with campaign, seed, paired round and order; `all-warmups.csv`: 700 warmups.
- `campaign-summary.csv`: distributions of campaign medians; `scenario-summary.csv`: median/range/CV across campaigns.
- `paired-comparisons.csv`: campaign-level paired effects; `bootstrap-comparisons.csv`: final campaign-level intervals.
- `byte-decomposition.csv`, `scenario-ranks.csv`, `timing-diagnostics.csv`, `outliers.csv`: decomposition and stability diagnostics.
- `campaign-01/` through `campaign-10/`: original samples, logs, endpoint telemetry, environment, and secondary bootstrap results.
- `metadata.json`, `environment.json`, `tests.log`, `tests-status.json`, source/fixture hash inventories and `measurement-provenance.json`: reproducibility evidence.
- Measurement implementation and host orchestration/analysis are stored in `source/`; the saved protocol commit is unchanged.
