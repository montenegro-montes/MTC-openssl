# Server repeat, November 16, 2026

This is a **new measurement series**. It does not replace the October figure
data or the November 15 Table I data in the parent directory.

## Figures 4 and 5

`figure_4_5_samples.csv` contains 1,500 anonymized measured connections:
100 per displayed profile, client, and arm. `figure_4_5_values.csv` contains
the mean credential-validation time, mean TLS `CertificateVerify` time, and
their per-connection sum for the 15 bars. The source OpenSSL `native.csv` and
`summary.json` are included in `figure_4/`. Chromium's raw CSVs and summaries
remain outside Git because they contain absolute machine paths; their SHA-256
hashes, run IDs, PASS results, and binary identity are in `provenance.json`.

Both figure blocks used `mt-tls-mtc:local` with image ID
`sha256:0bdda1759a3856517a5f0cb5ae2e13e0f58760e93b43b84d5269ef4a24be0883`,
TLS 1.3, `X25519MLKEM768`, and `server.mtc.example.com`. The native and
Chromium timings come from independent blocks.

## Table I

`table_i_values.csv` contains all six arms for each profile, with 100 measured
connections per arm. The four X.509 compression and elision arms come from
`table_i/<profile>/`; the native X.509 reference and both MTC arms come from
`table_i/native/`. All blocks used image
`sha256:8f86ea6caacafcba6dfed963c5c3a0dfa991865ad4fad3755e9159faa4f4c277`.
The ordinary X.509 reference matches the elision block exactly in both byte
directions for all three profiles, and the
hostname, group, X.509 fixtures, and image ID match. `table_i_x509_only.csv`
preserves the earlier partial calculation.

| Signature profile | X.509 D=3 | D=3 + zlib | Intermediate omitted | Omitted + zlib offered | MTC Standalone | MTC Landmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ECDSA P-384 | 4,156 | 3,920 (5.68%) | 3,644 (12.32%) | 3,613 (13.07%) | 3,841 (7.58%) | 3,620 (12.90%) |
| ML-DSA-65 | 17,482 | 17,253 (1.31%) | 11,911 (31.87%) | 11,904 (31.91%) | 15,312 (12.41%) | 8,680 (50.35%) |
| SLH-DSA-192s | 52,464 | 52,319 (0.28%) | 35,858 (31.65%) | 35,863 (31.64%) | 52,193 (0.52%) | 19,687 (62.48%) |

Entries are median bidirectional TLS handshake bytes; percentages use the
ordinary X.509 D=3 median for the same profile. The zlib arms sent
`CompressedCertificate`, including SLH-DSA-192s with the intermediate omitted.
Table I's native and elision rows come from distinct measurement blocks;
their latency samples are not paired.
