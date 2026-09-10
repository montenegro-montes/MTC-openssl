# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 16.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic | 1216 [1215,1216] | 0.781 | 0.519 | 0.811 |
| pq | 9572 [9572,9572] | 1.533 | 0.862 | 1.674 |
| classic-mt | 1397 [1396,1397] | 0.804 | 0.518 | 0.795 |
| pq-mt | 9754 [9754,9754] | 1.749 | 0.891 | 1.859 |
| classic-compact-warm | 1159 [1159,1160] | 1.600 | 1.359 | 1.632 |
| classic-compact-cold | 1288 [1288,1288] | 1.568 | 1.350 | 1.599 |
| pq-compact-warm | 6281 [6281,6281] | 2.327 | 1.451 | 2.377 |
| pq-compact-cold | 9648 [9648,9648] | 2.669 | 1.625 | 3.043 |
| classic-mtc-experimental-standalone | 1412 [1412,1412] | 0.780 | 0.551 | 0.818 |
| classic-mtc-experimental-landmark | 1261 [1260,1261] | 0.685 | 0.442 | 0.722 |
| pq-mtc-experimental-standalone | 13010 [13010,13010] | 1.349 | 1.113 | 2.015 |
| pq-mtc-experimental-landmark | 6382 [6382,6382] | 1.475 | 0.537 | 1.528 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
