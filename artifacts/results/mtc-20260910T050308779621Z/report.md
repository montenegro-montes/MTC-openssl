# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 16.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic-compact-warm | 1161 [1159,1161] | 1.556 | 1.334 | 1.590 |
| classic-compact-cold | 1289 [1289,1290] | 1.589 | 1.363 | 1.622 |
| classic-mtc-experimental-standalone | 1413 [1412,1413] | 0.826 | 0.570 | 0.861 |
| classic-mtc-experimental-landmark | 1261 [1261,1262] | 0.681 | 0.447 | 0.714 |
| pq-compact-warm | 6281 [6281,6281] | 2.285 | 1.419 | 2.334 |
| pq-compact-cold | 9648 [9648,9648] | 1.960 | 1.638 | 2.365 |
| pq-mtc-experimental-standalone | 13010 [13010,13010] | 1.262 | 0.952 | 1.928 |
| pq-mtc-experimental-landmark | 6382 [6382,6382] | 1.091 | 0.520 | 1.135 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
