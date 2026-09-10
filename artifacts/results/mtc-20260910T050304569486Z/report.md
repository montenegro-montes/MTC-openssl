# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 4.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic-compact-warm | 1095 [1095,1096] | 1.474 | 1.268 | 1.505 |
| classic-compact-cold | 1226 [1226,1226] | 1.610 | 1.373 | 1.642 |
| classic-mtc-experimental-standalone | 1348 [1348,1348] | 0.715 | 0.515 | 0.769 |
| classic-mtc-experimental-landmark | 1197 [1196,1198] | 0.668 | 0.427 | 0.705 |
| pq-compact-warm | 6217 [6217,6217] | 2.295 | 1.432 | 2.330 |
| pq-compact-cold | 9584 [9584,9584] | 2.138 | 1.662 | 2.517 |
| pq-mtc-experimental-standalone | 12946 [12946,12946] | 1.152 | 0.894 | 1.812 |
| pq-mtc-experimental-landmark | 6318 [6318,6318] | 1.112 | 0.520 | 1.168 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
