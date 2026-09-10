# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 256.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic-compact-warm | 1288 [1287,1288] | 1.593 | 1.359 | 1.630 |
| classic-compact-cold | 1416 [1416,1417] | 1.605 | 1.360 | 1.632 |
| classic-mtc-experimental-standalone | 1540 [1539,1541] | 0.782 | 0.564 | 0.818 |
| classic-mtc-experimental-landmark | 1390 [1390,1390] | 0.744 | 0.469 | 0.775 |
| pq-compact-warm | 6409 [6409,6409] | 2.586 | 1.544 | 2.630 |
| pq-compact-cold | 9776 [9776,9776] | 2.077 | 1.713 | 2.475 |
| pq-mtc-experimental-standalone | 13138 [13138,13138] | 1.315 | 0.941 | 2.006 |
| pq-mtc-experimental-landmark | 6511 [6511,6511] | 1.752 | 0.662 | 1.787 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
