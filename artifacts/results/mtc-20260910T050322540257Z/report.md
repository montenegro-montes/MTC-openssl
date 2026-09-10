# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 1024.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic-compact-warm | 1352 [1352,1353] | 1.470 | 1.262 | 1.502 |
| classic-compact-cold | 1481 [1481,1481] | 1.578 | 1.360 | 1.609 |
| classic-mtc-experimental-standalone | 1605 [1605,1606] | 0.743 | 0.535 | 0.777 |
| classic-mtc-experimental-landmark | 1454 [1454,1455] | 0.649 | 0.426 | 0.681 |
| pq-compact-warm | 6473 [6473,6473] | 1.908 | 1.443 | 1.975 |
| pq-compact-cold | 9840 [9840,9840] | 2.405 | 1.611 | 2.776 |
| pq-mtc-experimental-standalone | 13202 [13202,13202] | 1.191 | 0.959 | 1.869 |
| pq-mtc-experimental-landmark | 6576 [6576,6576] | 1.582 | 0.482 | 1.627 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
