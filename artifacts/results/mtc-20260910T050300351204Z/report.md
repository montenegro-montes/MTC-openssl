# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 1.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic-compact-warm | 1032 [1032,1032] | 1.535 | 1.331 | 1.569 |
| classic-compact-cold | 1162 [1161,1162] | 1.627 | 1.376 | 1.658 |
| classic-mtc-experimental-standalone | 1318 [1318,1319] | 0.792 | 0.557 | 0.826 |
| classic-mtc-experimental-landmark | 1165 [1164,1166] | 0.684 | 0.449 | 0.733 |
| pq-compact-warm | 6153 [6153,6153] | 1.833 | 1.408 | 1.881 |
| pq-compact-cold | 9520 [9520,9520] | 2.092 | 1.610 | 2.533 |
| pq-mtc-experimental-standalone | 12914 [12914,12914] | 1.123 | 0.885 | 1.766 |
| pq-mtc-experimental-landmark | 6286 [6286,6286] | 1.252 | 0.519 | 1.300 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
