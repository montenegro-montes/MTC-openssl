# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 3. Seed: 42. Tree population: 64.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic-compact-warm | 1225 [1224,1225] | 1.539 | 1.316 | 1.569 |
| classic-compact-cold | 1352 [1352,1353] | 1.568 | 1.338 | 1.600 |
| classic-mtc-experimental-standalone | 1478 [1478,1478] | 0.788 | 0.559 | 0.817 |
| classic-mtc-experimental-landmark | 1326 [1325,1326] | 0.752 | 0.495 | 0.779 |
| pq-compact-warm | 6345 [6345,6345] | 2.544 | 1.408 | 2.592 |
| pq-compact-cold | 9712 [9712,9712] | 2.317 | 1.750 | 2.681 |
| pq-mtc-experimental-standalone | 13074 [13074,13074] | 1.068 | 0.889 | 1.524 |
| pq-mtc-experimental-landmark | 6447 [6447,6447] | 1.444 | 0.533 | 1.496 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
