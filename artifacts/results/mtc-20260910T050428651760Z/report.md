# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 30. Seed: 42. Tree population: 16.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic | 1215 [1214,1216] | 0.767 | 0.493 | 0.744 |
| pq | 9572 [9572,9572] | 1.660 | 0.763 | 1.849 |
| classic-rpk | 873 [871,874] | 2.555 | 2.346 | 2.604 |
| pq-rpk | 5994 [5994,5994] | 3.386 | 2.521 | 3.443 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
