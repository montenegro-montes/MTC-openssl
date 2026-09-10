# MTC-experimental: controlled local measurements

Draft: draft-ietf-plants-merkle-tree-certs-05. Rounds: 30. Seed: 42. Tree population: 16.

| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |
|---|---:|---:|---:|---:|
| classic | 1215 [1214,1216] | 0.764 | 0.487 | 0.738 |
| pq | 9572 [9572,9572] | 1.351 | 0.756 | 1.467 |
| classic-mt | 1397 [1396,1398] | 0.796 | 0.502 | 0.761 |
| pq-mt | 9754 [9754,9754] | 1.424 | 0.757 | 1.532 |
| classic-compact-warm | 1160 [1159,1161] | 1.485 | 1.272 | 1.516 |
| classic-compact-cold | 1288 [1287,1289] | 1.550 | 1.331 | 1.582 |
| pq-compact-warm | 6281 [6281,6281] | 2.164 | 1.416 | 2.206 |
| pq-compact-cold | 9648 [9648,9648] | 1.996 | 1.622 | 2.383 |
| classic-mtc-experimental-standalone | 1411 [1410,1412] | 0.766 | 0.531 | 0.789 |
| classic-mtc-experimental-landmark | 1261 [1260,1262] | 0.640 | 0.423 | 0.676 |
| pq-mtc-experimental-standalone | 13010 [13010,13010] | 1.168 | 0.887 | 1.612 |
| pq-mtc-experimental-landmark | 6382 [6382,6382] | 1.390 | 0.510 | 1.432 |

MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.
Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.
Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.
Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.
Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.
