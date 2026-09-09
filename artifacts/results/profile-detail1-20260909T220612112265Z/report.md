# Exploratory endpoint profiling

Detailed timers: 1. RPK pin is a diagnostic control, not a PKI replacement.

| Scenario | TLS bytes | Client wall ms | Client CPU ms | Server CPU ms | Combined CPU ms |
|---|---:|---:|---:|---:|---:|
| classic | 1215 | 0.783 | 0.509 | 0.263 | 0.773 |
| pq | 9572 | 1.436 | 0.786 | 0.820 | 1.559 |
| classic-mt | 1397 | 0.779 | 0.511 | 0.268 | 0.787 |
| pq-mt | 9754 | 1.632 | 0.800 | 0.988 | 1.809 |
| classic-compact-warm | 1160 | 1.518 | 1.315 | 0.245 | 1.557 |
| classic-compact-cold | 1288 | 1.596 | 1.370 | 0.249 | 1.628 |
| pq-compact-warm | 6281 | 2.263 | 1.418 | 0.834 | 2.300 |
| pq-compact-cold | 9648 | 2.041 | 1.614 | 0.755 | 2.430 |
| classic-rpk | 873 | 2.614 | 2.406 | 0.251 | 2.665 |
| pq-rpk | 5994 | 3.408 | 2.629 | 0.835 | 3.459 |

Components are inclusive/nested; do not sum them. Endpoint CPU sums are not elapsed handshake time.
Warm root signature setup remains outside handshake and inside full client process time. No persistent cache or optimized verifier has been introduced.
