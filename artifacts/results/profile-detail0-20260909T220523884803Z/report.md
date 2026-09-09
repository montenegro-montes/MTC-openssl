# Exploratory endpoint profiling

Detailed timers: 0. RPK pin is a diagnostic control, not a PKI replacement.

| Scenario | TLS bytes | Client wall ms | Client CPU ms | Server CPU ms | Combined CPU ms |
|---|---:|---:|---:|---:|---:|
| classic | 1215 | 0.791 | 0.503 | 0.276 | 0.773 |
| pq | 9572 | 1.710 | 0.802 | 1.082 | 1.862 |
| classic-mt | 1397 | 0.822 | 0.528 | 0.264 | 0.786 |
| pq-mt | 9754 | 1.539 | 0.804 | 0.887 | 1.671 |
| classic-compact-warm | 1160 | 1.543 | 1.316 | 0.253 | 1.576 |
| classic-compact-cold | 1288 | 1.617 | 1.385 | 0.258 | 1.654 |
| pq-compact-warm | 6281 | 2.147 | 1.423 | 0.761 | 2.188 |
| pq-compact-cold | 9648 | 2.252 | 1.667 | 0.899 | 2.660 |
| classic-rpk | 874 | 2.641 | 2.407 | 0.266 | 2.694 |
| pq-rpk | 5994 | 3.356 | 2.612 | 0.804 | 3.432 |

Components are inclusive/nested; do not sum them. Endpoint CPU sums are not elapsed handshake time.
Warm root signature setup remains outside handshake and inside full client process time. No persistent cache or optimized verifier has been introduced.
