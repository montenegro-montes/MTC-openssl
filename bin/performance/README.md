# Performance launchers

`mt-handshake-performance` measures the active X.509 and experimental MTC
handshakes. It provides native timing, packet-capture measurements, mutual
authentication cases and the nine-profile Trust Anchor Retry matrix. Simple and
mutual MTC measurements each include landmark and standalone credentials.
The handshake report presents absolute results for every profile and case. Its
Native and PCAP tables include sample count, mean, sample standard deviation,
median and a 95% Student t confidence interval for the mean; it does not use a
baseline subtraction.

Run it from the repository root:

```bash
bin/performance/mt-handshake-performance
```

Native and PCAP populations can be executed independently for simple or mutual
authentication. `run-single` and `run-mutual` execute Native followed by PCAP
only for their three authentication cases. `run-native-pcap` retains the full
six-case execution.

HTML renderers are centralized under `bin/renders/`.
