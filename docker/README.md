# Container definitions

The current image relationships are:

```text
mt-tls-lab:local -> mt-tls-mtc:local -> mt-tls-capture:local
                                      -> mt-tls-network-measurement:local
                                         -> mt-tls-network:local
```

`base/` contains the base, experimental MTC and capture Dockerfiles. `network/` contains the measurement/network layers and the latency, bandwidth, loss and combined Compose definitions. `validation/` contains validation-only definitions. `cryptographic_scaling/` contains certificate-scaling definitions.

Use `bin/base/mt-prepare` for the base/MTC/capture chain and `bin/containers/mt-containers` for current network targets.
