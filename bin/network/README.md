# Network campaign launcher

`mt-network` coordinates latency, bandwidth, packet-loss and combined campaigns
for all nine profiles. Every operation that prepares, shows, executes or
analyzes a campaign requires an authentication mode: `single` or `mutual`.

```sh
bin/network/mt-network prepare latency single
bin/network/mt-network run latency single
bin/network/mt-network prepare latency mutual
bin/network/mt-network run latency mutual
```

Mutual mode reuses the N=16 fixtures produced by the mutual-authentication
crossover stage of `bin/cryptographic_scaling/mt-cert-scaling`. Initialization
only records their configured paths; it does not execute that stage.
