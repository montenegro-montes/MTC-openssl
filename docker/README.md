# Docker definitions

Run Docker commands from the repository root and pass the Compose file explicitly:

```sh
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm setup
```

The Compose definitions use `..` as their build context and bind `../artifacts` and `../campaigns`, because paths are resolved relative to this directory.

| Compose file | Purpose |
|---|---|
| `compose.yaml` | Original classic/PQ TLS laboratory |
| `compose.compact.yaml` | Compact Merkle authentication |
| `compose.profile.yaml` | Detailed profiling |
| `compose.mtc.yaml` | Experimental MTC implementation |
| `compose.paper.yaml` | Controlled N=16 campaign image |
| `compose.scaling.yaml` | Tree-population scaling |
| `compose.network-latency.yaml` | Latency-only network campaign |
| `compose.network-bandwidth.yaml` | Bandwidth-limited campaign |
| `compose.network-loss.yaml` | Packet-loss campaign |
| `compose.network-combined.yaml` | Combined representative profiles |

`archive/` contains obsolete definitions retained only for historical inspection. Do not use them for new measurements.
