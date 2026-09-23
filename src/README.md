# Laboratory implementation

| Component | Start here | Supporting code |
|---|---|---|
| Integration | `integration/mt_wire.h`, `integration/mt_wire.c` | `mt_bundle.c`, `mt_tls.c`, `patch_openssl.py` |
| MTC experimental | `mtc/core.py`, `mtc/mtc.c` | `tls.c`, `patch.py`, fixture builders, draft references and component tests |
| Native timing | `profiling/native_metrics.h`, `profiling/native_metrics.c` | `patch_native_metrics.py` |

See the [architecture guide](../docs/architecture.md) for active dependencies and experiment boundaries.
