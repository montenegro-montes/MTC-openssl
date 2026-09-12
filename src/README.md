# Laboratory implementation

| Component | Start here | Supporting code |
|---|---|---|
| Integration | `integration/mt_wire.h`, `integration/mt_wire.c` | `mt_bundle.c`, `mt_tls.c`, `patch_openssl.py` |
| Compact | `compact/compact.c` | `prepare.py`, `patch.py`, runtime adapters and component tests |
| MTC experimental | `mtc/core.py`, `mtc/mtc.c` | `tls.c`, `patch.py`, fixture builders, draft references and component tests |
| Profiling | `profiling/profile.h`, `profiling/profile.c` | `metrics.c`, `patch.py`, runtime adapters and component tests |

See the [architecture guide](../docs/architecture.md) for dependencies, test
boundaries and the relationship between implementation and experiments.
