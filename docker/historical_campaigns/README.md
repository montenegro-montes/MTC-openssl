# Historical campaign Docker infrastructure

**Frozen archive.** These definitions retain Compact and the former combined
measurement chain for reproduction. They are excluded from active preparation.

This category contains the network and scaling definitions used by the original
validated campaign group. File contents and Compose project names retain their
original roles.

The active X.509/MTC image chain lives in `docker/base/`. This directory retains
historical Compact, profiling, measurement, scaling and network definitions.
Commands should be run from the repository root using paths such as:

```sh
docker compose -f docker/historical_campaigns/compose.yaml config
docker compose -f docker/historical_campaigns/compose.scaling.yaml config
```

Use `bin/containers/mt-containers` and `bin/historical_campaigns/mt-campaigns` for normal
operation because both managers now resolve these grouped paths.
