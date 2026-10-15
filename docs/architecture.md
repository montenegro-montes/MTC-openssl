# Repository architecture

The active study compares X.509 with the experimental MTC draft. User commands live in `bin/`; implementations are grouped under `campaigns/` by validation, performance, scaling and network responsibility.

The base image in `docker/base/Dockerfile` provides OpenSSL and the X.509 laboratory. `docker/base/Dockerfile.mtc` adds the MTC patch and native timing instrumentation from `src/mtc/` and `src/profiling/`. The capture image and the network measurement chain derive directly from that MTC image.

Generated fixtures, observations, captures and reports remain under `artifacts/`. Launcher state is kept in `.mt-state/`. Published result snapshots under `results/` are independent evidence and are not reset with the local laboratory.

The prepared functional lab can be checked with Chromium without changing the
Chromium workflow's persistent fixture selection:

```sh
bin/base/mt-lab chromium-test
```

This bounded integration follows `RP HTTP -> MTS1 trusted subtrees -> Chromium
Plants-07 -> MTC verification -> TLS 1.3 -> HTTP`. It uses the exact
`MT_LAB_FIXTURE` and its matching pre-existing validation evidence; it does not
generate or select a replacement fixture.
