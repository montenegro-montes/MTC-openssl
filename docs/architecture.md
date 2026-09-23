# Repository architecture

The active study compares X.509 with the experimental MTC draft. User commands live in `bin/`; implementations are grouped under `campaigns/` by validation, performance, scaling and network responsibility.

The base image in `docker/base/Dockerfile` provides OpenSSL and the X.509 laboratory. `docker/base/Dockerfile.mtc` adds the MTC patch and native timing instrumentation from `src/mtc/` and `src/profiling/`. The capture image and the network measurement chain derive directly from that MTC image.

Generated fixtures, observations, captures and reports remain under `artifacts/`. Launcher state is kept in `.mt-state/`. Published result snapshots under `results/` are independent evidence and are not reset with the local laboratory.
