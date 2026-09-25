# Isolated MTC endpoint profiling

The crossover-N/boundary runners require `PROFILE_METRICS` on both endpoints,
not only the base image's client `NATIVE_METRICS`. Build explicitly from the
repository root:

```sh
bin/base/mt-prepare run 4
```

This derives from the existing `mt-tls-mtc:local` image, recompiles its OpenSSL
library/application, and preserves the base image and fixtures. It does not run
TLS or campaigns. An alternative immutable base can be passed with
`--build-arg MTC_BASE_IMAGE=sha256:...`. The crossover boundary runner defaults to
the new tag, accepts `--image`, or reads `MTC_PROFILE_IMAGE`; it resolves the image
to an immutable ID before fixture generation and measurement.

`profile.c`, `profile.h` and `metrics.c` recover the measurement implementation
from commit `06e1cd4b7^` (before the historical-code removal). The metrics include
handshake wall/process-CPU time, BIO byte counters, handshake-message lengths,
client random, resumption flag and timed TLS components. Certificate-message
lengths include their handshake framing and are compared at both endpoints.
Server records are stored by client random. Component times are nested/inclusive;
they must not be summed. Process CPU time is not thread-specific.

`patch_profile_metrics.py` retains only the TLS component wrappers from that
historical patch and adds endpoint metrics to the current MTC/native client and
server. It does not restore Compact, change certificate validation, or replace
native timing. Historical Compact category names remain in the JSON schema for
compatibility but receive no instrumentation. The current client option enables
both native and endpoint observers, chaining callbacks. The custom MTC peer
verification is included in the wrapped `ssl_verify_internal` call.

Each source replacement fails if its anchor is missing/duplicated. The resulting
image stores `PROFILE_SHA256`; the build verifies server option availability.
The runtime preflight checks capability markers, not scientific correctness.
The measurement runner additionally requires valid profile snapshots, a matching
client random, peer-auth calls, nonzero Certificate bytes and matching endpoint
Certificate sizes. No missing metrics are replaced by zeros or inferred values.

Preparation was checked offline; compilation against the actual container source
and TLS execution remain **NOT CHECKED — requires execution**. Existing source
and fixture provenance checks remain in force. Keep prior failed results intact.

Installation integration: `mt-prepare run ALL` and `mt-install run ALL` prepare
profiling and mutual-profiling images automatically. Stages 4 and 5 can prepare
images without fixture generation. Default boundary execution restores missing
profile ancestors before the capability check; custom image references are
never replaced. Network measurement images also derive from profiling.
