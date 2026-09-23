# Shared base images

This directory contains the active TLS image chain used by MTC/X.509 validation
and cryptographic scaling:

```text
mt-tls-lab:local -> mt-tls-mtc:local -> mt-tls-capture:local
```

Compact, its profiling layer and the former combined measurement image are kept
under `docker/historical_campaigns/` for historical reproduction only.
