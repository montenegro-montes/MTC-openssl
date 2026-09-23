# Shared base images

This directory contains the active TLS image chain used by MTC/X.509 validation
and cryptographic scaling:

```text
mt-tls-lab:local -> mt-tls-mtc:local -> mt-tls-capture:local
```

Network measurement images extend `mt-tls-mtc:local` from `docker/network/`.
