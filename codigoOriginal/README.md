# Received original code

This directory preserves the starting material separately from the active
experimental implementation:

- `C/`: received Merkle/MTC implementation and C test programs.
- `Bash/`: received certificate-generation script.
- `MTC/`: independent received MTC prototype, configuration, scripts, and
  local results.

The active laboratory does not edit these sources. Dockerfiles compile the C
tests from this location, while later development lives in `integration/`,
`compact/`, `profiling/`, and `mtc/`.

`.env` files, private keys, compiled binaries, and debug symbols remain
excluded from Git. Treat `MTC/output/` as local prototype evidence rather than
results from the current reproducible campaigns.

## Role in project setup

Do not use this directory as the entry point for the active laboratory. The base
image copies `C/crypto/` and `C/*tests.c` and compiles them in the container:

```sh
docker compose -f docker/compose.yaml build
```

After building, inspect the installed test programs with:

```sh
docker run --rm --network none mt-tls-lab:local \
  sh -c 'ls -l /opt/mt/bin/merkle_tests /opt/mt/bin/mtc_tests /opt/mt/bin/merkle_mtc_tests'
```

Follow the [root README](../README.md) and
[Docker instructions](../docker/README.md) for the active integration. The
`MTC/README.TXT` file remains historical documentation and does not replace
the current reproducible workflow.

## Check before publication

```sh
git status --short
git ls-files codigoOriginal
git check-ignore codigoOriginal/MTC/config/.env
git check-ignore codigoOriginal/C/certs/cert1.key
```

The final two commands must confirm that the local environment and private keys
are ignored. Do not add `.DS_Store`, local binaries, private keys, or new
prototype results.
