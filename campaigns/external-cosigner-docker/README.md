# External cosigner container smoke test

Run every command from this directory.

```sh
docker compose build
docker compose --profile provision run --rm provision
docker compose up -d cosigner

PYTHONPATH=../../src/mtc python3 smoke.py accept
PYTHONPATH=../../src/mtc python3 smoke.py sign

docker compose restart cosigner
PYTHONPATH=../../src/mtc python3 smoke.py sign

PYTHONPATH=../../src/mtc python3 smoke.py no-cert
```

The successful signature after `docker compose restart` demonstrates that the
accepted checkpoint survived in the `cosigner-state` volume. The `no-cert`
operation must report that the TLS handshake was rejected.

Inspect only public/client-side material:

```sh
find client -maxdepth 1 -type f -print
```

This directory contains the client certificate and key, the server CA
certificate, and the external cosigner public key. It never contains the
external cosigner private key.

Stop the service without deleting persistent volumes:

```sh
docker compose down
```

Delete the isolated lab volumes only when intentionally resetting the smoke
environment:

```sh
docker compose down --volumes
```
