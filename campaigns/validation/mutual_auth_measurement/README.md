# Mutual Authentication Measurement

This campaign measures successful TLS 1.3 mutual-authentication handshakes across classical X.509, post-quantum X.509, and MTC-experimental credentials.

It is a measurement campaign, not a negative-case validation. Failed authentication paths are covered by `campaigns/validation/mutual_auth/preflight.py`.

## Scope

The campaign measures positive mutual-authentication paths only:

1. X.509 server with X.509 client
2. PQ X.509 server with PQ X.509 client
3. MTC server with X.509 client
4. X.509 server with MTC client
5. MTC server with MTC client

## Fixed TLS parameters

All cases use:

- TLS 1.3
- X25519 key exchange
- TLS_AES_256_GCM_SHA384
- No session tickets
- No resumption
- Client authentication required by the server

## Outputs

The campaign writes the following files under the selected result root:

- `observations.csv`
- `summary.json`
- `metadata.json`
- `raw/*.client.log`
- `raw/*.server.log`

Each observation records:

- case name
- round index
- client return code
- client-side command wall time
- TLS bytes read and written from `s_client`
- TLS version
- cipher
- server authentication mode
- client authentication mode
- aggregate MTC setup time, when present
- aggregate MTC verification time, when present

The MTC timing fields are extracted from `MTC_SETUP` and `MTC_VERIFY` lines observed in the client and server logs. For cases where both endpoints use MTC, the values are currently aggregated across both endpoints.

## Smoke run

From the repository root:

```bash
ROOT="artifacts/results/mutual-auth-measurement-smoke-$(date -u +%Y%m%dT%H%M%SZ)"

python3 campaigns/validation/mutual_auth_measurement/run.py \
  --root "$ROOT" \
  --preflight
```

The smoke run executes one round for each of the five positive cases.

## Full run

Example:

```bash
ROOT="artifacts/results/mutual-auth-measurement-$(date -u +%Y%m%dT%H%M%SZ)"

python3 campaigns/validation/mutual_auth_measurement/run.py \
  --root "$ROOT" \
  --rounds 30
```

## Interpretation

This campaign measures successful mutual-authentication handshakes only. It should not be used to draw conclusions about failed authentication paths.

The wall-clock timing is measured around the `s_client` command execution from the host side. It is useful for controlled relative comparisons inside this validation layer, but it is not a replacement for the native timing methodology used in the main performance campaigns.

The MTC cases use the repository's MTC-experimental implementation and should not be described as native OpenSSL MTC support.
