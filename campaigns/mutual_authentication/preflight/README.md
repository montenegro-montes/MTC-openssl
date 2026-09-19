# Mutual Authentication Validation

This validation layer checks that the experimental TLS 1.3 stack supports mutual authentication across classical X.509, post-quantum X.509, and MTC-experimental credentials.

The validation is intentionally functional. It does not perform performance measurements and does not replace the controlled timing campaigns. Its purpose is to verify that both peers can authenticate each other under fixed TLS parameters.

## Fixed TLS parameters

All preflight cases use:

- TLS 1.3
- X25519 key exchange
- TLS_AES_256_GCM_SHA384
- No session tickets
- No resumption
- Client authentication required by the server

## Positive scenarios

The preflight validates five positive mutual-authentication scenarios:

1. X.509 server with X.509 client
2. PQ X.509 server with PQ X.509 client
3. MTC server with X.509 client
4. X.509 server with MTC client
5. MTC server with MTC client

A positive case passes only if the client completes the TLS handshake successfully and the server log confirms that the client certificate and CertificateVerify were received.

For MTC client authentication, the server log must also contain:

```text
MTC verification: OK
```

For MTC server authentication, the client output must contain:

```text
Verification: OK
```

## Negative scenarios

The automated preflight validates three negative mutual-authentication scenarios:

1. Missing client credential
2. Wrong X.509 client CA
3. Untrusted MTC client domain

A negative case passes only if the client command fails and the server log contains the expected rejection evidence.

### Missing client credential

In this case, the server requires client authentication, while the client does not provide a certificate or private key.

The client command uses `-ign_eof` so that `s_client` waits for the server-side rejection instead of exiting immediately after sending its Finished message.

Expected rejection evidence includes:

```text
peer did not return a certificate
SSL_accept:error
```

### Wrong X.509 client CA

In this case, the server trusts `client-ca.pem`, while the client presents `wrong-client.pem`, which is issued by a different CA.

Expected rejection evidence includes:

```text
unable to get local issuer certificate
certificate verify failed
```

### Untrusted MTC client domain

In this case, the server is configured with the primary MTC client trust file, while the client presents a credential from the alternate MTC client domain.

Expected rejection evidence includes:

```text
handshake failure
certificate verify failed
```

This should be described conservatively as rejection by the configured MTC trust policy. The current OpenSSL output does not expose a more specific Merkle-root mismatch reason.

## Running the preflight

From the repository root:

```bash
python3 campaigns/mutual_authentication/preflight/preflight.py --json
```

Expected result:

```text
PASS: 8/8 mutual-auth preflights
```

With `--json`, the script prints a machine-readable summary containing the positive and negative case names and their pass/fail status.

The expected JSON summary includes:

```json
{
  "result": "PASS",
  "positive_case_count": 5,
  "negative_case_count": 3,
  "case_count": 8,
  "passed": 8
}
```

## OQS provider handling

The PQ X.509 scenario requires the OQS provider to be loaded explicitly. The preflight does not rely on automatic OpenSSL configuration for PQ support.

The PQ cases use:

```text
-provider-path /opt/openssl/lib/ossl-modules
-provider default
-provider oqsprovider
```

and the container environment includes:

```text
LD_LIBRARY_PATH=/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib
```

This is required so that OpenSSL can load `oqsprovider` and read ML-DSA private keys.

## MTC landmark mode

The MTC credentials used here are landmark-mode credentials. Any peer that loads an MTC trust file must use:

```text
-mtc_landmark
```

For MTC server authentication, the client uses:

```text
-mtc_trust <trust.bin>
-mtc_landmark
```

For MTC client authentication, the server uses:

```text
-mtc_client_trust <trust.bin>
-mtc_landmark
```

The MTC client presents its credential with:

```text
-cert <landmark certificate>
-key <matching private key>
-mtc_client_id <trust-anchor-id>
-mtc_landmark
```

## Scope and interpretation

This validation uses the project’s MTC-experimental implementation. It targets the laboratory implementation used in this repository and should not be described as native OpenSSL MTC support.

The current preflight validates functional mutual-authentication behaviour only. It is not a timing campaign and should not be used as performance evidence.

Measurement campaigns, transcript-level validation, PCAP checks, and HTML reporting should be added separately.
