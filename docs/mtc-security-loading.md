# MTC proof loading on the replacement OpenSSL stack

The user changed the image stack to OpenSSL 3.4.7, liboqs 0.16.0 and
an oqs-provider main-branch build reporting 0.12.0-dev. These changes are
preserved. The previous 3.5.8 campaign environment must not be conflated with it.

`SSL_CTX_use_certificate` calls the generic certificate security gate before
loading the local certificate. MTC encodes its proof under the private
signature OID `1.3.6.1.4.1.44363.47.0`; OpenSSL cannot assign ordinary CA
signature strength to that OID and reports `ca md too weak`.

The MTC application patch now installs MTC mode before `set_cert_key_stuff`.
In that explicitly enabled server context, a wrapper accepts only the local
`SSL_SECOP_CA_MD` operation when both the outer and TBS signature algorithms
are the exact MTC proof OID. All other operations delegate to the previous
security callback. There is no global security-level change or X.509 bypass.
The peer proof verifier, key-strength checks, TLS CertificateVerify and
Finished processing are unchanged.

Offline tests load standalone and landmark credentials for classic and PQ at
security level 2 and assert ordinary CA-digest, peer and weak-key rejection.
The patch was applied to temporary copies of the actual installed OpenSSL
application sources to verify the registration order. The agent ran no TLS
handshakes. The user subsequently reported successful manual completion of
`07.measurement-image`: 70 MTC TLS cases including malformed/signed invalid
credentials, and `ALL REGRESSION AND NEGATIVE TESTS PASS`.
The unit test is included in the measurement-image regression script.

To reproduce the completed check from the repository root, rebuild MTC and retry the
measurement-image step (which builds its child and runs the regression suite):

```sh
bin/containers/mt-containers build mtc && bin/original_campaigns/mt-campaigns retry 07.measurement-image
```

This does not regenerate fixtures. The user-reported pass validates the
regression gate; it does not constitute Paper-1 performance measurements.
