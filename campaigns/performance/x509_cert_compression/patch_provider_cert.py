#!/usr/bin/env python3
"""Allow OpenSSL 3.4.7 to precompress a provider-backed active certificate.

The stock SSL_CTX_compress_certs() only iterates CERT::pkeys. Provider-backed
post-quantum certificates can be selected as CERT::key without occupying a pkeys
slot. This patch adds a zlib fallback for that active certificate in the
experiment-only image. TLS signing and verification code is unchanged.
"""

from pathlib import Path
import sys


source = Path(sys.argv[1])
old = """    ret = ssl_compress_certs(new, ctx->cert->pkeys, alg);
    SSL_free(new);
"""
new = """    ret = ssl_compress_certs(new, ctx->cert->pkeys, alg);
    if (ret == 0 && (alg == 0 || alg == TLSEXT_comp_cert_zlib)
        && ctx->cert->key != NULL && ctx->cert->key->x509 != NULL
        && ossl_comp_has_alg(TLSEXT_comp_cert_zlib)) {
        CERT_PKEY *active = ctx->cert->key;

        ret = ssl_compress_one_cert(new, active, TLSEXT_comp_cert_zlib);
        if (ret && active->comp_cert[TLSEXT_comp_cert_zlib]->len
                   >= active->comp_cert[TLSEXT_comp_cert_zlib]->orig_len) {
            OSSL_COMP_CERT_free(active->comp_cert[TLSEXT_comp_cert_zlib]);
            active->comp_cert[TLSEXT_comp_cert_zlib] = NULL;
            ret = 0;
        }
    }
    SSL_free(new);
"""
text = source.read_text()
if text.count(old) != 1:
    raise SystemExit("Expected SSL_CTX_compress_certs source was not found exactly once")
source.write_text(text.replace(old, new, 1))
