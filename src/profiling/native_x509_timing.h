#ifndef OSSL_CRYPTO_MTC_X509_TIMING_H
#define OSSL_CRYPTO_MTC_X509_TIMING_H

#include <openssl/asn1.h>
#include <openssl/types.h>

typedef void (*OSSL_MTC_X509_TIMING_CALLBACK)(void *arg);

typedef struct {
    OSSL_MTC_X509_TIMING_CALLBACK begin;
    OSSL_MTC_X509_TIMING_CALLBACK end;
    void *arg;
} OSSL_MTC_X509_TIMING;

void ossl_x509_store_ctx_set_signature_timing(
    X509_STORE_CTX *ctx, const OSSL_MTC_X509_TIMING *timing);
int ossl_x509_verify_with_timing(X509 *cert, EVP_PKEY *pkey,
                                 const OSSL_MTC_X509_TIMING *timing);
int ossl_asn1_item_verify_ex_with_timing(
    const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    const ASN1_OCTET_STRING *id, EVP_PKEY *pkey,
    OSSL_LIB_CTX *libctx, const char *propq,
    const OSSL_MTC_X509_TIMING *timing);

#endif
