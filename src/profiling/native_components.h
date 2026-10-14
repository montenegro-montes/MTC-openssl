#ifndef MTC_NATIVE_COMPONENTS_H
#define MTC_NATIVE_COMPONENTS_H
#include <openssl/ssl.h>
#include <stdint.h>
enum { MTC_NATIVE_X509_VERIFY, MTC_NATIVE_CERTIFICATE_VERIFY, MTC_NATIVE_COMPONENT_COUNT };
enum { MTC_NATIVE_X509_SIGNATURE_CRYPTO,
       MTC_NATIVE_CERTIFICATE_VERIFY_CRYPTO,
       MTC_NATIVE_CRYPTO_COMPONENT_COUNT };
int mtc_native_components_reset(SSL *ssl);
void mtc_native_component_begin(SSL *ssl, int component);
void mtc_native_component_end(SSL *ssl, int component);
void mtc_native_authentication_begin(SSL *ssl);
void mtc_native_authentication_end(SSL *ssl);
void mtc_native_credential_validation_begin(SSL *ssl);
void mtc_native_credential_validation_end(SSL *ssl);
int mtc_native_components_snapshot(SSL *ssl, double *milliseconds,
                                   unsigned long *calls, size_t count);
int mtc_native_authentication_snapshot(SSL *ssl, double *milliseconds);
int mtc_native_credential_validation_snapshot(SSL *ssl,
                                              uint64_t *nanoseconds);
void mtc_native_crypto_begin(SSL *ssl, int component);
void mtc_native_crypto_end(SSL *ssl, int component);
int mtc_native_crypto_snapshot(SSL *ssl, uint64_t *nanoseconds,
                               uint64_t *calls, size_t count);
int mtc_native_certificate_verify_crypto_snapshot(SSL *ssl,
                                                  uint64_t *nanoseconds,
                                                  uint64_t *calls);
void mtc_native_x509_measurement_begin(SSL *ssl);
void mtc_native_x509_measurement_end(SSL *ssl);
void mtc_native_x509_signature_begin(void *ssl);
void mtc_native_x509_signature_end(void *ssl);
int mtc_native_x509_signature_snapshot(SSL *ssl, uint64_t *nanoseconds,
                                       uint64_t *calls);
#endif
