#ifndef MTC_NATIVE_COMPONENTS_H
#define MTC_NATIVE_COMPONENTS_H
#include <openssl/ssl.h>
enum { MTC_NATIVE_X509_VERIFY, MTC_NATIVE_CERTIFICATE_VERIFY, MTC_NATIVE_COMPONENT_COUNT };
int mtc_native_components_reset(SSL *ssl);
void mtc_native_component_begin(SSL *ssl, int component);
void mtc_native_component_end(SSL *ssl, int component);
void mtc_native_authentication_begin(SSL *ssl);
void mtc_native_authentication_end(SSL *ssl);
int mtc_native_components_snapshot(SSL *ssl, double *milliseconds,
                                   unsigned long *calls, size_t count);
int mtc_native_authentication_snapshot(SSL *ssl, double *milliseconds);
#endif
