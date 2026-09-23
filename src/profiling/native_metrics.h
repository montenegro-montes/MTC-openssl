#ifndef MTC_NATIVE_METRICS_H
#define MTC_NATIVE_METRICS_H
#include <openssl/ssl.h>
int mtc_native_metrics_enable(SSL_CTX *ctx);
void mtc_native_connect_start(SSL *ssl);
void mtc_native_connect_done(SSL *ssl, int success);
#endif
