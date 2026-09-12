#ifndef LAB_COMPACT_H
#define LAB_COMPACT_H
#include <openssl/ssl.h>
int compact_client(SSL_CTX *ctx, const char *authority, const char *cached_root);
int compact_server(SSL_CTX *ctx, const char *bundle, const char *signed_root);
int lab_metrics_enable(SSL_CTX *ctx);
#endif
