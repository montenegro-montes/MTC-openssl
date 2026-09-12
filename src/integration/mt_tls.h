#ifndef MT_TLS_H
#define MT_TLS_H
#include <openssl/ssl.h>
int mt_client_configure(SSL_CTX *ctx, const char *root_file);
int mt_server_configure(SSL_CTX *ctx, const char *proof_file);
#endif
