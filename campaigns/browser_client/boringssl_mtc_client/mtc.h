#ifndef LAB_MTC_H
#define LAB_MTC_H
#include <openssl/ssl.h>
#include <stdint.h>
#define MTC_MAX 65536
#include <openssl/tls1.h>
#define MTC_EXT TLSEXT_TYPE_trust_anchors
#define MTC_DRAFT "draft-ietf-plants-merkle-tree-certs-05"
typedef struct mtc_config MTCConfig;
MTCConfig *mtc_load_config_v2(const char *path, int landmark);
void mtc_free(MTCConfig *c);
int mtc_verify(X509 *x, MTCConfig *c);
int mtc_client(SSL_CTX *ctx,const char *path,int landmark);
int mtc_server(SSL_CTX *ctx,const char *id);
int mtc_server_verify_client(SSL_CTX *ctx,const char *path,int landmark);
int mtc_client_present(SSL_CTX *ctx,const char *id,int landmark);
int mtc_eval(const unsigned char leaf[32],uint64_t index,uint64_t start,uint64_t end,const unsigned char *proof,size_t n,unsigned char out[32]);
#endif
