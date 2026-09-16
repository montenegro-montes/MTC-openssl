#ifndef LAB_PROFILE_H
#define LAB_PROFILE_H
#include <openssl/ssl.h>
#define PROFILE_COUNT 16
enum {
    P_CERT_PARSE, P_RPK_PARSE, P_PEER_AUTH, P_CV_VERIFY, P_CV_SIGN,
    P_COMPACT_PARSE, P_ROOT_AUTH, P_ROOT_SIGNATURE, P_CREDENTIAL,
    P_POLICY, P_KEY_BINDING, P_KEY_ENCODE, P_KEY_HASH, P_PROOF,
    P_PHASE1_PROOF, P_CERT_BUILD
};
int SSL_profile_reset(SSL *s, int enabled);
void SSL_profile_begin(SSL *s, int category);
void SSL_profile_end(SSL *s, int category);
int SSL_profile_snapshot(SSL *s, double *wall, double *cpu, unsigned long *calls, size_t count);
int lab_metrics_connect(SSL *ssl, BIO *bio);
void lab_metrics_connect_start(SSL *ssl);
void lab_metrics_connect_done(SSL *ssl, int success);
#endif
