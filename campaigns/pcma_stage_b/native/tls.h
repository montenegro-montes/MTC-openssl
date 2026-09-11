#ifndef PCMA_TLS_H
#define PCMA_TLS_H
#include <openssl/ssl.h>
#include "protocol.h"
int pcma_client(SSL_CTX *,const char *,const char *,const char *,unsigned,unsigned);
int pcma_server(SSL_CTX *,const char *,const char *);
int pcma_finish(SSL *);
int compact_observation(SSL *,PcMetrics *);
const PcMetrics *pcma_metrics(SSL *);
#endif
