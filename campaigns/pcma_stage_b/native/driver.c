#define _POSIX_C_SOURCE 200809L
#include "tls.h"
#include "../../../compact/compact.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>

typedef struct { unsigned long long incoming,outgoing,hello,certificate,cv,ee,records,cv_scheme; } Wire;
static void msg(int write,int version,int type,const void *buf,size_t n,SSL *ssl,void *arg){Wire *w=arg;const unsigned char *p=buf;(void)version;(void)ssl;if(type==SSL3_RT_HEADER){w->records++;return;}if(type!=SSL3_RT_HANDSHAKE||!n)return;if(write)w->outgoing+=n;else w->incoming+=n;if(p[0]==SSL3_MT_CLIENT_HELLO)w->hello+=n;if(p[0]==SSL3_MT_CERTIFICATE)w->certificate+=n;if(p[0]==SSL3_MT_CERTIFICATE_VERIFY){w->cv+=n;if(n>=6)w->cv_scheme=((unsigned)p[4]<<8)|p[5];}if(p[0]==SSL3_MT_ENCRYPTED_EXTENSIONS)w->ee+=n;}
static double cpu(void){struct timespec t;clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}
static int endpoint(const char *host,const char *port,int server,const char *ready){struct addrinfo hints={0},*res=NULL,*it;int fd=-1;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;if(getaddrinfo(host,port,&hints,&res))return -1;for(it=res;it;it=it->ai_next){fd=socket(it->ai_family,it->ai_socktype,it->ai_protocol);if(fd<0)continue;if(server){int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));if(!bind(fd,it->ai_addr,it->ai_addrlen)&&!listen(fd,1))break;}else if(!connect(fd,it->ai_addr,it->ai_addrlen))break;close(fd);fd=-1;}freeaddrinfo(res);if(server&&fd>=0){FILE *f=fopen(ready,"wx");if(!f){close(fd);return -1;}fputs("ready\n",f);fclose(f);int accepted=accept(fd,NULL,NULL);close(fd);fd=accepted;}return fd;}
int main(int argc,char **argv){
    if(argc==1||!strcmp(argv[1],"--help")){puts("pcma_tls client|server pq|pq-compact-warm|pq-compact-pcma HOST PORT DNS CERT KEY CA BUNDLE ROOT CACHE BUDGET lru|upper-level READY\nSingle explicit TLS operation. --version does not connect.");return 0;}
    if(!strcmp(argv[1],"--version")){printf("%s %s\n",PC_VERSION,OpenSSL_version(OPENSSL_VERSION));return 0;}
    if(argc!=15){fprintf(stderr,"invalid arguments; use --help\n");return 2;}
    int server=!strcmp(argv[1],"server"),pcma=!strcmp(argv[2],"pq-compact-pcma"),warm=!strcmp(argv[2],"pq-compact-warm");
    if((!server&&strcmp(argv[1],"client"))||(!pcma&&!warm&&strcmp(argv[2],"pq")))return 2;
    char *end;unsigned long budget=strtoul(argv[12],&end,10);if(*end||budget>69*PC_MAX||(strcmp(argv[13],"lru")&&strcmp(argv[13],"upper-level")))return 2;
    umask(077);signal(SIGPIPE,SIG_IGN);alarm(45);
    SSL_CTX *ctx=SSL_CTX_new(server?TLS_server_method():TLS_client_method());SSL *ssl=NULL;int fd=-1,ok=0;Wire wire={0};double wall=0,processor=0;unsigned long long read_bytes=0,written_bytes=0;const PcMetrics *pm=NULL;PcMetrics empty={0};int sig=0,peer_ml_dsa65=0;
    if(!ctx||!SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)||!SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION)||!SSL_CTX_set1_groups_list(ctx,"X25519")||!SSL_CTX_set_ciphersuites(ctx,"TLS_AES_256_GCM_SHA384"))goto done;
    SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET);SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);SSL_CTX_set_num_tickets(ctx,0);
    if(server){if(!SSL_CTX_use_certificate_chain_file(ctx,argv[6])||!SSL_CTX_use_PrivateKey_file(ctx,argv[7],SSL_FILETYPE_PEM)||!SSL_CTX_check_private_key(ctx)||!EVP_PKEY_is_a(SSL_CTX_get0_privatekey(ctx),"ML-DSA-65"))goto done;if(pcma&&!pcma_server(ctx,argv[9],argv[10]))goto done;if(warm&&!compact_server(ctx,argv[9],argv[10]))goto done;}
    else{SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);if(!X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(ctx),argv[5],0))goto done;if(pcma){if(!pcma_client(ctx,argv[8],argv[10],argv[11],(unsigned)budget,!strcmp(argv[13],"upper-level")))goto done;}else if(warm){if(!compact_client(ctx,argv[8],argv[10]))goto done;}else if(!SSL_CTX_load_verify_locations(ctx,argv[8],NULL))goto done;}
    SSL_CTX_set_msg_callback(ctx,msg);SSL_CTX_set_msg_callback_arg(ctx,&wire);
    ssl=SSL_new(ctx);if(!ssl)goto done;if(!server&&!SSL_set_tlsext_host_name(ssl,argv[5]))goto done;
    fd=endpoint(argv[3],argv[4],server,argv[14]);if(fd<0||!SSL_set_fd(ssl,fd))goto done;
    wall=pc_clock();processor=cpu();ok=(server?SSL_accept(ssl):SSL_connect(ssl))==1;processor=cpu()-processor;wall=pc_clock()-wall;
    read_bytes=BIO_number_read(SSL_get_rbio(ssl));written_bytes=BIO_number_written(SSL_get_wbio(ssl));
    if(ok){if(SSL_session_reused(ssl)||SSL_version(ssl)!=TLS1_3_VERSION||strcmp(SSL_get_cipher_name(ssl),"TLS_AES_256_GCM_SHA384")||SSL_get_negotiated_group(ssl)!=NID_X25519)ok=0;
        if(!server){EVP_PKEY *peer=SSL_get0_peer_rpk(ssl);if(!peer){X509 *cert=SSL_get0_peer_certificate(ssl);peer=cert?X509_get0_pubkey(cert):NULL;}peer_ml_dsa65=peer&&EVP_PKEY_is_a(peer,"ML-DSA-65");if(!peer_ml_dsa65||SSL_get_verify_result(ssl)!=X509_V_OK)ok=0;SSL_get_peer_signature_nid(ssl,&sig);}
        if(ok&&pcma&&!pcma_finish(ssl))ok=0;}
    pm=pcma?pcma_metrics(ssl):NULL;
    if(warm&&!server)compact_observation(ssl,&empty);
 done:
    if(!pm)pm=&empty;
    printf("PCMA_METRICS {\"success\":%s,\"protocol\":\"%s\",\"wall_ms\":%.9f,\"cpu_ms\":%.9f,\"tls_read_bytes\":%llu,\"tls_written_bytes\":%llu,\"handshake_read_bytes\":%llu,\"handshake_written_bytes\":%llu,\"clienthello_bytes\":%llu,\"certificate_bytes\":%llu,\"certificate_verify_bytes\":%llu,\"encrypted_extensions_bytes\":%llu,\"tls_record_count\":%llu,\"tls_version\":%d,\"resumed\":%d,\"cipher\":\"%s\",\"group\":%d,\"signature_nid\":%d,\"peer_key_ml_dsa65\":%d,\"certificate_verify_scheme\":%llu,\"advertisement_bytes\":%u,\"pcma_extension_bytes\":%u,\"credential_bytes\":%u,\"proof_bytes\":%u,\"normal_hashes\":%u,\"reused_hashes\":%u,\"transmitted_hashes\":%u,\"cache_nodes\":%u,\"cache_bytes\":%u,\"cache_hits\":%u,\"cache_misses\":%u,\"nodes_added\":%u,\"nodes_evicted\":%u,\"fallback_events\":0,\"encode_ms\":%.9f,\"advertisement_parse_ms\":%.9f,\"range_lookup_ms\":%.9f,\"partial_construction_ms\":%.9f,\"cache_lookup_ms\":%.9f,\"reconstruction_ms\":%.9f,\"verification_ms\":%.9f,\"credential_verify_ms\":%.9f}\n",
    ok?"true":"false",PC_VERSION,wall,processor,read_bytes,written_bytes,wire.incoming,wire.outgoing,wire.hello,wire.certificate,wire.cv,wire.ee,wire.records,ssl?SSL_version(ssl):0,ssl?SSL_session_reused(ssl):0,ssl?SSL_get_cipher_name(ssl):"none",ssl?(int)SSL_get_negotiated_group(ssl):0,sig,peer_ml_dsa65,wire.cv_scheme,pm->advertised,pcma?pm->advertised+4:0,pm->credential_bytes,pm->proof_bytes,pm->normal,pm->reused,pm->sent,pm->cache_nodes,pm->cache_bytes,pm->hits,pm->misses,pm->added,pm->evicted,pm->encode_ms,pm->parse_ms,pm->range_ms,pm->construct_ms,pm->lookup_ms,pm->reconstruct_ms,pm->verify_ms,pm->credential_verify_ms);
    if(!ok)ERR_print_errors_fp(stderr);SSL_free(ssl);SSL_CTX_free(ctx);if(fd>=0)close(fd);return ok?0:1;
}
