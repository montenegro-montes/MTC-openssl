/* One native client attempt per process; bounded server for manual preflight.
   No application data, resumption, verification shortcuts or timing changes. */
#include "retry_tls.c"
#include <openssl/err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

static double tick_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return -1.0;
    return t.tv_sec*1000.0+t.tv_nsec/1e6;
}

static int transport(const char *host,const char *port,int server) {
    struct addrinfo hints={0},*addresses=NULL,*a;int fd=-1,one=1;
    hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,port,&hints,&addresses))return -1;
    for(a=addresses;a;a=a->ai_next){
        fd=socket(a->ai_family,a->ai_socktype,a->ai_protocol); /* fresh socket */
        if(fd<0)continue;
        if(server)setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        if((server?bind(fd,a->ai_addr,a->ai_addrlen):connect(fd,a->ai_addr,a->ai_addrlen))==0)break;
        close(fd);fd=-1;
    }
    freeaddrinfo(addresses);return fd;
}
static void deadline(int fd) {
    struct timeval t={5,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t));
}
static void timing(SSL *ssl,double tcp_ms,double tls_ms,double attempt_ms) {
    unsigned char random[32];size_t n=SSL_get_client_random(ssl,random,sizeof(random));
    uint64_t bytes_read=BIO_number_read(SSL_get_rbio(ssl));
    uint64_t bytes_written=BIO_number_written(SSL_get_wbio(ssl));
    fprintf(stdout,"MTC_RETRY_TIMING {\"connection_id\":\"");
    retry_hex(stdout,random,n);
    fprintf(stdout,"\",\"retry_tcp_connect_wall_ms_native\":%.6f,\"retry_tls_attempt_wall_ms\":%.6f,\"retry_attempt_wall_ms_native\":%.6f,\"tls_bytes_read\":%llu,\"tls_bytes_written\":%llu,\"tls_bytes_total\":%llu}\n",
            tcp_ms,tls_ms,attempt_ms,(unsigned long long)bytes_read,
            (unsigned long long)bytes_written,
            (unsigned long long)(bytes_read+bytes_written));
    fflush(stdout);
}
static void result(SSL *ssl,int ok) {
    unsigned char random[32];size_t n=SSL_get_client_random(ssl,random,sizeof(random));
    fprintf(stdout,"MTC_RETRY_RESULT {\"result\":\"%s\",\"connection_id\":\"",ok?"PASS":"FAIL");
    retry_hex(stdout,random,n);
    fprintf(stdout,"\",\"session_reused\":%s,\"tls_version\":\"%s\",\"cipher\":\"%s\",\"negotiated_group\":%ld}\n",
            SSL_session_reused(ssl)?"true":"false",SSL_get_version(ssl),SSL_get_cipher_name(ssl),SSL_get_negotiated_group(ssl));
    fflush(stdout);
}
int main(int argc,char **argv) {
    SSL_CTX *ctx=NULL;SSL *ssl=NULL;X509 *cert=NULL;EVP_PKEY *key=NULL;BIO *b=NULL;
    int server,landmark,fd=-1,listener=-1,ok=0,count=1,exit_code=1;
    signal(SIGPIPE,SIG_IGN);
    if(argc==2&&!strcmp(argv[1],"--help")){
        puts("inspect TRUST landmark|standalone\nclient HOST PORT TRUST MODE REQUESTED_ID HOSTNAME\nserver HOST PORT TRUST MODE CERT KEY CONNECTIONS(1|2)");return 0;
    }
    if(argc==4&&!strcmp(argv[1],"inspect")){
        MTCConfig *trust;
        if(strcmp(argv[3],"landmark")&&strcmp(argv[3],"standalone"))return 2;
        trust=mtc_load(argv[2],!strcmp(argv[3],"landmark"));if(!trust)return 1;
        fputs("MTC_RETRY_TRUST {\"trusted_id_hex\":\"",stdout);retry_hex(stdout,trust->signal,trust->signal_len);
        puts("\"}");mtc_free(trust);return 0;
    }
    server=argc>1&&!strcmp(argv[1],"server");
    if((!server&&(argc!=8||strcmp(argv[1],"client")))||(server&&argc!=9))return 2;
    if(strcmp(argv[5],"landmark")&&strcmp(argv[5],"standalone"))return 2;
    landmark=!strcmp(argv[5],"landmark");
    ctx=SSL_CTX_new(server?TLS_server_method():TLS_client_method());if(!ctx)goto end;
    if(!SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)||!SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_ciphersuites(ctx,"TLS_AES_256_GCM_SHA384")||!SSL_CTX_set1_groups_list(ctx,"X25519"))goto end;
    if(server){
        if(strcmp(argv[8],"1")&&strcmp(argv[8],"2"))goto end;
        count=atoi(argv[8]);
        b=BIO_new_file(argv[6],"r");if(!b)goto end;cert=PEM_read_bio_X509(b,NULL,NULL,NULL);BIO_free(b);b=NULL;
        b=BIO_new_file(argv[7],"r");if(!b)goto end;key=PEM_read_bio_PrivateKey(b,NULL,NULL,NULL);BIO_free(b);b=NULL;
        if(!cert||!key||!retry_configure(ctx,argv[4],landmark,NULL,cert,key)){
            fputs("MTC_RETRY_ERROR {\"reason\":\"credential_mapping_rejected\"}\n",stderr);goto end;
        }
        listener=transport(argv[2],argv[3],1);
        if(listener<0||listen(listener,2)){
            fprintf(stderr,"MTC_RETRY_ERROR {\"reason\":\"listen_failed\",\"errno\":%d}\n",errno);goto end;
        }
        puts("MTC_RETRY_READY");fflush(stdout);
    }else if(!retry_configure(ctx,argv[4],landmark,argv[6],NULL,NULL))goto end;
    for(int i=0;i<count;i++){
        double attempt_start=-1.0,tcp_done=-1.0,tls_start=-1.0,tls_done=-1.0;
        if(server){struct pollfd ready={listener,POLLIN,0};if(poll(&ready,1,10000)<=0)goto end;fd=accept(listener,NULL,NULL);}
        else {attempt_start=tick_ms();fd=transport(argv[2],argv[3],0);tcp_done=tick_ms();}
        if(fd<0)goto end;
        deadline(fd);
        ssl=SSL_new(ctx); /* new SSL object for this accepted/connected socket */
        if(!ssl||!SSL_set_fd(ssl,fd))goto end;
        if(!server&&(!SSL_set_tlsext_host_name(ssl,argv[7])||!SSL_set1_host(ssl,argv[7])))goto end;
        if(!server)tls_start=tick_ms();
        ok=(server?SSL_accept(ssl):SSL_connect(ssl))==1; /* native handshake / ClientHello */
        if(!server)tls_done=tick_ms();
        if(ok&&(SSL_session_reused(ssl)||SSL_version(ssl)!=TLS1_3_VERSION
               ||(!server&&SSL_get_verify_result(ssl)!=X509_V_OK)))ok=0;
        result(ssl,ok);
        if(!server&&attempt_start>=0.0&&tcp_done>=attempt_start&&tls_start>=0.0&&tls_done>=tls_start)
            timing(ssl,tcp_done-attempt_start,tls_done-tls_start,tls_done-attempt_start);
        if(!ok)ERR_print_errors_fp(stderr);
        SSL_free(ssl);ssl=NULL;close(fd);fd=-1; /* attempt ends before another starts */
        exit_code=ok?0:1;
    }
end:
    if(exit_code)ERR_print_errors_fp(stderr);
    BIO_free(b);SSL_free(ssl);if(fd>=0)close(fd);if(listener>=0)close(listener);
    SSL_CTX_free(ctx);X509_free(cert);EVP_PKEY_free(key);return exit_code;
}
