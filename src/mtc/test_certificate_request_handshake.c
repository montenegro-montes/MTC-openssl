/* In-memory TLS 1.3 CertificateRequest extension integration test.
 * Uses the same local certificate on both peers and an accept-all test
 * verification callback. It tests extension routing, not MTC authentication. */
#include "tls.c"
#include <assert.h>
#include <openssl/err.h>
#include <stdio.h>

typedef struct {
    unsigned char request[83];
    size_t request_n;
    int client_hello_seen;
    int certificate_request_sent;
    int client_marker_seen;
} Probe;

static int probe_add(SSL *ssl,unsigned type,unsigned context,
                     const unsigned char **out,size_t *out_n,X509 *x,
                     size_t chainidx,int *alert,void *arg){
    Probe *probe=arg;
    (void)ssl;(void)type;(void)x;(void)chainidx;(void)alert;
    if(context!=SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)return 0;
    probe->certificate_request_sent++;
    *out=probe->request;
    *out_n=probe->request_n;
    return 1;
}

static int probe_parse(SSL *ssl,unsigned type,unsigned context,
                       const unsigned char *in,size_t in_n,X509 *x,
                       size_t chainidx,int *alert,void *arg){
    Probe *probe=arg;
    (void)ssl;(void)type;(void)x;
    if(context==SSL_EXT_CLIENT_HELLO){
        probe->client_hello_seen++;
        return 1;
    }
    if(context==SSL_EXT_TLS1_3_CERTIFICATE){
        if(in_n||chainidx){*alert=SSL_AD_DECODE_ERROR;return 0;}
        probe->client_marker_seen++;
    }
    return 1;
}

static int accept_test_cert(int ok,X509_STORE_CTX *store){
    (void)ok;(void)store;
    return 1;
}

static X509 *read_cert(const char *path){
    BIO *bio=BIO_new_file(path,"r");
    X509 *cert=bio?PEM_read_bio_X509(bio,NULL,NULL,NULL):NULL;
    BIO_free(bio);
    return cert;
}

static EVP_PKEY *read_key(const char *path){
    BIO *bio=BIO_new_file(path,"r");
    EVP_PKEY *key=bio?PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL):NULL;
    BIO_free(bio);
    return key;
}

int main(int argc,char **argv){
    const unsigned char large_id[]={
        0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
    };
    SSL_CTX *server_ctx=NULL,*client_ctx=NULL;
    SSL *server=NULL,*client=NULL;
    BIO *server_bio=NULL,*client_bio=NULL;
    X509 *cert=NULL;EVP_PKEY *key=NULL;
    Probe probe={0};size_t known_n=0,pos=2;
    int server_done=0,client_done=0,ok=0;
    const char *phase="load";

    if(argc!=3){fprintf(stderr,"usage: %s cert.pem key.pem\n",argv[0]);return 2;}
    cert=read_cert(argv[1]);key=read_key(argv[2]);
    server_ctx=SSL_CTX_new(TLS_server_method());
    client_ctx=SSL_CTX_new(TLS_client_method());
    if(!cert||!key||!server_ctx||!client_ctx)goto end;
    phase="tls_setup";
    if(!SSL_CTX_set_min_proto_version(server_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_max_proto_version(server_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_min_proto_version(client_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_max_proto_version(client_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set1_groups_list(server_ctx,"X25519:P-256")
       ||!SSL_CTX_set1_groups_list(client_ctx,"X25519:P-256"))goto end;
    /* The fixture is a server leaf. This bypasses certificate policy only
       for the extension-routing test; it makes no authentication claim. */
    SSL_CTX_set_security_level(server_ctx,0);
    SSL_CTX_set_verify(server_ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       accept_test_cert);
    SSL_CTX_set_verify(client_ctx,SSL_VERIFY_NONE,NULL);
    phase="certificates";
    if(!mtc_client_present(client_ctx,"32473.101.1.1.1",0)
       ||!SSL_CTX_use_certificate(server_ctx,cert)
       ||!SSL_CTX_use_PrivateKey(server_ctx,key)
       ||!SSL_CTX_use_certificate(client_ctx,cert)
       ||!SSL_CTX_use_PrivateKey(client_ctx,key))goto end;

    probe.request[pos++]=(unsigned char)sizeof(large_id);
    memcpy(probe.request+pos,large_id,sizeof(large_id));pos+=sizeof(large_id);
    if(!id_encode("32473.101.1.1.1",probe.request+pos+1,&known_n))goto end;
    probe.request[pos++]=(unsigned char)known_n;
    pos+=known_n;
    put(probe.request,pos-2,2);
    probe.request_n=pos;
    phase="extension_registration";
    if(!SSL_CTX_add_custom_ext(server_ctx,MTC_EXT,CONTEXT,
                               probe_add,NULL,&probe,probe_parse,&probe))goto end;
    phase="bio_pair";
    server=SSL_new(server_ctx);client=SSL_new(client_ctx);
    if(!server||!client||!BIO_new_bio_pair(&server_bio,0,&client_bio,0))goto end;
    SSL_set_bio(server,server_bio,server_bio);
    SSL_set_bio(client,client_bio,client_bio);
    server_bio=client_bio=NULL;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);
    phase="handshake";
    for(int step=0;step<100&&(!server_done||!client_done);step++){
        SSL *peers[2]={client,server};
        int *done[2]={&client_done,&server_done};
        for(int i=0;i<2;i++){
            int result,error;
            if(*done[i])continue;
            result=SSL_do_handshake(peers[i]);
            if(result==1){*done[i]=1;continue;}
            error=SSL_get_error(peers[i],result);
            if(error!=SSL_ERROR_WANT_READ&&error!=SSL_ERROR_WANT_WRITE){
                fprintf(stderr,"handshake_peer=%s ssl_error=%d result=%d\n",
                        i?"server":"client",error,result);
                goto end;
            }
        }
    }
    phase="expectations";
    ok=server_done&&client_done&&probe.client_hello_seen==1
       &&probe.certificate_request_sent==1&&probe.client_marker_seen==1
       &&SSL_get0_peer_certificate(server)!=NULL;
end:
    printf("phase=%s server_done=%d client_done=%d ch_seen=%d cr_sent=%d marker_seen=%d peer_cert=%d\n",
           phase,
           server_done,client_done,probe.client_hello_seen,
           probe.certificate_request_sent,probe.client_marker_seen,
           server&&SSL_get0_peer_certificate(server)!=NULL);
    puts(ok?"PASS: CertificateRequest large and known ID, client marker"
           :"FAIL: CertificateRequest handshake");
    if(!ok)ERR_print_errors_fp(stderr);
    BIO_free(server_bio);BIO_free(client_bio);
    SSL_free(server);SSL_free(client);
    SSL_CTX_free(server_ctx);SSL_CTX_free(client_ctx);
    X509_free(cert);EVP_PKEY_free(key);
    return ok?0:1;
}
