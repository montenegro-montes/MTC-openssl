/* Offline certificate loading and security-policy regression; no sockets. */
#include "tls.c"
#include <openssl/err.h>
#include <assert.h>
static X509 *read_cert(const char *path){
    BIO *b=BIO_new_file(path,"r");assert(b);
    X509 *x=PEM_read_bio_X509(b,NULL,NULL,NULL);BIO_free(b);assert(x);return x;
}
int main(int argc,char **argv){
    assert(argc==3);
    X509 *mtc=read_cert(argv[1]),*ordinary=read_cert(argv[2]);
    SSL_CTX *ctx=SSL_CTX_new(TLS_method());assert(ctx);
    SSL_CTX_set_security_level(ctx,2);
    assert(mtc_server(ctx,"32473.1"));
    assert(SSL_CTX_get_security_level(ctx)==2);
    assert(SSL_CTX_use_certificate(ctx,mtc)==1);
    SecurityCallback cb=SSL_CTX_get_security_callback(ctx);
    assert(cb(NULL,ctx,SSL_SECOP_CA_MD,-1,NID_undef,mtc,NULL)==1);
    assert(cb(NULL,ctx,SSL_SECOP_CA_MD,-1,NID_undef,ordinary,NULL)==0);
    assert(cb(NULL,ctx,SSL_SECOP_CA_MD|SSL_SECOP_PEER,-1,NID_undef,mtc,NULL)==0);
    assert(cb(NULL,ctx,SSL_SECOP_EE_KEY,0,NID_undef,mtc,NULL)==0);
    SSL_CTX *plain=SSL_CTX_new(TLS_method());assert(plain);
    SSL_CTX_set_security_level(plain,2);
    assert(SSL_CTX_get_security_callback(plain)!=cb);
    SSL_CTX_free(plain);SSL_CTX_free(ctx);X509_free(mtc);X509_free(ordinary);
    puts("PASS: MTC local proof loading; ordinary/peer/key security gates preserved");
    return 0;
}
