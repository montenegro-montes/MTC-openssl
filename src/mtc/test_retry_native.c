/* Offline native parser/credential tests. No sockets, measurements or TLS runs. */
#include "retry_tls.c"
#include <assert.h>

int main(int argc,char **argv) {
    SSL_CTX *server,*client;SSL *s,*cl;BIO *bio;X509 *cert;EVP_PKEY *key;
    const unsigned char *out;size_t out_n;int alert=0;
    assert(argc==4);
    bio=BIO_new_file(argv[2],"r");assert(bio);cert=PEM_read_bio_X509(bio,NULL,NULL,NULL);BIO_free(bio);assert(cert);
    bio=BIO_new_file(argv[3],"r");assert(bio);key=PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);BIO_free(bio);assert(key);
    server=SSL_CTX_new(TLS_server_method());client=SSL_CTX_new(TLS_client_method());assert(server&&client);
    assert(retry_configure(server,argv[1],1,NULL,cert,key));
    assert(retry_configure(client,argv[1],1,"32473.9.1.1.1",NULL,NULL));
    RetryConfig *r=(RetryConfig *)SSL_CTX_get_ex_data(server,retry_ci),*c=(RetryConfig *)SSL_CTX_get_ex_data(client,retry_ci);
    s=SSL_new(server);cl=SSL_new(client);assert(s&&cl);
    /* CASE B first attempt: valid incompatible CH, credential-backed EE,
       no confirmation on fallback, explicit client mismatch rejection. */
    assert(retry_parse(s,MTC_EXT,SSL_EXT_CLIENT_HELLO,c->request_list,c->requested_len+3,NULL,0,&alert,r));
    assert(!retry_state(s)->matched);
    assert(retry_add(s,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,&out,&out_n,NULL,0,&alert,r)==1);
    assert(out_n==r->base.n+3&&!memcmp(out+3,r->base.trust->signal,r->base.n));
    assert(retry_add(s,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,&out,&out_n,NULL,0,&alert,r)==0);
    assert(!retry_parse(cl,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,r->base.list,r->base.n+3,NULL,0,&alert,c));
    assert(alert==SSL_AD_UNKNOWN_CA&&!retry_state(cl)->available);
    SSL_free(cl);SSL_CTX_free(client);SSL_free(s);
    /* CASE A / B second: fresh contexts and SSL state; exact individual B. */
    client=SSL_CTX_new(TLS_client_method());assert(client);
    assert(retry_configure(client,argv[1],1,"32473.101.1.1.1",NULL,NULL));
    c=(RetryConfig *)SSL_CTX_get_ex_data(client,retry_ci);s=SSL_new(server);cl=SSL_new(client);assert(s&&cl);
    assert(!retry_state(s)->matched&&!retry_state(cl)->available&&!retry_state(cl)->confirmed);
    assert(retry_parse(s,MTC_EXT,SSL_EXT_CLIENT_HELLO,c->request_list,c->requested_len+3,NULL,0,&alert,r));
    assert(retry_state(s)->matched);
    assert(retry_parse(cl,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,r->base.list,r->base.n+3,NULL,0,&alert,c));
    assert(retry_parse(cl,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,(const unsigned char *)"",0,NULL,0,&alert,c));
    assert(retry_state(cl)->available&&retry_state(cl)->confirmed);
    /* Invoke the unchanged authentication callback with real leaf constraints. */
    X509_STORE *store=X509_STORE_new();X509_STORE_CTX *check=X509_STORE_CTX_new();
    assert(store&&check&&X509_STORE_CTX_init(check,store,cert,NULL));
    assert(X509_STORE_CTX_set_ex_data(check,SSL_get_ex_data_X509_STORE_CTX_idx(),cl));
    assert(X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(check),"wrong.invalid",0));
    assert(!verify(check,&c->base));
    assert(X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(check),"server",0));
    assert(verify(check,&c->base));
    X509_STORE_CTX_free(check);X509_STORE_free(store);
    /* CASE D: malformed/canonicality/duplicate handling. */
    const unsigned char malformed[][8]={{0,0},{0,3,2,0x80,1},{0,2,1,0x81},{0,4,1,1,1,1}};
    const size_t lengths[]={2,5,4,6};
    for(size_t i=0;i<4;i++){
        assert(!retry_parse(s,MTC_EXT,SSL_EXT_CLIENT_HELLO,malformed[i],lengths[i],NULL,0,&alert,r));
        assert(alert==SSL_AD_DECODE_ERROR);
    }
    assert(SSL_CTX_get_verify_mode(client)&SSL_VERIFY_PEER);
    assert(SSL_CTX_get_session_cache_mode(client)==SSL_SESS_CACHE_OFF&&SSL_CTX_get_num_tickets(client)==0);
    /* A different public key cannot satisfy possession-key binding. */
    SSL_CTX *wrong_key=SSL_CTX_new(TLS_server_method());assert(wrong_key);
    assert(!retry_configure(wrong_key,argv[1],1,NULL,cert,r->base.trust->signers[0].key));SSL_CTX_free(wrong_key);
    /* Invalid proof cannot be mapped/advertised. */
    const ASN1_BIT_STRING *signature;const X509_ALGOR *algorithm_unused;
    X509_get0_signature(&signature,&algorithm_unused,cert);
    ASN1_BIT_STRING *proof=(ASN1_BIT_STRING *)signature;assert(proof&&proof->length);
    proof->data[proof->length-1]^=1;
    SSL_CTX *invalid=SSL_CTX_new(TLS_server_method());assert(invalid);
    assert(!retry_configure(invalid,argv[1],1,NULL,cert,key));SSL_CTX_free(invalid);
    SSL_free(s);SSL_free(cl);SSL_CTX_free(server);SSL_CTX_free(client);X509_free(cert);EVP_PKEY_free(key);
    puts("PASS: native mismatch/discovery, fresh state, exact ID, malformed lists, credential binding, verification/resumption gates");
    return 0;
}
