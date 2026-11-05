/* Offline fixture binding and credential selection. No sockets or handshakes. */
#include "tls.c"
#include <assert.h>

static X509 *read_certificate(const char *path){
    BIO *bio=BIO_new_file(path,"r");
    X509 *certificate;
    assert(bio);
    certificate=PEM_read_bio_X509(bio,NULL,NULL,NULL);
    BIO_free(bio);
    assert(certificate);
    return certificate;
}
static EVP_PKEY *read_key(const char *path){
    BIO *bio=BIO_new_file(path,"r");
    EVP_PKEY *key;
    assert(bio);
    key=PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
    BIO_free(bio);
    assert(key);
    return key;
}
static size_t request_signal(unsigned char *out,const unsigned char *id,
                             size_t id_n){
    assert(id_n<256);
    put(out,id_n+1,2);
    out[2]=(unsigned char)id_n;
    memcpy(out+3,id,id_n);
    return id_n+3;
}

int main(int argc,char **argv){
    MTCConfig *standalone,*landmark;
    X509 *standalone_cert,*landmark_cert;
    EVP_PKEY *key;
    SSL_CTX *ctx;
    MTCServerCandidates *set;
    SSL *connection;
    unsigned char id[80];size_t id_n;
    unsigned char request[100];size_t request_n;
    char landmark_id[80];int written;
    assert(argc==8);
    standalone=mtc_load_authority_config_with_ca_v2(argv[1],argv[5],argv[6]);
    landmark=mtc_load_trust_config_with_ca_v2(argv[2],argv[5],argv[6]);
    standalone_cert=read_certificate(argv[3]);
    landmark_cert=read_certificate(argv[4]);
    assert(standalone&&landmark&&!standalone->landmark&&landmark->landmark);
    assert(id_encode(standalone->caid,id,&id_n));
    assert(id_n==standalone->signal_len
           &&!memcmp(id,standalone->signal,id_n));
    assert(landmark->signal_len>id_n
           &&!memcmp(landmark->signal,id,id_n));
    assert(candidate_proof_mode(standalone_cert,0));
    assert(candidate_proof_mode(landmark_cert,1));
    assert(!candidate_proof_mode(standalone_cert,1));
    assert(!candidate_proof_mode(landmark_cert,0));
    assert(mtc_verify(standalone_cert,standalone));
    assert(mtc_verify(landmark_cert,landmark));
    assert(!mtc_verify(landmark_cert,standalone));
    key=read_key(argv[7]);
    assert(X509_check_private_key(standalone_cert,key));
    assert(X509_check_private_key(landmark_cert,key));
    written=snprintf(landmark_id,sizeof(landmark_id),"%s.1.%llu.%llu",
                     landmark->caid,(unsigned long long)landmark->log,
                     (unsigned long long)landmark->number);
    assert(written>0&&(size_t)written<sizeof(landmark_id));
    ctx=SSL_CTX_new(TLS_server_method());
    assert(ctx);
    assert(!mtc_server_add_candidate(ctx,landmark_id,landmark_cert,key,
                                     argv[1],argv[5],argv[6]));
    assert(mtc_server_add_candidate(ctx,landmark_id,landmark_cert,key,
                                    argv[2],argv[5],argv[6]));
    assert(mtc_server_add_candidate(ctx,standalone->caid,standalone_cert,key,
                                    argv[1],argv[5],argv[6]));
    set=SSL_CTX_get_ex_data(ctx,candidates_ci);
    assert(set&&set->count==2);
    connection=SSL_new(ctx);
    assert(connection);
    request_n=request_signal(request,landmark->signal,landmark->signal_len);
    assert(select_and_install_server_candidate_eligible(connection,set,
           (Slice){request,request_n},3U)==MTC_SELECT_LANDMARK);
    assert(SSL_get_certificate(connection)==landmark_cert);
    assert(SSL_check_private_key(connection));
    SSL_free(connection);
    connection=SSL_new(ctx);
    assert(connection);
    request_n=request_signal(request,standalone->signal,standalone->signal_len);
    assert(select_and_install_server_candidate_eligible(connection,set,
           (Slice){request,request_n},3U)==MTC_SELECT_STANDALONE);
    assert(SSL_get_certificate(connection)==standalone_cert);
    assert(SSL_check_private_key(connection));
    SSL_free(connection);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(key);
    X509_free(standalone_cert);X509_free(landmark_cert);
    mtc_free(standalone);mtc_free(landmark);
    return 0;
}
