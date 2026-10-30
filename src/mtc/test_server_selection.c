/* Offline candidate-selection policy. No keys, sockets, or TLS handshakes. */
#include "tls.c"
#include <assert.h>

static size_t request_id(unsigned char *out,const char *text){
    size_t n;
    assert(id_encode(text,out+3,&n));
    put(out,n+1,2);
    out[2]=(unsigned char)n;
    return n+3;
}

int main(void){
    TLSConfig standalone={0},landmark={0};
    TLSConfig *candidates[]={&standalone,&landmark};
    unsigned char request[100];size_t n,selected;
    const unsigned char empty[]={0,0},malformed[]={0,1,0};

    assert(id_encode("32473.101",standalone.id,&standalone.n));
    assert(id_encode("32473.101.1.7.129",landmark.id,&landmark.n));
    assert(initial_group(&landmark));
    landmark.has_group=1;
    landmark.group_n=landmark.n;

    /* Reversed candidate order does not override the Landmark preference. */
    n=request_id(request,"32473.101.2.7.129");
    assert(select_server_candidate(candidates,2,(Slice){request,n},&selected)
           ==MTC_SELECT_LANDMARK && selected==1);
    n=request_id(request,"32473.101.1.7.129");
    assert(select_server_candidate(candidates,2,(Slice){request,n},&selected)
           ==MTC_SELECT_LANDMARK && selected==1);
    n=request_id(request,"32473.999");
    {
        size_t second;
        assert(id_encode("32473.101.2.7.129",request+n+1,&second));
        request[n]=(unsigned char)second;
        n+=second+1;
        put(request,n-2,2);
    }
    assert(select_server_candidate(candidates,2,(Slice){request,n},&selected)
           ==MTC_SELECT_LANDMARK && selected==1);

    /* Bare CA and stale or unrelated landmark groups cannot select Landmark. */
    n=request_id(request,"32473.101");
    assert(select_server_candidate(candidates,2,(Slice){request,n},&selected)
           ==MTC_SELECT_STANDALONE && selected==0);
    n=request_id(request,"32473.101.2.7.128");
    assert(select_server_candidate(candidates,2,(Slice){request,n},&selected)
           ==MTC_SELECT_STANDALONE && selected==0);
    n=request_id(request,"32473.999");
    assert(select_server_candidate(candidates,2,(Slice){request,n},&selected)
           ==MTC_SELECT_FALLBACK_STANDALONE && selected==0);
    assert(select_server_candidate(candidates,2,
           (Slice){empty,sizeof(empty)},&selected)
           ==MTC_SELECT_FALLBACK_STANDALONE && selected==0);
    assert(select_server_candidate(candidates+1,1,
           (Slice){empty,sizeof(empty)},&selected)
           ==MTC_SELECT_NONE && selected==SIZE_MAX);
    assert(select_server_candidate(candidates,2,
           (Slice){malformed,sizeof(malformed)},&selected)==MTC_SELECT_INVALID);
    {
        unsigned char oversized[36]={0,34,33};
        assert(select_server_candidate(candidates,2,
               (Slice){oversized,sizeof(oversized)},&selected)
               ==MTC_SELECT_INVALID);
    }

    /* Registration retains both objects without installing a TLS certificate.
       A synthetic X.509 object suffices to test this storage contract. */
    {
        SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());
        SSL_CTX *legacy=SSL_CTX_new(TLS_server_method());
        X509 *cert=X509_new();
        X509 *landmark_cert=X509_new();
        EVP_PKEY *key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
        EVP_PKEY *wrong=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
        MTCServerCandidates *set;
        assert(ctx&&legacy&&cert&&landmark_cert&&key&&wrong);
        assert(X509_set_version(cert,2));
        assert(ASN1_INTEGER_set(X509_get_serialNumber(cert),1));
        assert(X509_gmtime_adj(X509_getm_notBefore(cert),-60));
        assert(X509_gmtime_adj(X509_getm_notAfter(cert),3600));
        assert(X509_NAME_add_entry_by_txt(X509_get_subject_name(cert),"CN",
                                          MBSTRING_ASC,(unsigned char *)"server",
                                          -1,-1,0));
        assert(X509_set_issuer_name(cert,X509_get_subject_name(cert)));
        assert(X509_set_pubkey(cert,key));
        assert(X509_sign(cert,key,EVP_sha256()));
        assert(X509_set_version(landmark_cert,2));
        assert(ASN1_INTEGER_set(X509_get_serialNumber(landmark_cert),2));
        assert(X509_gmtime_adj(X509_getm_notBefore(landmark_cert),-60));
        assert(X509_gmtime_adj(X509_getm_notAfter(landmark_cert),3600));
        assert(X509_set_subject_name(landmark_cert,X509_get_subject_name(cert)));
        assert(X509_set_issuer_name(landmark_cert,X509_get_subject_name(cert)));
        assert(X509_set_pubkey(landmark_cert,key));
        assert(X509_sign(landmark_cert,key,EVP_sha256()));
        assert(X509_check_private_key(cert,key));
        assert(mtc_server(legacy,"32473.101"));
        assert(!mtc_server_add_candidate_unchecked(legacy,
               "32473.101.1.7.129",cert,key));
        assert(!mtc_server_add_candidate_unchecked(ctx,"32473.101",cert,wrong));
        assert(mtc_server_add_candidate_unchecked(ctx,"32473.101",cert,key));
        assert(!mtc_server_add_candidate_unchecked(ctx,
               "32473.102.1.7.129",cert,key));
        assert(mtc_server_add_candidate_unchecked(ctx,"32473.101.1.7.129",
                                                  landmark_cert,key));
        assert(!mtc_server_add_candidate_unchecked(ctx,"32473.101",cert,key));
        assert(!mtc_server_add_candidate(ctx,"32473.101",cert,key,
                                         "missing","missing","missing"));
        assert(!mtc_server(ctx,"32473.101"));
        set=SSL_CTX_get_ex_data(ctx,candidates_ci);
        assert(set&&set->count==2&&set->items[0].certificate==cert
               &&set->items[1].certificate==landmark_cert
               &&set->items[1].key==key);
        {
            SSL *connection=SSL_new(ctx);
            TLSEndpointState *state;
            const unsigned char *out;
            size_t out_n;int alert=0;
            assert(connection);
            n=request_id(request,"32473.101.2.7.129");
            assert(select_and_install_server_candidate(connection,set,
                   (Slice){request,n})==MTC_SELECT_LANDMARK);
            state=endpoint_state(connection);
            assert(state&&state->server_selected==1
                   &&state->server_selection_reason==MTC_SELECT_LANDMARK);
            assert(SSL_get_certificate(connection)==set->items[1].certificate);
            assert(SSL_check_private_key(connection));
            assert(candidates_add(connection,MTC_EXT,
                   SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,&out,&out_n,
                   NULL,0,&alert,set)==1);
            assert(out==set->available
                   &&out_n==landmark.n+standalone.n+4
                   &&out[2]==landmark.n
                   &&!memcmp(out+3,landmark.id,landmark.n)
                   &&out[3+landmark.n]==standalone.n
                   &&!memcmp(out+4+landmark.n,standalone.id,standalone.n));
            assert(candidates_add(connection,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                   &out,&out_n,landmark_cert,0,&alert,set)==1&&out_n==0);
            assert(candidates_add(connection,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                   &out,&out_n,landmark_cert,1,&alert,set)==0);
            assert(candidates_add(connection,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                   &out,&out_n,cert,0,&alert,set)==-1);
            SSL_free(connection);
            connection=SSL_new(ctx);
            assert(connection);
            n=request_id(request,"32473.101");
            assert(select_and_install_server_candidate(connection,set,
                   (Slice){request,n})==MTC_SELECT_STANDALONE);
            state=endpoint_state(connection);
            assert(state&&state->server_selected==0);
            assert(SSL_get_certificate(connection)==set->items[0].certificate);
            assert(SSL_check_private_key(connection));
            assert(candidates_add(connection,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                   &out,&out_n,cert,0,&alert,set)==1&&out_n==0);
            SSL_free(connection);
            connection=SSL_new(ctx);
            assert(connection);
            n=request_id(request,"32473.999");
            assert(select_and_install_server_candidate(connection,set,
                   (Slice){request,n})==MTC_SELECT_FALLBACK_STANDALONE);
            assert(candidates_add(connection,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                   &out,&out_n,cert,0,&alert,set)==0);
            SSL_free(connection);
        }
        X509_free(cert);X509_free(landmark_cert);
        EVP_PKEY_free(key);EVP_PKEY_free(wrong);
        assert(X509_check_private_key(set->items[0].certificate,
                                      set->items[0].key));
        SSL_CTX_free(ctx);
        SSL_CTX_free(legacy);
    }
    return 0;
}
