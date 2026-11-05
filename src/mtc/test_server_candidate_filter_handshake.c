/* Focused in-memory TLS integration test for the pair's per-connection EE list.
 * Uses unchecked registration so certificates with different CA IDs can model
 * different TLS signing curves. It does not validate MTC credential binding. */
#include "tls.c"
#include <assert.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned char request[83];
    size_t request_n;
    unsigned char available[164];
    size_t available_n;
    int ee_count;
    int certificate_marker_count;
} ClientOffer;

static int offer_add(SSL *ssl,unsigned type,unsigned context,
                     const unsigned char **out,size_t *out_n,X509 *x,
                     size_t chainidx,int *alert,void *arg){
    ClientOffer *offer=arg;
    (void)ssl;(void)type;(void)x;(void)chainidx;(void)alert;
    if(context!=SSL_EXT_CLIENT_HELLO)return 0;
    *out=offer->request;
    *out_n=offer->request_n;
    return 1;
}

static int offer_parse(SSL *ssl,unsigned type,unsigned context,
                       const unsigned char *in,size_t in_n,X509 *x,
                       size_t chainidx,int *alert,void *arg){
    ClientOffer *offer=arg;
    (void)ssl;(void)type;(void)x;(void)chainidx;
    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){
        if(++offer->ee_count!=1||in_n>sizeof(offer->available))goto bad;
        memcpy(offer->available,in,in_n);
        offer->available_n=in_n;
    }else if(context==SSL_EXT_TLS1_3_CERTIFICATE){
        offer->certificate_marker_count++;
    }
    return 1;
bad:
    *alert=SSL_AD_DECODE_ERROR;
    return 0;
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
    SSL_CTX *server_ctx=NULL,*client_ctx=NULL;
    SSL *server=NULL,*client=NULL;
    BIO *server_bio=NULL,*client_bio=NULL;
    X509 *standalone=NULL,*landmark=NULL;
    EVP_PKEY *standalone_key=NULL,*landmark_key=NULL;
    MTCServerCandidates *set;
    TLSEndpointState *state;
    ClientOffer offer={0};
    unsigned char standalone_id[80],individual_landmark_id[80];
    size_t standalone_id_n=0,landmark_id_n=0,individual_landmark_id_n=0;
    int server_done=0,client_done=0,group_request,large_request,large_only,
        both_eligible,ok=0;
    const unsigned char large_id[]={
        0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
    };

    if(argc!=5&&(argc!=6||(strcmp(argv[5],"group")
                              &&strcmp(argv[5],"large-group")
                              &&strcmp(argv[5],"large-only")
                              &&strcmp(argv[5],"both-large-group")))){
        fprintf(stderr,"usage: %s standalone.pem standalone.key landmark.pem landmark.key [group|large-group|large-only|both-large-group]\n",argv[0]);
        return 2;
    }
    both_eligible=argc==6&&!strcmp(argv[5],"both-large-group");
    group_request=argc==6&&(!strcmp(argv[5],"group")
                            ||!strcmp(argv[5],"large-group")
                            ||both_eligible);
    large_request=argc==6&&(!strcmp(argv[5],"large-group")
                            ||!strcmp(argv[5],"large-only")
                            ||both_eligible);
    large_only=argc==6&&!strcmp(argv[5],"large-only");
    standalone=read_cert(argv[1]);
    standalone_key=read_key(argv[2]);
    landmark=read_cert(argv[3]);
    landmark_key=read_key(argv[4]);
    server_ctx=SSL_CTX_new(TLS_server_method());
    client_ctx=SSL_CTX_new(TLS_client_method());
    if(!standalone||!standalone_key||!landmark||!landmark_key
       ||!server_ctx||!client_ctx
       ||!SSL_CTX_set_min_proto_version(server_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_max_proto_version(server_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_min_proto_version(client_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set_max_proto_version(client_ctx,TLS1_3_VERSION)
       ||!SSL_CTX_set1_groups_list(server_ctx,"X25519")
       ||!SSL_CTX_set1_groups_list(client_ctx,"X25519:P-256")
       ||!id_encode(group_request?"32473.101.2.1.1":"32473.101.1.1.1",
                      offer.request+3,&landmark_id_n)
       ||!id_encode("32473.101",standalone_id,&standalone_id_n)
       ||!id_encode("32473.101.1.1.1",individual_landmark_id,
                      &individual_landmark_id_n))goto end;

    put(offer.request,landmark_id_n+1,2);
    offer.request[2]=(unsigned char)landmark_id_n;
    offer.request_n=landmark_id_n+3;
    if(large_request){
        if(large_only){
            put(offer.request,sizeof(large_id)+1,2);
            offer.request[2]=(unsigned char)sizeof(large_id);
            memcpy(offer.request+3,large_id,sizeof(large_id));
            offer.request_n=sizeof(large_id)+3;
        }else{
            memmove(offer.request+4+sizeof(large_id),offer.request+3,
                    landmark_id_n);
            put(offer.request,sizeof(large_id)+landmark_id_n+2,2);
            offer.request[2]=(unsigned char)sizeof(large_id);
            memcpy(offer.request+3,large_id,sizeof(large_id));
            offer.request[3+sizeof(large_id)]=(unsigned char)landmark_id_n;
            offer.request_n=sizeof(large_id)+landmark_id_n+4;
        }
    }
    if(!mtc_server_add_candidate_unchecked(server_ctx,"32473.101",
                                           standalone,standalone_key)
       ||!mtc_server_add_candidate_unchecked(server_ctx,"32473.101.1.1.1",
                                             landmark,landmark_key)
       ||!SSL_CTX_add_custom_ext(client_ctx,MTC_EXT,CONTEXT,
                                 offer_add,NULL,&offer,offer_parse,&offer))
        goto end;
    SSL_CTX_set_verify(client_ctx,SSL_VERIFY_NONE,NULL);
    server=SSL_new(server_ctx);
    client=SSL_new(client_ctx);
    if(!server||!client
       ||!BIO_new_bio_pair(&server_bio,0,&client_bio,0))goto end;
    SSL_set_bio(server,server_bio,server_bio);
    SSL_set_bio(client,client_bio,client_bio);
    server_bio=client_bio=NULL;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);

    for(int step=0;step<100&&(!server_done||!client_done);step++){
        SSL *peers[2]={client,server};
        int *done[2]={&client_done,&server_done};
        for(int i=0;i<2;i++){
            int result,error;
            if(*done[i])continue;
            result=SSL_do_handshake(peers[i]);
            if(result==1){*done[i]=1;continue;}
            error=SSL_get_error(peers[i],result);
            if(error!=SSL_ERROR_WANT_READ&&error!=SSL_ERROR_WANT_WRITE)
                goto end;
        }
    }
    state=si>=0?SSL_get_ex_data(server,si):NULL;
    set=candidates_ci>=0?SSL_CTX_get_ex_data(server_ctx,candidates_ci):NULL;
    ok=server_done&&client_done&&state&&set
       &&state->server_selected==(both_eligible?1U:0U)
       &&state->server_selection_reason==(both_eligible?MTC_SELECT_LANDMARK:
                                          group_request?MTC_SELECT_STANDALONE:
                                          MTC_SELECT_FALLBACK_STANDALONE)
       &&SSL_get_certificate(server)==(both_eligible?landmark:standalone)
       &&offer.ee_count==1
       &&offer.certificate_marker_count==group_request
       &&offer.available_n==standalone_id_n+3
                              +(both_eligible?individual_landmark_id_n+1:0)
       &&offer.available[2]==(both_eligible?individual_landmark_id_n:
                                             standalone_id_n)
       &&!memcmp(offer.available+3,
                  both_eligible?individual_landmark_id:standalone_id,
                  both_eligible?individual_landmark_id_n:standalone_id_n)
       &&(!both_eligible
           ||(offer.available[3+individual_landmark_id_n]==standalone_id_n
              &&!memcmp(offer.available+4+individual_landmark_id_n,
                         standalone_id,standalone_id_n)))
       &&state->server_available_n==offer.available_n
       &&!memcmp(state->server_available,offer.available,offer.available_n);
end:
    printf("server_done=%d client_done=%d ee_count=%d marker_count=%d available_n=%zu\n",
           server_done,client_done,offer.ee_count,
           offer.certificate_marker_count,offer.available_n);
    puts(ok?(both_eligible
             ?"PASS: large and group CH selects Landmark; both IDs ordered; marker present"
             :large_request
             ?(large_only
               ?"PASS: large-only CH falls back without marker"
               :"PASS: large and group CH selects Standalone with marker")
             :(group_request
               ?"PASS: group matches only eligible Standalone ID; marker present"
               :"PASS: only eligible Standalone ID in EE; fallback has no marker"))
           :"FAIL: per-connection eligibility handshake");
    if(!ok)ERR_print_errors_fp(stderr);
    BIO_free(server_bio);
    BIO_free(client_bio);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    X509_free(standalone);
    X509_free(landmark);
    EVP_PKEY_free(standalone_key);
    EVP_PKEY_free(landmark_key);
    return ok?0:1;
}
