/* Offline native parser/credential tests. No sockets, measurements or TLS runs. */
#include "retry_tls.c"
#include <assert.h>

static int group_text(TLSConfig *config,const char *text){
    unsigned char id[80];size_t id_len;
    assert(id_encode(text,id,&id_len));
    return mtc_group_match(config,id,id_len);
}

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
    /* Initial CH group selects the exact landmark. EE still names .1, not .2. */
    SSL *group_peer=SSL_new(server);assert(group_peer);
    unsigned char group_list[93];size_t group_len=r->base.trust->request_signal_len;
    put(group_list,group_len+1,2);group_list[2]=(unsigned char)group_len;
    memcpy(group_list+3,r->base.trust->request_signal,group_len);
    assert(parse_one(group_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,group_list,group_len+3,NULL,0,&alert,&r->base));
    assert(state(group_peer,MTC_ROLE_SERVER_PRESENT)->matched);
    assert(add_one(group_peer,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,&out,&out_n,NULL,0,&alert,&r->base)==1);
    assert(out_n==r->base.n+3&&!memcmp(out+3,r->base.trust->signal,r->base.n));
    SSL_free(group_peer);
    /* Component parsing, not a last-three-bytes shortcut. */
    TLSConfig coordinates={0};unsigned char expected_group[80];size_t expected_len;
    assert(id_encode("32473.101.1.7.129",coordinates.id,&coordinates.n));
    assert(initial_group(&coordinates));
    assert(id_encode("32473.101.2.7.129",expected_group,&expected_len));
    assert(expected_len==coordinates.n&&!memcmp(expected_group,coordinates.group,expected_len));
    assert(id_encode("32473.101.2.1.1",coordinates.id,&coordinates.n));
    assert(!initial_group(&coordinates));
    assert(id_encode("32473.101",coordinates.id,&coordinates.n));
    assert(!initial_group(&coordinates));

    /* TAI Sections 3.1 and 4.2; MTC Sections 8.1 and 8.2.1. */
    TLSConfig landmark_range={0},standalone_range={0};
    assert(id_encode("32473.101.1.7.129",landmark_range.id,
                     &landmark_range.n));
    landmark_range.has_group=initial_group(&landmark_range);
    assert(landmark_range.has_group);
    landmark_range.group_n=landmark_range.n;

    /* A CA ID requests any usable credential under that CA.
       Mirror mtc_server(): no trust object is available here. */
    assert(!landmark_range.trust);
    assert(group_text(&landmark_range,"32473.101"));
    assert(!group_text(&landmark_range,"32473.102"));

    assert(group_text(&landmark_range,"32473.101.2.7.129"));
    assert(group_text(&landmark_range,"32473.101.2.7.130"));
    assert(!group_text(&landmark_range,"32473.101.2.7.128"));
    assert(!group_text(&landmark_range,"32473.101.2.8.129"));
    assert(!group_text(&landmark_range,"32473.102.2.7.129"));
    assert(!group_text(&landmark_range,"32473.101.2.7.129.1"));
    assert(!group_text(&landmark_range,"32473.101.1.7.129"));

    /*
     * draft-06 permits landmark numbers through 2^48-1.  Exercise the
     * first value above the former 32-bit implementation limit and the
     * protocol maximum.
     */
    TLSConfig landmark_2p32={0},landmark_2p48m1={0};

    assert(id_encode("32473.101.1.7.4294967296",
                     landmark_2p32.id,&landmark_2p32.n));
    landmark_2p32.has_group=initial_group(&landmark_2p32);
    assert(landmark_2p32.has_group);
    landmark_2p32.group_n=landmark_2p32.n;
    assert(group_text(&landmark_2p32,
                      "32473.101.2.7.4294967296"));
    assert(group_text(&landmark_2p32,
                      "32473.101.2.7.4294967297"));
    assert(!group_text(&landmark_2p32,
                       "32473.101.2.7.4294967295"));

    assert(id_encode("32473.101.1.7.281474976710655",
                     landmark_2p48m1.id,&landmark_2p48m1.n));
    landmark_2p48m1.has_group=initial_group(&landmark_2p48m1);
    assert(landmark_2p48m1.has_group);
    landmark_2p48m1.group_n=landmark_2p48m1.n;
    assert(group_text(&landmark_2p48m1,
                      "32473.101.2.7.281474976710655"));
    assert(group_text(&landmark_2p48m1,
                      "32473.101.2.7.281474976710656"));
    assert(!group_text(&landmark_2p48m1,
                       "32473.101.2.7.281474976710654"));

    assert(id_encode("32473.101",standalone_range.id,&standalone_range.n));
    assert(group_text(&standalone_range,"32473.101.2.1.1"));
    assert(group_text(&standalone_range,"32473.101.2.7.129"));
    assert(!group_text(&standalone_range,"32473.101.2"));
    assert(!group_text(&standalone_range,"32473.101.2.7"));
    assert(!group_text(&standalone_range,"32473.101.2.7.129.1"));
    assert(!group_text(&standalone_range,"32473.101"));

    unsigned char malformed_group[80];size_t malformed_len,prefix_len;
    assert(id_encode("32473.101.2.7",malformed_group,&prefix_len));
    malformed_group[prefix_len]=0x80;
    malformed_group[prefix_len+1]=0;
    malformed_len=prefix_len+2;
    assert(!mtc_group_match(&landmark_range,malformed_group,malformed_len));
    malformed_group[prefix_len]=0x81;
    malformed_len=prefix_len+1;
    assert(!mtc_group_match(&landmark_range,malformed_group,malformed_len));
    malformed_group[prefix_len]=0x82;
    memset(malformed_group+prefix_len+1,0x80,8);
    malformed_group[prefix_len+9]=0;
    malformed_len=prefix_len+10;
    assert(!mtc_group_match(&landmark_range,malformed_group,malformed_len));

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
