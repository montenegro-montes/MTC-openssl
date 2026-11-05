/* Offline native parser/credential tests. No sockets, measurements or TLS runs. */
#include "retry_tls.c"
#include <assert.h>

static int group_text(TLSConfig *config,const char *text){
    unsigned char id[80];size_t id_len;
    assert(id_encode(text,id,&id_len));
    return mtc_group_match(config,id,id_len);
}

static size_t id_list(unsigned char *out,const char *text){
    size_t n;
    assert(id_encode(text,out+3,&n));
    put(out,n+1,2);out[2]=(unsigned char)n;
    return n+3;
}

int main(int argc,char **argv) {
    SSL_CTX *server,*client;SSL *s,*cl;BIO *bio;X509 *cert;EVP_PKEY *key;
    const unsigned char *out;size_t out_n;int alert=0;
    const char *hostname;
    assert(argc==4||argc==5);hostname=argc==5?argv[4]:"server";
    bio=BIO_new_file(argv[2],"r");assert(bio);cert=PEM_read_bio_X509(bio,NULL,NULL,NULL);BIO_free(bio);assert(cert);
    bio=BIO_new_file(argv[3],"r");assert(bio);key=PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);BIO_free(bio);assert(key);
    server=SSL_CTX_new(TLS_server_method());client=SSL_CTX_new(TLS_client_method());assert(server&&client);
    assert(retry_configure(server,argv[1],1,NULL,cert,key));
    assert(retry_configure(client,argv[1],1,"32473.9.1.1.1",NULL,NULL));
    RetryConfig *r=(RetryConfig *)SSL_CTX_get_ex_data(server,retry_ci),*c=(RetryConfig *)SSL_CTX_get_ex_data(client,retry_ci);
    {
        unsigned char encoded[80];size_t encoded_n;
        const char *valid[]={
            "4294967296",
            "281474976710655",
            "18446744073709551615",
        };
        for(size_t i=0;i<sizeof(valid)/sizeof(valid[0]);i++){
            assert(id_encode(valid[i],encoded,&encoded_n));
            assert(retry_id_valid((Slice){encoded,encoded_n}));
        }
        const unsigned char overflow[]={
            0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
        };
        const unsigned char noncanonical[]={0x80,0x00};
        const unsigned char unterminated[]={0x81};
        const unsigned char too_long[33]={0};
        assert(!retry_id_valid((Slice){overflow,sizeof(overflow)}));
        assert(wire_id_valid((Slice){overflow,sizeof(overflow)}));
        assert(!retry_id_valid((Slice){noncanonical,sizeof(noncanonical)}));
        assert(!wire_id_valid((Slice){noncanonical,sizeof(noncanonical)}));
        assert(!retry_id_valid((Slice){unterminated,sizeof(unterminated)}));
        assert(!wire_id_valid((Slice){unterminated,sizeof(unterminated)}));
        assert(!retry_id_valid((Slice){too_long,sizeof(too_long)}));
    }
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
    {
        const unsigned char large_id[]={
            0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
        };
        size_t list_n=2;
        group_list[list_n++]=(unsigned char)sizeof(large_id);
        memcpy(group_list+list_n,large_id,sizeof(large_id));
        list_n+=sizeof(large_id);
        put(group_list,list_n-2,2);
        group_peer=SSL_new(server);assert(group_peer);
        assert(parse_one(group_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                         group_list,list_n,NULL,0,&alert,&r->base));
        assert(!state(group_peer,MTC_ROLE_SERVER_PRESENT)->matched);
        assert(retry_parse(group_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                           group_list,list_n,NULL,0,&alert,r));
        assert(!retry_state(group_peer)->matched);
        SSL_free(group_peer);
        group_list[list_n++]=(unsigned char)group_len;
        memcpy(group_list+list_n,r->base.trust->request_signal,group_len);
        list_n+=group_len;
        put(group_list,list_n-2,2);
        group_peer=SSL_new(server);assert(group_peer);
        assert(parse_one(group_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                         group_list,list_n,NULL,0,&alert,&r->base));
        assert(state(group_peer,MTC_ROLE_SERVER_PRESENT)->matched);
        assert(retry_parse(group_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                           group_list,list_n,NULL,0,&alert,r));
        assert(retry_state(group_peer)->matched);
        SSL_free(group_peer);
        put(group_list,group_len+1,2);
        group_list[2]=(unsigned char)group_len;
        memcpy(group_list+3,r->base.trust->request_signal,group_len);
    }
    /* A matching first ID cannot hide a later overlong wire ID. */
    size_t oversized_list_n=group_len+3;
    group_list[oversized_list_n++]=33;
    memset(group_list+oversized_list_n,0,33);oversized_list_n+=33;
    put(group_list,oversized_list_n-2,2);
    SSL *oversized_peer=SSL_new(server);assert(oversized_peer);
    assert(!parse_one(oversized_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                      group_list,oversized_list_n,NULL,0,&alert,&r->base));
    assert(alert==SSL_AD_HANDSHAKE_FAILURE);
    SSL_free(oversized_peer);
    char oversized_text[66];
    for(size_t i=0;i<33;i++){
        oversized_text[2*i]='0';
        oversized_text[2*i+1]=i==32?'\0':'.';
    }
    SSL_CTX *oversized_ctx=SSL_CTX_new(TLS_server_method());
    assert(oversized_ctx);
    assert(!mtc_server(oversized_ctx,oversized_text));
    SSL_CTX_free(oversized_ctx);
    oversized_text[63]='\0'; /* 32 one-byte components fit exactly. */
    SSL_CTX *boundary_ctx=SSL_CTX_new(TLS_server_method());
    assert(boundary_ctx&&mtc_server(boundary_ctx,oversized_text));
    SSL_CTX_free(boundary_ctx);
    /* TAI-06 Sections 5.1/5.6: an absent extension invokes no parser, while a
       present empty Requested list is valid discovery and matches nothing. */
    SSL *absent_peer=SSL_new(server);assert(absent_peer);
    assert(SSL_get_ex_data(absent_peer,si)==NULL);
    SSL_free(absent_peer);
    const unsigned char empty_request[]={0,0};
    SSL *empty_peer=SSL_new(server);assert(empty_peer);
    assert(parse_one(empty_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                     empty_request,sizeof(empty_request),NULL,0,&alert,
                     &r->base));
    assert(!state(empty_peer,MTC_ROLE_SERVER_PRESENT)->matched);
    assert(add_one(empty_peer,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                   &out,&out_n,NULL,0,&alert,&r->base)==1);
    assert(out_n==r->base.n+3);
    assert(add_one(empty_peer,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                   &out,&out_n,NULL,0,&alert,&r->base)!=1);
    SSL_free(empty_peer);

    SSL *empty_retry_peer=SSL_new(server);assert(empty_retry_peer);
    assert(retry_parse(empty_retry_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                       empty_request,sizeof(empty_request),NULL,0,&alert,r));
    assert(!retry_state(empty_retry_peer)->matched);
    assert(retry_add(empty_retry_peer,MTC_EXT,
                     SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                     &out,&out_n,NULL,0,&alert,r)==1);
    assert(out_n==r->base.n+3);
    assert(retry_add(empty_retry_peer,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                     &out,&out_n,NULL,0,&alert,r)==0);
    SSL_free(empty_retry_peer);
    /* Requested order is immaterial: inspect every ID before selecting B. */
    unsigned char multi_request[83],wrong_request[32];size_t wrong_n,request_n=2;
    assert(id_encode("32473.9.1.1.1",wrong_request,&wrong_n));
    multi_request[request_n++]=(unsigned char)wrong_n;
    memcpy(multi_request+request_n,wrong_request,wrong_n);request_n+=wrong_n;
    multi_request[request_n++]=(unsigned char)r->base.n;
    memcpy(multi_request+request_n,r->base.id,r->base.n);request_n+=r->base.n;
    put(multi_request,request_n-2,2);
    SSL *multi_request_peer=SSL_new(server);assert(multi_request_peer);
    assert(retry_parse(multi_request_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                       multi_request,request_n,NULL,0,&alert,r));
    assert(retry_state(multi_request_peer)->matched);
    SSL_free(multi_request_peer);
    multi_request[request_n++]=0;
    put(multi_request,request_n-2,2);
    multi_request_peer=SSL_new(server);assert(multi_request_peer);
    assert(!retry_parse(multi_request_peer,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                        multi_request,request_n,NULL,0,&alert,r));
    assert(alert==SSL_AD_DECODE_ERROR);
    SSL_free(multi_request_peer);
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
     * draft-07 permits landmark numbers through 2^48-1.  Exercise the
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

    /* The exact group sent by this connection accepts only individual
       landmarks in the same CA/log whose number is at most its bound. */
    TLSConfig group_client={0};TLSEndpointConfig group_endpoint={0};
    unsigned char available[83];size_t available_n;
    group_client.role=MTC_ROLE_CLIENT_VERIFY_SERVER;
    assert(id_encode("32473.101.1.2.1",group_client.id,&group_client.n));
    assert(id_encode("32473.101.2.2.2",group_client.group,
                     &group_client.group_n));
    group_client.has_group=1;
    SSL *group_client_ssl=SSL_new(client);assert(group_client_ssl);
    group_endpoint.verify=&group_client;
    assert(endpoint_add(group_client_ssl,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                        &out,&out_n,NULL,0,&alert,&group_endpoint)==1);
    assert(out_n==group_client.group_n+3
           &&!memcmp(out+3,group_client.group,group_client.group_n));
    TLSState *group_client_state=state(
        group_client_ssl,MTC_ROLE_CLIENT_VERIFY_SERVER);
    assert(group_client_state);
    assert(group_client_state->requested_group
           &&group_client_state->requested_n==group_client.group_n
           &&!memcmp(group_client_state->requested,group_client.group,
                      group_client.group_n));

    available_n=id_list(available,"32473.101.1.2.1");
    assert(parse_one(group_client_ssl,MTC_EXT,
                     SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                     available,available_n,NULL,0,&alert,&group_client));
    assert(parse_one(group_client_ssl,MTC_EXT,SSL_EXT_TLS1_3_CERTIFICATE,
                     (const unsigned char *)"",0,NULL,0,&alert,
                     &group_client));
    assert(group_client_state->confirmed);
    /* CertificateRequest uses the client-presentation route. A valid large
       ID is ignored locally; a later known ID still enables presentation. */
    {
        const unsigned char large_id[]={
            0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
        };
        TLSConfig client_present={0};
        TLSEndpointConfig client_endpoint={0};
        unsigned char requested[83];size_t requested_n=2;
        SSL *client_present_ssl=SSL_new(client);
        assert(client_present_ssl);
        client_present.role=MTC_ROLE_CLIENT_PRESENT;
        assert(id_encode("32473.101.1.1.1",client_present.id,
                         &client_present.n));
        client_endpoint.present=&client_present;
        requested[requested_n++]=(unsigned char)sizeof(large_id);
        memcpy(requested+requested_n,large_id,sizeof(large_id));
        requested_n+=sizeof(large_id);
        put(requested,requested_n-2,2);
        assert(endpoint_parse(client_present_ssl,MTC_EXT,
                              SSL_EXT_TLS1_3_CERTIFICATE_REQUEST,
                              requested,requested_n,NULL,0,&alert,
                              &client_endpoint));
        assert(!state(client_present_ssl,MTC_ROLE_CLIENT_PRESENT)->available);
        requested[requested_n++]=(unsigned char)client_present.n;
        memcpy(requested+requested_n,client_present.id,client_present.n);
        requested_n+=client_present.n;
        put(requested,requested_n-2,2);
        assert(endpoint_parse(client_present_ssl,MTC_EXT,
                              SSL_EXT_TLS1_3_CERTIFICATE_REQUEST,
                              requested,requested_n,NULL,0,&alert,
                              &client_endpoint));
        assert(state(client_present_ssl,MTC_ROLE_CLIENT_PRESENT)->available);
        assert(endpoint_add(client_present_ssl,MTC_EXT,
                            SSL_EXT_TLS1_3_CERTIFICATE,
                            &out,&out_n,NULL,0,&alert,&client_endpoint)==1);
        assert(out_n==0);
        requested[3]=0x80; /* malformed, noncanonical component */
        assert(!endpoint_parse(client_present_ssl,MTC_EXT,
                               SSL_EXT_TLS1_3_CERTIFICATE_REQUEST,
                               requested,requested_n,NULL,0,&alert,
                               &client_endpoint));
        SSL_free(client_present_ssl);
    }
    {
        const unsigned char large_id[]={
            0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
        };
        size_t list_n=2;
        available[list_n++]=(unsigned char)sizeof(large_id);
        memcpy(available+list_n,large_id,sizeof(large_id));
        list_n+=sizeof(large_id);
        put(available,list_n-2,2);
        group_client_state->available=0;
        assert(parse_one(group_client_ssl,MTC_EXT,
                         SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                         available,list_n,NULL,0,&alert,&group_client));
        assert(!group_client_state->available);
        available[list_n++]=(unsigned char)group_client.n;
        memcpy(available+list_n,group_client.id,group_client.n);
        list_n+=group_client.n;
        put(available,list_n-2,2);
        assert(parse_one(group_client_ssl,MTC_EXT,
                         SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                         available,list_n,NULL,0,&alert,&group_client));
        assert(group_client_state->available);
    }
    group_client_state->available=0;
    available_n=id_list(available,"32473.101.1.2.2");
    assert(parse_one(group_client_ssl,MTC_EXT,
                     SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                     available,available_n,NULL,0,&alert,&group_client));
    group_client_state->available=0;
    available_n=id_list(available,"32473.101.1.2.3");
    assert(!parse_one(group_client_ssl,MTC_EXT,
                      SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                      available,available_n,NULL,0,&alert,&group_client));
    available_n=id_list(available,"32473.101.1.1.2");
    assert(!parse_one(group_client_ssl,MTC_EXT,
                      SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                      available,available_n,NULL,0,&alert,&group_client));

    /* Without retained-landmark metadata the exact request sent is bare
       caID.  It may select only this configuration's individual landmark. */
    TLSConfig bare_client={0};TLSEndpointConfig bare_endpoint={0};
    bare_client.role=MTC_ROLE_CLIENT_VERIFY_SERVER;
    assert(id_encode("32473.101.1.2.2",bare_client.id,&bare_client.n));
    assert(id_encode("32473.101",bare_client.group,&bare_client.group_n));
    bare_client.has_group=1;bare_endpoint.verify=&bare_client;
    SSL *bare_client_ssl=SSL_new(client);assert(bare_client_ssl);
    assert(endpoint_add(bare_client_ssl,MTC_EXT,SSL_EXT_CLIENT_HELLO,
                        &out,&out_n,NULL,0,&alert,&bare_endpoint)==1);
    assert(out_n==bare_client.group_n+3
           &&!memcmp(out+3,bare_client.group,bare_client.group_n));
    available_n=id_list(available,"32473.101.1.2.2");
    assert(parse_one(bare_client_ssl,MTC_EXT,
                     SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                     available,available_n,NULL,0,&alert,&bare_client));
    state(bare_client_ssl,MTC_ROLE_CLIENT_VERIFY_SERVER)->available=0;
    available_n=id_list(available,"32473.102.1.2.2");
    assert(!parse_one(bare_client_ssl,MTC_EXT,
                      SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                      available,available_n,NULL,0,&alert,&bare_client));
    SSL_free(bare_client_ssl);

    group_client_state->requested_group=0;
    group_client_state->requested_n=group_client.n;
    memcpy(group_client_state->requested,group_client.id,group_client.n);
    available_n=id_list(available,"32473.101.1.2.1");
    assert(parse_one(group_client_ssl,MTC_EXT,
                     SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                     available,available_n,NULL,0,&alert,&group_client));
    SSL_free(group_client_ssl);

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
    /* A second, untrusted available ID may precede the authenticated one. */
    unsigned char multi_available[83],other_id[32];size_t other_n,pos=2;
    assert(id_encode("32473.102.1.1.1",other_id,&other_n));
    multi_available[pos++]=(unsigned char)other_n;
    memcpy(multi_available+pos,other_id,other_n);pos+=other_n;
    multi_available[pos++]=(unsigned char)c->base.n;
    memcpy(multi_available+pos,c->base.id,c->base.n);pos+=c->base.n;
    put(multi_available,pos-2,2);
    retry_state(cl)->available=0;
    assert(retry_parse(cl,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                       multi_available,pos,NULL,0,&alert,c));
    assert(retry_state(cl)->available);
    {
        const unsigned char large_id[]={
            0x82,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00
        };
        size_t list_n=2;
        multi_available[list_n++]=(unsigned char)sizeof(large_id);
        memcpy(multi_available+list_n,large_id,sizeof(large_id));
        list_n+=sizeof(large_id);
        multi_available[list_n++]=(unsigned char)c->base.n;
        memcpy(multi_available+list_n,c->base.id,c->base.n);
        list_n+=c->base.n;
        put(multi_available,list_n-2,2);
        retry_state(cl)->available=0;
        assert(retry_parse(cl,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                           multi_available,list_n,NULL,0,&alert,c));
        assert(retry_state(cl)->available);
    }
    retry_state(cl)->available=0;
    multi_available[2]=(unsigned char)other_n;
    memcpy(multi_available+3,other_id,other_n);
    put(multi_available,other_n+1,2);
    assert(!retry_parse(cl,MTC_EXT,SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                        multi_available,other_n+3,NULL,0,&alert,c));
    assert(alert==SSL_AD_UNKNOWN_CA&&!retry_state(cl)->available);
    /* Invoke the unchanged authentication callback with real leaf constraints. */
    X509_STORE *store=X509_STORE_new();X509_STORE_CTX *check=X509_STORE_CTX_new();
    assert(store&&check&&X509_STORE_CTX_init(check,store,cert,NULL));
    assert(X509_STORE_CTX_set_ex_data(check,SSL_get_ex_data_X509_STORE_CTX_idx(),cl));
    assert(X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(check),"wrong.invalid",0));
    assert(!verify(check,&c->base));
    assert(X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(check),hostname,0));
    assert(verify(check,&c->base));
    X509_STORE_CTX_free(check);X509_STORE_free(store);
    /* CASE D: malformed/canonicality/duplicate handling. */
    const unsigned char malformed[][8]={{0,1},{0,1,0},{0,3,2,0x80,1},{0,2,1,0x81},{0,3,1,1,0}};
    const size_t lengths[]={2,3,5,4,5};
    for(size_t i=0;i<5;i++){
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
