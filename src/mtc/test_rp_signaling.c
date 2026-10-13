#include "tls.c"
#include <assert.h>

static void expect_request(const char *trust,const char *mts1,
                           const char *certificate,const char *root,
                           const char *expected){
    SSL_CTX *ctx=SSL_CTX_new(TLS_method());
    TLSEndpointConfig *endpoint;
    TLSConfig *config;
    unsigned char encoded[80];
    size_t encoded_n;

    assert(ctx);
    assert(id_encode(expected,encoded,&encoded_n));
    assert(mtc_client(ctx,trust,1,mts1,certificate,root));

    endpoint=SSL_CTX_get_ex_data(ctx,ci);
    assert(endpoint);
    config=endpoint->verify;
    assert(config);
    assert(config->list_n==encoded_n+3);
    assert(config->list[0]==0);
    assert(config->list[1]==encoded_n+1);
    assert(config->list[2]==encoded_n);
    assert(!memcmp(config->list+3,encoded,encoded_n));

    SSL_CTX_free(ctx);
}

int main(int argc,char **argv){
    SSL_CTX *ctx;

    assert(argc==8);

    /*
     * argv:
     *   1 trust.bin
     *   2 RP generation with retained landmark
     *   3 RP generation with null retained landmark
     *   4 legacy RP generation without metadata
     *   5 RP generation with wrong-log metadata
     *   6 MTC CA certificate
     *   7 trusted representation root
     */

    {
        MTCConfig *trust=mtc_load_trust_config_v2(argv[1]);
        char retained[120];
        int retained_n;

        assert(trust);
        retained_n=snprintf(retained,sizeof(retained),"%s.2.%llu.1",
                            trust->caid,(unsigned long long)trust->log);
        assert(retained_n>0&&(size_t)retained_n<sizeof(retained));

        expect_request(argv[1],argv[2],argv[6],argv[7],retained);
        expect_request(argv[1],argv[3],argv[6],argv[7],trust->caid);
        expect_request(argv[1],argv[4],argv[6],argv[7],trust->caid);

        mtc_free(trust);
    }

    ctx=SSL_CTX_new(TLS_method());
    assert(ctx);
    assert(!mtc_client(ctx,argv[1],1,argv[5],argv[6],argv[7]));
    SSL_CTX_free(ctx);

    puts("PASS: RP retained-landmark signaling and fail-closed log binding");
    return 0;
}
