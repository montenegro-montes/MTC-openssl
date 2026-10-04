/* Focused structural tests for the typed local-format native loaders. */
#include "mtc.c"
#include <assert.h>

static uint64_t decimal(const char *value){
    char *end;unsigned long long result=strtoull(value,&end,10);
    assert(*value&&!*end);return (uint64_t)result;
}

static void signal_is(const unsigned char *actual,size_t actual_len,
                      const char *expected){
    unsigned char encoded[80];size_t encoded_len;
    assert(id_encode(expected,encoded,&encoded_len));
    assert(actual_len==encoded_len&&!memcmp(actual,encoded,encoded_len));
}

int main(int argc,char **argv){
    assert(argc>=3);
    if(!strcmp(argv[1],"authority")){
        MTCAuthorityV2 *value=mtc_load_authority_v2(argv[2]);
        assert(argc==6&&value);
        assert(value->log==decimal(argv[3]));
        assert(value->count==(size_t)decimal(argv[4]));
        assert(!value->count||value->signers[value->count-1].spki_len>=decimal(argv[5]));
        mtc_free_authority_v2(value);return 0;
    }
    if(!strcmp(argv[1],"checkpoint")){
        MTCCheckpointV2 *value=mtc_load_checkpoint_v2(argv[2]);
        assert(argc==5&&value);
        assert(value->size==decimal(argv[3]));
        assert(value->signature_count==(size_t)decimal(argv[4]));
        mtc_free_checkpoint_v2(value);return 0;
    }
    if(!strcmp(argv[1],"bundle")){
        MTCTrustBundleV2 *value=mtc_load_trust_bundle_v2(argv[2]);
        assert(argc==4&&value);
        if(!strcmp(argv[3],"none"))assert(!value->has_landmark);
        else assert(value->has_landmark&&value->landmark==decimal(argv[3]));
        mtc_free_trust_bundle_v2(value);return 0;
    }
    if(!strcmp(argv[1],"trust-config")){
        MTCConfig *value=mtc_load_trust_config_v2(argv[2]);
        assert(argc==6&&value);
        assert(value->number==decimal(argv[3]));
        signal_is(value->signal,value->signal_len,argv[4]);
        signal_is(value->request_signal,value->request_signal_len,argv[5]);
        mtc_free(value);return 0;
    }
    if(!strcmp(argv[1],"reject-authority")){
        MTCAuthorityV2 *value=mtc_load_authority_v2(argv[2]);
        assert(!value);return 0;
    }
    if(!strcmp(argv[1],"reject-checkpoint")){
        MTCCheckpointV2 *value=mtc_load_checkpoint_v2(argv[2]);
        assert(!value);return 0;
    }
    if(!strcmp(argv[1],"reject-bundle")){
        MTCTrustBundleV2 *value=mtc_load_trust_bundle_v2(argv[2]);
        assert(!value);return 0;
    }
    if(!strcmp(argv[1],"reject-trust-config")){
        MTCConfig *value=mtc_load_trust_config_v2(argv[2]);
        assert(!value);return 0;
    }
    return 2;
}
