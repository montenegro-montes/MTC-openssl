#include "mtc.c"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void fill_hash(unsigned char hash[32], unsigned char value){
    memset(hash,value,32);
}

int main(void){
    unsigned char h1[32],h2[32],h3[32];
    MTCConfig *c;

    fill_hash(h1,0x11);
    fill_hash(h2,0x22);
    fill_hash(h3,0x33);

    /* Section 7.4 configuration requires landmark mode. */
    assert(!mtc_add_trusted_subtree(NULL,1,0,4,h1));

    c=OPENSSL_zalloc(sizeof(*c));
    assert(c);
    c->log=1;

    assert(!mtc_add_trusted_subtree(c,1,0,4,h1));

    c->landmark=1;

    /* Invalid log identifiers and hashes are rejected. */
    assert(!mtc_add_trusted_subtree(c,0,0,4,h1));
    assert(!mtc_add_trusted_subtree(c,2,0,4,h1));
    assert(!mtc_add_trusted_subtree(c,1,0,4,NULL));

    /* Invalid Section 4.1 intervals are rejected. */
    assert(!mtc_add_trusted_subtree(c,1,5,4,h1));
    assert(!mtc_add_trusted_subtree(c,1,1,5,h1));

    /* Multiple valid trusted-subtree entries coexist. */
    assert(mtc_add_trusted_subtree(c,1,0,4,h1));
    assert(mtc_add_trusted_subtree(c,1,4,8,h2));
    assert(mtc_add_trusted_subtree(c,1,8,12,h3));

    assert(c->ntrusted==3);
    assert(c->trusted[0].log==1);
    assert(c->trusted[0].start==0);
    assert(c->trusted[0].end==4);
    assert(!memcmp(c->trusted[0].hash,h1,32));

    assert(c->trusted[1].start==4);
    assert(c->trusted[1].end==8);
    assert(!memcmp(c->trusted[1].hash,h2,32));

    assert(c->trusted[2].start==8);
    assert(c->trusted[2].end==12);
    assert(!memcmp(c->trusted[2].hash,h3,32));

    /* The same (log,start,end) cannot acquire a second hash. */
    assert(!mtc_add_trusted_subtree(c,1,0,4,h2));
    assert(c->ntrusted==3);

    /* Section 7.4 storage is separate from MCF1 checkpoint subtrees. */
    assert(c->nsubs==0);

    mtc_free(c);

    /* Capacity is fail-closed: the 65th trusted subtree is rejected. */
    c=OPENSSL_zalloc(sizeof(*c));
    assert(c);
    c->landmark=1;
    c->log=1;

    for(unsigned i=0;i<MTC_MAX_TRUSTED_SUBTREES;i++){
        uint64_t start=(uint64_t)i*4;
        assert(mtc_add_trusted_subtree(c,1,start,start+4,h1));
    }

    assert(c->ntrusted==MTC_MAX_TRUSTED_SUBTREES);
    assert(!mtc_add_trusted_subtree(c,1,256,260,h1));

    mtc_free(c);

    puts("PASS: MTC trusted-subtree relying-party configuration");
    return 0;
}
