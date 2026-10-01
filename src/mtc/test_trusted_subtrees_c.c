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

    /*
     * MTS1 loader: use a real landmark-mode configuration object and verify
     * framing, semantic validation, duplicate rejection and atomic rollback.
     */
    {
        const char *path="test-trusted-subtrees.mts1";
        unsigned char file[6+3*46];
        FILE *f;
        size_t pos;

        c=OPENSSL_zalloc(sizeof(*c));
        assert(c);
        c->landmark=1;
        c->log=1;

        memcpy(file,"MTS1",4);
        file[4]=0;
        file[5]=3;
        pos=6;

#define PUT_BE(value,width) do { \
            uint64_t put_value=(uint64_t)(value); \
            for(unsigned put_i=0;put_i<(width);put_i++) \
                file[pos+(width)-1-put_i]=(unsigned char)(put_value>>(8*put_i)); \
            pos+=(width); \
        } while(0)

#define PUT_ENTRY(log_value,start_value,end_value,hash_value) do { \
            PUT_BE((log_value),2); \
            PUT_BE((start_value),6); \
            PUT_BE((end_value),6); \
            memcpy(file+pos,(hash_value),32); \
            pos+=32; \
        } while(0)

        PUT_ENTRY(1,0,4,h1);
        PUT_ENTRY(1,4,8,h2);
        PUT_ENTRY(1,8,12,h3);

        assert(pos==sizeof(file));

        f=fopen(path,"wb");
        assert(f);
        assert(fwrite(file,1,sizeof(file),f)==sizeof(file));
        assert(!fclose(f));

        assert(mtc_load_trusted_subtrees(c,path));
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

        /*
         * A second file containing a duplicate of an installed tuple fails
         * and leaves the existing configuration unchanged.
         */
        assert(!mtc_load_trusted_subtrees(c,path));
        assert(c->ntrusted==3);

        remove(path);

        /* Bad magic. */
        memcpy(file,"BAD!",4);
        f=fopen(path,"wb");
        assert(f);
        assert(fwrite(file,1,sizeof(file),f)==sizeof(file));
        assert(!fclose(f));
        assert(!mtc_load_trusted_subtrees(c,path));
        assert(c->ntrusted==3);
        remove(path);

        /* Truncated MTS1. */
        memcpy(file,"MTS1",4);
        f=fopen(path,"wb");
        assert(f);
        assert(fwrite(file,1,sizeof(file)-1,f)==sizeof(file)-1);
        assert(!fclose(f));
        assert(!mtc_load_trusted_subtrees(c,path));
        assert(c->ntrusted==3);
        remove(path);

        /*
         * Semantic failure after one otherwise valid entry must roll back
         * every entry added by this load operation.
         */
        mtc_free(c);
        c=OPENSSL_zalloc(sizeof(*c));
        assert(c);
        c->landmark=1;
        c->log=1;

        memcpy(file,"MTS1",4);
        file[4]=0;
        file[5]=3;
        pos=6;
        PUT_ENTRY(1,0,4,h1);
        PUT_ENTRY(2,4,8,h2);
        PUT_ENTRY(1,8,12,h3);

        f=fopen(path,"wb");
        assert(f);
        assert(fwrite(file,1,sizeof(file),f)==sizeof(file));
        assert(!fclose(f));

        assert(!mtc_load_trusted_subtrees(c,path));
        assert(c->ntrusted==0);
        remove(path);

        /* Invalid Section 4.1 subtree is rejected atomically. */
        pos=6;
        memcpy(file,"MTS1",4);
        file[4]=0;
        file[5]=3;
        PUT_ENTRY(1,0,4,h1);
        PUT_ENTRY(1,1,5,h2);
        PUT_ENTRY(1,8,12,h3);

        f=fopen(path,"wb");
        assert(f);
        assert(fwrite(file,1,sizeof(file),f)==sizeof(file));
        assert(!fclose(f));

        assert(!mtc_load_trusted_subtrees(c,path));
        assert(c->ntrusted==0);
        remove(path);

        /* Empty MTS1 is structurally valid and installs nothing. */
        {
            static const unsigned char empty[]={
                'M','T','S','1',0,0
            };
            f=fopen(path,"wb");
            assert(f);
            assert(fwrite(empty,1,sizeof(empty),f)==sizeof(empty));
            assert(!fclose(f));

            assert(mtc_load_trusted_subtrees(c,path));
            assert(c->ntrusted==0);
            remove(path);
        }

        /* Count 65 is rejected before entries are parsed. */
        {
            static const unsigned char over_limit[]={
                'M','T','S','1',0,65
            };
            f=fopen(path,"wb");
            assert(f);
            assert(fwrite(over_limit,1,sizeof(over_limit),f)==sizeof(over_limit));
            assert(!fclose(f));

            assert(!mtc_load_trusted_subtrees(c,path));
            assert(c->ntrusted==0);
            remove(path);
        }

        mtc_free(c);

#undef PUT_ENTRY
#undef PUT_BE
    }

    puts("PASS: MTC trusted-subtree relying-party configuration and MTS1 loader");
    return 0;
}
