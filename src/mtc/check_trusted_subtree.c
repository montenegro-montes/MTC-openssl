#include "mtc.c"
#include <stdio.h>

static int fail(const char *message){
    fprintf(stderr,"check-trusted-subtree: %s\n",message);
    return 1;
}

static X509 *read_der(const char *path){
    FILE *f=fopen(path,"rb");
    unsigned char buf[MTC_MAX];
    size_t n;
    int extra;
    const unsigned char *p;
    X509 *x;

    if(!f)return NULL;
    n=fread(buf,1,sizeof(buf),f);
    extra=fgetc(f);
    fclose(f);
    if(n==0||extra!=EOF)return NULL;

    p=buf;
    x=d2i_X509(NULL,&p,(long)n);
    if(!x||p!=buf+n){
        X509_free(x);
        return NULL;
    }
    return x;
}

static int verify_with_subtree(const char *trust,X509 *x,
                               uint64_t log_number,
                               uint64_t start,uint64_t end,
                               const unsigned char hash[32],
                               int install,int expected){
    MTCConfig *c=mtc_load(trust,1);
    int actual;

    if(!c)return 0;
    if(install&&!mtc_add_trusted_subtree(
            c,log_number,start,end,hash)){
        mtc_free(c);
        return 0;
    }

    actual=mtc_verify(x,c);
    mtc_free(c);
    return actual==expected;
}

static int hex_hash(const char *text,unsigned char out[32]){
    if(strlen(text)!=64)return 0;
    for(unsigned i=0;i<32;i++){
        unsigned value;
        if(sscanf(text+2*i,"%2x",&value)!=1)return 0;
        out[i]=(unsigned char)value;
    }
    return 1;
}

int main(int argc,char **argv){
    X509 *x;
    unsigned char hash[32],wrong[32];
    uint64_t log_number,start,end;

    if(argc!=7){
        fprintf(stderr,
                "usage: check-trusted-subtree TRUST CERT LOG START END HASH_HEX\n");
        return 2;
    }

    log_number=strtoull(argv[3],NULL,10);
    start=strtoull(argv[4],NULL,10);
    end=strtoull(argv[5],NULL,10);
    if(!hex_hash(argv[6],hash))
        return fail("invalid subtree hash");

    x=read_der(argv[2]);
    if(!x)return fail("cannot parse canonical DER certificate");

    /*
     * A landmark-relative certificate for this new interval must not
     * verify from the checkpoint's historical covering subtrees alone.
     */
    if(!verify_with_subtree(
            argv[1],x,log_number,start,end,hash,0,0)){
        X509_free(x);
        return fail("certificate unexpectedly trusted without configured subtree");
    }

    if(!verify_with_subtree(
            argv[1],x,log_number,start,end,hash,1,1)){
        X509_free(x);
        return fail("configured trusted subtree did not verify certificate");
    }

    memcpy(wrong,hash,32);
    wrong[0]^=1;

    if(!verify_with_subtree(
            argv[1],x,log_number,start,end,wrong,1,0)){
        X509_free(x);
        return fail("wrong trusted-subtree hash did not reject certificate");
    }

    X509_free(x);
    puts("PASS: real landmark-relative certificate obeys trusted-subtree policy");
    return 0;
}
