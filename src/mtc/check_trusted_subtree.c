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

static int verify_with_mts1(const char *trust,const char *mts1,
                            X509 *x,int load,int expected){
    MTCConfig *c=mtc_load(trust,1);
    int actual;

    if(!c)return 0;

    if(load&&!mtc_load_trusted_subtrees(c,mts1)){
        mtc_free(c);
        return 0;
    }

    actual=mtc_verify(x,c);
    mtc_free(c);
    return actual==expected;
}

int main(int argc,char **argv){
    X509 *x;

    if(argc!=4){
        fprintf(stderr,
                "usage: check-trusted-subtree TRUST CERT MTS1\n");
        return 2;
    }

    x=read_der(argv[2]);
    if(!x)
        return fail("cannot parse canonical DER certificate");

    /*
     * The evolved landmark-relative certificate must not verify from the
     * historical MCF1 checkpoint subtrees alone.
     */
    if(!verify_with_mts1(argv[1],argv[3],x,0,0)){
        X509_free(x);
        return fail(
            "certificate unexpectedly trusted without MTS1 configuration"
        );
    }

    /*
     * Loading the relying-party MTS1 configuration must make the same
     * certificate verifiable through the Section 7.4 trusted subtree.
     */
    if(!verify_with_mts1(argv[1],argv[3],x,1,1)){
        X509_free(x);
        return fail(
            "MTS1 trusted subtree did not verify certificate"
        );
    }

    X509_free(x);
    puts("PASS: real landmark-relative certificate obeys MTS1 trusted-subtree policy");
    return 0;
}
