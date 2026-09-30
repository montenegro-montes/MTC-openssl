#include "mtc.c"
#include <stdio.h>

static int fail(const char *message){
    fprintf(stderr,"check-revoked: %s\n",message);
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

static int load_and_verify(const char *trust,int landmark,X509 *x,
                           int revoke,uint64_t first,uint64_t last,
                           int expected){
    MTCConfig *c=mtc_load(trust,landmark);
    int actual;

    if(!c)return 0;
    if(revoke&&!mtc_add_revoked_serial_range(c,first,last)){
        mtc_free(c);
        return 0;
    }

    actual=mtc_verify(x,c);
    mtc_free(c);
    return actual==expected;
}

int main(int argc,char **argv){
    X509 *x;
    uint64_t serial=0;
    int landmark;

    if(argc!=4){
        fprintf(stderr,"usage: check-revoked TRUST 0|1 CERT\n");
        return 2;
    }

    if(!strcmp(argv[2],"1"))landmark=1;
    else if(!strcmp(argv[2],"0"))landmark=0;
    else{
        fprintf(stderr,"check-revoked: mode must be 0 or 1\n");
        return 2;
    }

    x=read_der(argv[3]);
    if(!x)return fail("cannot parse canonical DER certificate");

    if(!ASN1_INTEGER_get_uint64(&serial,X509_get_serialNumber(x))){
        X509_free(x);
        return fail("certificate serial is not uint64");
    }

    /* Positive control: the real certificate verifies normally. */
    if(!load_and_verify(argv[1],landmark,x,0,0,0,1)){
        X509_free(x);
        return fail("positive control verification failed");
    }

    /* Revoking exactly this certificate serial must reject it. */
    if(!load_and_verify(argv[1],landmark,x,1,serial,serial,0)){
        X509_free(x);
        return fail("revoked certificate was not rejected");
    }

    /* Neighboring serials must not revoke this certificate. */
    if(serial>0&&!load_and_verify(
            argv[1],landmark,x,1,serial-1,serial-1,1)){
        X509_free(x);
        return fail("previous-serial range incorrectly rejected certificate");
    }

    if(serial<UINT64_MAX&&!load_and_verify(
            argv[1],landmark,x,1,serial+1,serial+1,1)){
        X509_free(x);
        return fail("next-serial range incorrectly rejected certificate");
    }

    X509_free(x);
    printf("PASS: real MTC certificate serial %llu obeys revoked-range policy\n",
           (unsigned long long)serial);
    return 0;
}
