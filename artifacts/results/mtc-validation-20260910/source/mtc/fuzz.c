#include "mtc.c"
int main(int argc,char **argv){
    if(argc!=3)return 2;MTCConfig *c=mtc_load(argv[1],0);FILE *f=fopen(argv[2],"rb");
    if(!c||!f)return 2;unsigned char der[MTC_MAX],random[8192];size_t len=fread(der,1,sizeof(der),f);fclose(f);
    const unsigned char *p=der;X509 *x=d2i_X509(NULL,&p,(long)len);if(!x||!mtc_verify(x,c))return 2;
    const ASN1_BIT_STRING *value;X509_get0_signature(&value,NULL,x);ASN1_BIT_STRING *mut=(ASN1_BIT_STRING *)value;
    size_t n=(size_t)value->length;unsigned char *original=OPENSSL_memdup(value->data,n);if(!original)return 2;
    for(size_t i=0;i<n;i++){ASN1_STRING_set(mut,original,(int)i);if(mtc_verify(x,c))return 3;}
    uint32_t seed=42;for(unsigned i=0;i<20000;i++){
        seed=1664525*seed+1013904223;size_t size=seed%sizeof(random);
        for(size_t j=0;j<size;j++){seed=1664525*seed+1013904223;random[j]=(unsigned char)(seed>>24);}
        ASN1_STRING_set(mut,random,(int)size);if(mtc_verify(x,c))return 3;
    }
    OPENSSL_free(original);X509_free(x);mtc_free(c);puts("MTC parser fuzz: all truncations and 20000 deterministic inputs PASS");return 0;
}
