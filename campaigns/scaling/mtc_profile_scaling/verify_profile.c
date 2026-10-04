/* Manual offline check. Compile only during the operator's validation step. */
#include "mtc.c"
static int expected_key(EVP_PKEY *key,const char *name,const char *digest){
    if(!supported_signer_key(key)||!EVP_PKEY_is_a(key,name))return 0;
    const char *actual=ec_signer_digest(key);
    return actual?strcmp(actual,digest)==0:strcmp(digest,"-")==0;
}
int main(int argc,char **argv){
    /* trust, landmark flag, DER certificate, implementation, digest, CA, cosigner */
    if(argc!=8)return 2;
    int landmark=atoi(argv[2]);
    MTCConfig *c=landmark?mtc_load_trust_config_v2(argv[1])
                         :mtc_load_authority_config_v2(argv[1]);
    if(!c)return 1;
    int ok=!strcmp(c->caid,argv[6])&&!strcmp(c->signers[0].id,argv[6])&&!strcmp(c->signers[1].id,argv[7]);
    for(unsigned i=0;i<c->count;i++)ok=ok&&expected_key(c->signers[i].key,argv[4],argv[5]);
    FILE *f=fopen(argv[3],"rb");unsigned char buf[MTC_MAX];size_t n=f?fread(buf,1,sizeof(buf),f):0;int extra=f?fgetc(f):0;
    if(f)fclose(f);
    const unsigned char *p=buf;X509 *x=n?d2i_X509(NULL,&p,(long)n):NULL;
    ok=ok&&x&&extra==EOF&&p==buf+n&&expected_key(X509_get0_pubkey(x),argv[4],argv[5])&&mtc_verify(x,c);
    X509_free(x);mtc_free(c);return ok?0:1;
}
