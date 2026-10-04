#include "mtc.c"
int main(int argc,char **argv){
    if(argc!=4)return 2;
    int landmark=atoi(argv[2]);
    MTCConfig *c=landmark?mtc_load_trust_config_v2(argv[1]):mtc_load_authority_config_v2(argv[1]);if(!c)return 1;
    FILE *f=fopen(argv[3],"rb");unsigned char buf[MTC_MAX];size_t n=f?fread(buf,1,sizeof(buf),f):0;int extra=f?fgetc(f):0;
    if(f)fclose(f);
    const unsigned char *p=buf;X509 *x=n?d2i_X509(NULL,&p,(long)n):NULL;
    int ok=x&&extra==EOF&&p==buf+n&&mtc_verify(x,c);
    X509_free(x);mtc_free(c);return ok?0:1;
}
