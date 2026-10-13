/* Focused transitional check: MTC-07 CA certificate reconciled with MCA2. */
#include "mtc.c"
int main(int argc,char **argv){
    MTCConfig *config;
    if(argc!=4){fprintf(stderr,"Usage: check-mtc-ca AUTHORITY MTC_CA_CERTIFICATE REPRESENTATION_ROOT\n");return 2;}
    config=mtc_load_authority_config_with_ca_v2(argv[1],argv[2],argv[3]);
    if(!config){fprintf(stderr,"MTC CA certificate or MCA2 reconciliation failed\n");return 1;}
    mtc_free(config);puts("PASS: MTC-07 CA certificate matches MCA2 authority");return 0;
}
