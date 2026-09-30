/* Offline tool: the first argument MUST be independently trusted authority.bin.
 * MCF1 is local lab storage. No TLS and no landmark allocation/update here. */
#include "mtc.c"
int main(int argc,char **argv){
    if(argc!=3){fprintf(stderr,"Usage: check_snapshot TRUSTED_AUTHORITY SNAPSHOT\n");return 2;}
    MTCConfig *trusted=mtc_load(argv[1],0),*snapshot=NULL;int ok=0;
    if(!trusted)goto end;
    snapshot=mtc_load(argv[2],1); /* Existing checkpoint signature/root checks. */
    if(!snapshot||strcmp(trusted->caid,snapshot->caid)||trusted->log!=snapshot->log||
       trusted->count!=snapshot->count||snapshot->min<trusted->min||snapshot->max>trusted->max)goto end;
    for(unsigned i=0;i<trusted->count;i++){
        if(strcmp(trusted->signers[i].id,snapshot->signers[i].id)||
           EVP_PKEY_eq(trusted->signers[i].key,snapshot->signers[i].key)!=1)goto end;
    }
    /* Output only after BOTH authentication and independent key pinning pass. */
    printf("{\"tree_size\":%llu,\"hash\":\"",(unsigned long long)snapshot->size);
    for(unsigned i=0;i<32;i++)printf("%02x",snapshot->root[i]);
    printf("\"}\n");ok=1;
end:
    if(!ok)fprintf(stderr,"Snapshot authentication or trusted identity/key check failed\n");
    mtc_free(snapshot);mtc_free(trusted);return ok?0:1;
}
