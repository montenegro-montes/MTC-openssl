/* Offline tool: independently trusted MCA2 authority plus MCP2 checkpoint. */
#include "mtc.c"
int main(int argc,char **argv){
    if(argc!=3){fprintf(stderr,"Usage: check_snapshot TRUSTED_AUTHORITY SNAPSHOT\n");return 2;}
    MTCAuthorityV2 *trusted=mtc_load_authority_v2(argv[1]);
    MTCCheckpointV2 *snapshot=mtc_load_checkpoint_v2(argv[2]);int ok=0;
    if(!trusted||!snapshot||snapshot->size-1>trusted->max-trusted->min||
       !mtc_authenticate_checkpoint_v2(trusted,snapshot))goto end;
    printf("{\"log_number\":%u,\"tree_size\":%llu,\"hash\":\"",
           (unsigned int)trusted->log,
           (unsigned long long)snapshot->size);
    for(unsigned i=0;i<32;i++)printf("%02x",snapshot->root[i]);
    printf("\"}\n");ok=1;
end:
    if(!ok)fprintf(stderr,"Snapshot authentication or trusted identity/key check failed\n");
    mtc_free_checkpoint_v2(snapshot);mtc_free_authority_v2(trusted);return ok?0:1;
}
