#include "mt_wire.h"
#include "mtc.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
/* Explicit input order, bounded offline generator; never overwrites a bundle. */
static int write_file(const char *dir, const char *name, const void *data, size_t n)
{
    char path[4096];
    FILE *f;
    int ok;
    int len = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (len < 0 || (size_t)len >= sizeof(path) || !(f = fopen(path, "wbx"))) return 0;
    ok = fwrite(data, 1, n, f) == n;
    if (fclose(f)) ok = 0;
    return ok;
}
int main(int argc, char **argv)
{
    MTCCertificate *certs;
    const unsigned char **data;
    size_t *lengths, n;
    unsigned char wire[MT_MAX_WIRE];
    MTRoot root;
    int result = 1;
    if (argc < 3 || argc > 1026) {
        fprintf(stderr, "Usage: mt_bundle NEW_DIRECTORY cert0.pem [cert1.pem ...] (max 1024)\n");
        return 1;
    }
    n = (size_t)argc - 2;
    certs = calloc(n, sizeof(*certs)); data = calloc(n, sizeof(*data)); lengths = calloc(n, sizeof(*lengths));
    if (!certs || !data || !lengths) goto end;
    for (size_t i = 0; i < n; i++) {
        if (!mtc_load(argv[i + 2], &certs[i])) goto end;
        data[i] = certs[i].der; lengths[i] = certs[i].der_len;
    }
    root.leaves = (uint32_t)n;
    if (!merkle_root(data, lengths, n, &root.root) || !mt_root_encode(&root, wire)) goto end;
    if (mkdir(argv[1], 0700) || !write_file(argv[1], "root.bin", wire, MT_ROOT_SIZE)) goto end;
    for (size_t i = 0; i < n; i++) {
        MerkleProof proof = {0};
        char name[40];
        size_t len;
        int ok = merkle_generate_proof(data, lengths, n, i, &proof)
                 && mt_proof_encode(&root, (uint32_t)i, &proof, wire, sizeof(wire), &len);
        merkle_free_proof(&proof);
        snprintf(name, sizeof(name), "proof-%04zu.bin", i);
        if (!ok || !write_file(argv[1], name, wire, len)) goto end;
    }
    result = 0;
end:
    if (certs) for (size_t i = 0; i < n; i++) mtc_free(&certs[i]);
    free(certs); free(data); free(lengths);
    if (result) fprintf(stderr, "Bundle failed; output must be a new directory. Partial output, if any, is not valid.\n");
    return result;
}
