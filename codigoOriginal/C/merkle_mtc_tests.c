/*
 * mtc_tree_test.c
 *
 * Usage:
 *   ./mtc_tree_test <cert_directory>
 *
 * Example:
 *   ./mtc_tree_test ../Bash/certs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "crypto/mtc.h"
#include "crypto/merkle.h"

#define MAX_CERTS 1024
#define MAX_PATH_LEN 4096


static int leaf_hash_exists(
    const MerkleHash hashes[],
    size_t count,
    const MerkleHash *candidate)
{
    for (size_t i = 0; i < count; i++) {
        if (memcmp(hashes[i].bytes, candidate->bytes, sizeof(candidate->bytes)) == 0)
            return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    DIR *dir;
    struct dirent *entry;

    MTCCertificate certs[MAX_CERTS];
    MerkleHash leaf_hashes[MAX_CERTS];

    const char *cert_dir;

    // Parse input to get certificate directory 
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <certificate_directory>\n", argv[0]);
        return 1;
    }
    cert_dir = argv[1];

    // Open specified directory
    dir = opendir(cert_dir);
    if (!dir) {
        perror("opendir");
        return 1;
    }

    //Iterate over all files in the directory
    size_t cert_count = 0;
    printf("Loading certificates from %s...\n",cert_dir);
    while ((entry = readdir(dir)) != NULL) {

        MTCCertificate cert;
        MerkleHash leaf_hash;
        char filepath[MAX_PATH_LEN];

        // Obtain the file path and load it
        snprintf(filepath, sizeof(filepath), "%s/%s", cert_dir, entry->d_name);
        if (!mtc_load(filepath, &cert)) {
            //fprintf(stderr, "%s not loaded. Probably not a certificate file.\n", filepath);
            continue;
        }

        // Get the Merkle hash of the certificate
        if (!mtc_leaf_hash(&cert, &leaf_hash)) {
            fprintf(stderr, "Failed to compute leaf hash: %s\n", filepath);
            mtc_free(&cert);
            continue;
        }

        // Check if already exists
        if (leaf_hash_exists(leaf_hashes, cert_count, &leaf_hash))
        {
            //printf("[DUPLICATE] %s\n", entry->d_name);
            mtc_free(&cert);
            continue;
        }

        // Keep track of this certificate
        certs[cert_count] = cert;
        leaf_hashes[cert_count] = leaf_hash;

        // Update certifcate count
        cert_count++;
        if (cert_count >= MAX_CERTS) {
            fprintf(stderr, "Reached maximum number of certificates (%d)\n", MAX_CERTS);
            break;
        }
    }
    closedir(dir);

    // End if no certificates where found
    if (cert_count == 0) {
        fprintf(stderr, "No certificates loaded\n");
        return 1;
    }

    // ================================================
    // Test 1: Print Merkle tree data (certificates)
    // ================================================
    printf("Merkle Tree data:\n");
    size_t n_leaves = cert_count;
    for (int i = 0; i < n_leaves; i++){ 
        printf("├──[%d]: ", i);
        print_merkle_hash(&leaf_hashes[i]);
        mtc_print(&certs[i]);
    }

    // ================================================
    // Test 2: Compute the root of the Merkle tree
    // ================================================
    MerkleHash root;
    const unsigned char *data[MAX_CERTS];
    size_t lengths[MAX_CERTS];
    
    // Build the necessary parameters for computing the Merkle root
    for (size_t i = 0; i < cert_count; i++) {
        data[i] = certs[i].der;
        lengths[i] = certs[i].der_len;
    }

    if (!merkle_root(data, lengths, cert_count, &root))
    {
        fprintf(stderr, "Failed to compute Merkle root\n");
        
        for (size_t i = 0; i < cert_count; i++)
            mtc_free(&certs[i]);

        return 1;
    }
    printf("\nMerkle Root: ");
    print_merkle_hash(&root);


    // ================================================
    // Test 3: Generated and verify a Merkle proof
    // ================================================
    MerkleProof proof;
    size_t leaf_index = 0; // Leaf index for the proof
    printf("\nGenerating proof for leaf %zu:\n", leaf_index);
    if (!merkle_generate_proof(data, lengths, n_leaves, leaf_index, &proof)){
        fprintf(stderr, "Error generating proof\n");
    }
    print_merkle_proof(&proof);

    /* Verificar prueba */
    int is_valid = merkle_verify_proof(data[leaf_index], lengths[leaf_index], &proof, &root);
    printf("Verification: %s\n", is_valid ? "VALID" : "INVALID");
    
    merkle_free_proof(&proof);

    // Free memory
    for (size_t i = 0; i < cert_count; i++)
        mtc_free(&certs[i]);

    return 0;
}