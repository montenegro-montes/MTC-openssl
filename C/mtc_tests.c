#include <stdio.h>

#include "crypto/mtc.h"

int main(int argc, char *argv[])
{
    MTCCertificate cert;
    MerkleHash hash;

    // Check command-line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <certificate.pem|certificate.der>\n", argv[0]);
        return 0;
    }

    // Load the certificate from the specified file
    if (!mtc_load(argv[1], &cert)) {
        fprintf(stderr, "Error: failed to load certificate '%s'\n", argv[1]);
        return 0;
    }
    printf("Certificate loaded successfully\n\n");

    // Print certificate information
    mtc_print(&cert);
    printf("\n");

    // Calculate the Merkle leaf hash for the certificate
    if (!mtc_leaf_hash(&cert, &hash)) {
        fprintf(stderr, "Error: failed to compute Merkle leaf hash\n");
        mtc_free(&cert);
        return 0;
    }

    // Print Merkle leaf hash
    printf("Merkle leaf hash:\n");
    print_merkle_hash(&hash);

    // Free memory
    mtc_free(&cert);

    return 1;
}