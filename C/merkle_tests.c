#include <stdint.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>

#include "crypto/merkle.h"

// Función principal para probar el cálculo de la raíz del árbol Merkle
int main(void)
{
    // Datos de las hojas del árbol Merkle
    const unsigned char *data[] = {
        (const unsigned char *)"block-1", 
        (const unsigned char *)"block-2", 
        (const unsigned char *)"block-3", 
        //(const unsigned char *)"block-4"
    };
    const size_t lengths[] = {
        strlen((const char *)data[0]), 
        strlen((const char *)data[1]), 
        strlen((const char *)data[2]), 
        //strlen((const char *)data[3])
    };
    int n_leaves = sizeof(data) / sizeof(data[0]);

    // ================================================
    // Test 1: Imprimir los datos del árbol Merkle
    // ================================================
    printf("Merkle Tree data:\n");
    for (int i = 0; i < n_leaves; i++){ 
        MerkleHash leaf_hash;
        merkle_leaf_hash(data[i], lengths[i], &leaf_hash);
        printf("├──[%d]: %s (%zu bytes): ", i, data[i], lengths[i]);
        print_merkle_hash(&leaf_hash);
    }

    // ================================================
    // Test 2: Calcular la raíz del árbol Merkle
    // ================================================
    MerkleHash root;
    if (!merkle_root(data, lengths, n_leaves, &root))
    {
        fprintf(stderr, "Error calculating Merkle root\n");
    }

    printf("\nMerkle root: ");
    print_merkle_hash(&root);
    
    // ================================================
    // Test 3: Generar y verificar una prueba de Merkle
    // ================================================
    MerkleProof proof;
    size_t leaf_index = 0; // Índice de la hoja para la que se generará la prueba
    printf("\nGenerating proof for %s:\n", data[leaf_index]);
    if (!merkle_generate_proof(data, lengths, n_leaves, leaf_index, &proof)){
        fprintf(stderr, "Error generating proof\n");
    }
    print_merkle_proof(&proof);

    /* Verificar prueba */
    int is_valid = merkle_verify_proof(data[leaf_index], lengths[leaf_index], &proof, &root);
    printf("Verification: %s\n", is_valid ? "VALID" : "INVALID");
    
    merkle_free_proof(&proof);
}