#include <openssl/evp.h>
#include <stdint.h>
#include "merkle.h"

/** Calculates the SHA-256 value of several fragments:
 *
 *  MTH = H(prefix || left || right)
 *
 *  *  - prefix is a byte that indicates the type of node: 
 *      + 0x00 for leaves, 
 *      + 0x01 for internal nodes
 *  - left and right are Merkle hashes (leaves or trees). 
 *    Right can be NULL if we are constructing a leaf.
 */
static int merkle_hash_node( 
    uint8_t prefix,
    const unsigned char *left, 
    size_t left_len,
    const unsigned char *right, 
    size_t right_len, 
    MerkleHash *result)
{
    // Variables definition
    EVP_MD_CTX *ctx = NULL; 
    unsigned int digest_len = 0; 
    int ok = 0;

    // Verifies that the parameters are not NULL
    if (result == NULL || left == NULL)  return 0;

    // Initializes the Digest context
    ctx = EVP_MD_CTX_new(); 
    if (ctx == NULL) return 0; 

    // Initializes the Digest with SHA-256
    if (EVP_DigestInit_ex2(ctx, EVP_sha256(), NULL) != 1) { 
        goto cleanup;
    }

    // Updates the Digest with the prefix
    if (EVP_DigestUpdate(ctx, &prefix, sizeof(prefix)) != 1) { 
        goto cleanup;
    }

    // Updates the Digest with the left fragment
    if (EVP_DigestUpdate(ctx, left, left_len) != 1) { 
        goto cleanup;
    }

    // Updates the Digest with the right fragment
    if (right != NULL && right_len > 0) {
        if (EVP_DigestUpdate(ctx, right, right_len) != 1) {
            goto cleanup; 
        }
    }

    // Finalizes the Digest and obtains the resulting hash
    if (EVP_DigestFinal_ex(ctx, result->bytes, &digest_len) != 1) {
        goto cleanup; 
    }

    // Verifies that the digest length is the expected one
    if (digest_len != HASH_SIZE) { 
        goto cleanup;
    }

    // If here, everything went well
    ok = 1;

    cleanup: // Frees the Digest context
        EVP_MD_CTX_free(ctx); 
        return ok;
}

/** Calculates the hash of a leaf node in the Merkle tree 
 *  Args:
 *      - data: pointer to the data of the leaf prior to be hashed
 *      - data_len: length of the data
 *      - result: pointer to the MerkleHash structure where the result will be stored
 *  Returns:
 *      - 1 if the hash was calculated successfully
 *      - 0 if there was an error
 * */ 
int merkle_leaf_hash(
    const unsigned char *data, 
    size_t data_len, 
    MerkleHash *result)
{
    return merkle_hash_node(0x00, data, data_len, NULL, 0, result); 
}

/** Calculates the hash of a parent node in the Merkle tree 
 * Args:
 *      - left: pointer to the MerkleHash of the left child
 *      - right: pointer to the MerkleHash of the right child
 *      - result: pointer to the MerkleHash where the result will be stored
 * Returns:
 *      - 1 if the hash was calculated successfully
 *      - 0 if there was an error
*/
int merkle_parent_hash(
    const MerkleHash *left, 
    const MerkleHash *right, 
    MerkleHash *result)
{
    if (left == NULL || right == NULL || result == NULL)
        return 0;

    return merkle_hash_node(0x01, left->bytes, HASH_SIZE, right->bytes, HASH_SIZE, result); 
}

/** Calculates the root of the Merkle tree.
 * Args:
 *     - data: array of pointers to the data of the leaves prior to be hashed
 *     - lengths: array of lengths of the data
 *     - leaf_count: number of leaves (size of the data and lengths arrays)
 *     - root: pointer to the MerkleHash where the root will be stored
 * Returns:
 *     - 1 if the root was calculated successfully
 *     - 0 if there was an error
 */
int merkle_root(
    const unsigned char *const data[], 
    const size_t lengths[],
    size_t leaf_count,
    MerkleHash *root)
{
    MerkleHash *level = NULL;
    size_t level_count;

    // Verifies that the parameters are not NULL and that there is at least one leaf
    if (data == NULL || lengths == NULL || root == NULL || leaf_count == 0)
        return 0;
    
    // Allocates memory to store the hashes of the leaves
    level = calloc(leaf_count, sizeof(*level));
    if (level == NULL)
        return 0;
    
    // Calculates the hashes of the leaves
    for (size_t i = 0; i < leaf_count; i++){
        if (data[i] == NULL ||
            !merkle_leaf_hash(data[i], lengths[i], &level[i])){
            free(level);
            return 0;
        }
    }

    // Builds the Merkle tree upwards until reaching the root
    level_count = leaf_count;
    while (level_count > 1)
    {
        size_t parent_count = (level_count + 1) / 2;
        for (size_t i = 0; i < parent_count; i++)
        {
            size_t left_index = 2 * i;
            size_t right_index = left_index + 1;
            const MerkleHash *left = &level[left_index];
            const MerkleHash *right =
                right_index < level_count ? &level[right_index] : left;
            if (!merkle_parent_hash(left, right, &level[i])){
                free(level);
                return 0;
            }
        }
        level_count = parent_count;
    }
    // The root of the Merkle tree is the only hash remaining in the top level
    *root = level[0];
    free(level);
    return 1;
}


/** Function to print a Merkle hash in hexadecimal format
 * Args:
 *     - hash: pointer to the hash to print
 */
void print_merkle_hash(MerkleHash *hash)
{
    printf("0x");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        printf("%02x", hash->bytes[i]);
    }
    putchar('\n');
}

/** Function to print a Merkle hash in hexadecimal format, 
 *  showing only the first and last 4 bytes
 * Args:
 *     - hash: pointer to the hash to print
 */
static void print_merkle_hash_short(MerkleHash *hash)
{
    printf("0x");
    for (size_t i = 0; i < 4; i++)
    {
        printf("%02x", hash->bytes[i]);
    }
    printf("...");
    for (size_t i = HASH_SIZE - 4; i < HASH_SIZE; i++)
    {
        printf("%02x", hash->bytes[i]);
    }
    putchar('\n');
}

// Función para imprimir el árbol Merkle a partir de los datos de las hojas
static void print_merkle_tree(
    const unsigned char *const data[],
    const size_t lengths[],
    size_t leaf_count)
{
    // Verifica que los parámetros no sean NULL y que haya al menos una hoja
    if (data == NULL || lengths == NULL || leaf_count == 0)
        return;

    // Asigna memoria para almacenar los hashes de cada nivel del árbol
    MerkleHash *level = calloc(leaf_count, sizeof(MerkleHash));
    if (level == NULL)
        return;

    // Construcción de hojas
    for (size_t i = 0; i < leaf_count; i++)
    {
        merkle_leaf_hash(data[i], lengths[i], &level[i]);
    }

    // Construcción de niveles superiores
    size_t level_count = leaf_count;
    size_t level_number = 0;
    while (1)
    {
        printf("Level %zu (%zu nodes)\n", level_number, level_count);
        for (size_t i = 0; i < level_count; i++)
        {
            printf("├──[%zu]: ", i);
            print_merkle_hash_short(&level[i]);
        }

        if (level_count == 1)
            break;

        // Construcción de nodos internos 
        size_t parent_count = (level_count + 1) / 2;
        for (size_t i = 0; i < parent_count; i++)
        {
            size_t left_index = 2 * i;
            size_t right_index = left_index + 1;

            const MerkleHash *left = &level[left_index];
            const MerkleHash *right = (right_index < level_count) ? &level[right_index] : left;

            merkle_parent_hash(left, right, &level[i]);
        }

        level_count = parent_count;
        level_number++;
    }

    free(level);
}


/** Function to generate a Merkle proof for a specific leaf index
 * Args:
 *     - data: array of pointers to the data of the leaves prior to be hashed
 *     - lengths: array of lengths of the data
 *     - leaf_count: number of leaves (size of the data and lengths arrays)
 *     - target_index: index of the leaf for which to generate a proof
 *     - proof: pointer to the MerkleProof structure where the proof will be stored
 * Returns:
 *     - 1 if the proof was generated successfully
 *     - 0 if there was an error
 */
int merkle_generate_proof(
    const unsigned char *const data[],
    const size_t lengths[],
    size_t leaf_count,
    size_t target_index,
    MerkleProof *proof)
{
    if (data == NULL || lengths == NULL ||
        proof == NULL || target_index >= leaf_count)
        return 0;

    proof->count = 0;
    proof->elements = NULL;

    MerkleHash *level = calloc(leaf_count, sizeof(MerkleHash));
    if (level == NULL)
        return 0;

    // Calculates the hashes of the leaves
    for (size_t i = 0; i < leaf_count; i++)
    {
        if (!merkle_leaf_hash(data[i], lengths[i], &level[i])){
            free(level);
            return 0;
        }
    }

    // Allocates memory for the proof elements
    proof->elements = calloc(leaf_count, sizeof(ProofElement));
    if (proof->elements == NULL){
        free(level);
        return 0;
    }

    // Iterates through the levels of the Merkle tree to build the proof
    size_t index = target_index;
    size_t level_count = leaf_count;
    while (level_count > 1)
    {
        size_t sibling_index;
        // Determines the sibling index and whether it is a left or right
        if ((index % 2) == 0){
            sibling_index = (index + 1 < level_count) ? index + 1 : index;
            proof->elements[proof->count].hash = level[sibling_index];
            proof->elements[proof->count].is_left = 0;
        }else{
            sibling_index = index - 1;
            proof->elements[proof->count].hash = level[sibling_index];
            proof->elements[proof->count].is_left = 1;
        }

        proof->count++;

        // Builds the next level of the Merkle tree
        size_t parent_count = (level_count + 1) / 2;
        for (size_t i = 0; i < parent_count; i++)
        {
            size_t left_index = 2 * i;
            size_t right_index = left_index + 1;

            const MerkleHash *left = &level[left_index];
            const MerkleHash *right = (right_index < level_count) ? &level[right_index] : left;

            merkle_parent_hash(left, right, &level[i]);
        }

        index /= 2;
        level_count = parent_count;
    }

    free(level);
    return 1;
}

/** Function to free the memory allocated for a Merkle proof
 * Args:
 *     - proof: pointer to the MerkleProof structure to free
 */
void merkle_free_proof(MerkleProof *proof)
{
    if (proof == NULL)
        return;

    free(proof->elements);

    proof->elements = NULL;
    proof->count = 0;
}

/** Function to verify a Merkle proof
 * Args:
 *     - data: pointer to the data to verify prior to be hashed
 *     - data_len: length of the data
 *     - proof: pointer to the MerkleProof structure to verify
 *     - expected_root: pointer to the expected root hash of the Merkle tree
 * Returns:
 *     - 1 if the proof is valid
 *     - 0 if the proof is invalid
 */
int merkle_verify_proof(
    const unsigned char *data,       
    size_t data_len,           
    const MerkleProof *proof,        
    const MerkleHash *expected_root) 
{
    // Verifies that the parameters are not NULL
    if (data == NULL ||proof == NULL || expected_root == NULL)
        return 0;

    // Calculates the hash of the leaf corresponding to the provided data
    MerkleHash current;
    if (!merkle_leaf_hash(data, data_len, &current))
        return 0;

    // Iterates over the proof elements to compute the hash up to the root
    for (size_t i = 0; i < proof->count; i++)
    {
        MerkleHash next;

        if (proof->elements[i].is_left){
            if (!merkle_parent_hash(&proof->elements[i].hash, &current, &next))
                return 0;
        }else{
            if (!merkle_parent_hash(&current, &proof->elements[i].hash, &next))
                return 0;
        }
        current = next;
    }

    // Compares the calculated hash with the expected root of the Merkle tree
    return CRYPTO_memcmp(current.bytes, expected_root->bytes, HASH_SIZE) == 0;
}

/** Function to print the elements of a Merkle proof
 * Args:
 *     - proof: pointer to the MerkleProof structure to print
 */
void print_merkle_proof(MerkleProof *proof)
{
    if (proof == NULL)
        return;

    printf("Merkle Proof (%zu elements):\n", proof->count);

    for (size_t i = 0; i < proof->count; i++) {
        printf("├──[%zu] Sibling %s: ", i, proof->elements[i].is_left ? "LEFT " : "RIGHT");
        print_merkle_hash(&proof->elements[i].hash);
    }
}
