/** Merkle Tree Header File 
 * 
 * This file contains the specification of Merkle tree operations, including
 * calculating leaf and parent hashes, generating Merkle proofs, and verifying proofs.
 * It also includes functions to print Merkle hashes and proofs in a readable format.
 *
 */

#ifndef MERKLE_H
#define MERKLE_H

#include <stddef.h>
#include <stdbool.h>

// ===============================================
// Definition of data structures for Merkle Trees and Merkle Proofs
// ===============================================

#define HASH_SIZE 32    //Size of SHA-256 hash in bytes

// MerkleHash: Array to store the hash bytes
typedef struct {
    unsigned char bytes[HASH_SIZE]; 
} MerkleHash;

// ProofElement: Represents an element in a Merkle proof
// containing the hash and its position (left or right)
typedef struct {
    MerkleHash hash; 
    bool is_left;
} ProofElement;

// MerkleProof: Represents a complete Merkle proof with
// a list of ProofElements and the count of elements
typedef struct {
    ProofElement *elements;
    size_t count;
} MerkleProof;


// ===============================================
// Function declarations for Merkle Tree operations
// ===============================================
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
    MerkleHash *result);


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
    MerkleHash *result);

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
    MerkleHash *root);

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
    MerkleProof *proof);

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
    const MerkleHash *expected_root);

/** Function to free the memory allocated for a Merkle proof
 * Args:
 *     - proof: pointer to the MerkleProof structure to free
 */
void merkle_free_proof(MerkleProof *proof);


/** Function to print a Merkle hash in hexadecimal format
 * Args:
 *     - hash: pointer to the hash to print
 */
void print_merkle_hash(MerkleHash *hash);

/** Function to print the elements of a Merkle proof
 * Args:
 *     - proof: pointer to the MerkleProof structure to print
 */
void print_merkle_proof(MerkleProof *proof);

#endif