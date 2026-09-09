#ifndef MT_WIRE_H
#define MT_WIRE_H
#include <stdint.h>
#include <stddef.h>
#include "merkle.h"
#define MT_MAX_DEPTH 20u
#define MT_MAX_LEAVES (1u << MT_MAX_DEPTH)
#define MT_ROOT_SIZE 40u
#define MT_PROOF_HEADER 45u
#define MT_MAX_WIRE (MT_PROOF_HEADER + 32u * MT_MAX_DEPTH)
typedef struct {
    uint32_t leaves;
    MerkleHash root;
} MTRoot;
typedef struct {
    MTRoot tree;
    uint32_t index;
    unsigned int depth;
    MerkleHash siblings[MT_MAX_DEPTH];
} MTProof;
int mt_root_encode(const MTRoot *root, unsigned char out[MT_ROOT_SIZE]);
int mt_root_decode(const unsigned char *in, size_t len, MTRoot *root);
int mt_proof_encode(const MTRoot *tree, uint32_t index, const MerkleProof *proof,
                    unsigned char *out, size_t capacity, size_t *len);
int mt_proof_decode(const unsigned char *in, size_t len, MTProof *proof);
int mt_proof_verify(const unsigned char *der, size_t len, const MTProof *proof,
                    const MTRoot *trusted);
int mt_read_file(const char *path, unsigned char *out, size_t cap, size_t *len);
#endif
