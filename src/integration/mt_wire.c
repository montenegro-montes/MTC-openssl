#include "mt_wire.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
           | ((uint32_t)p[2] << 8) | p[3];
}
static void put32(unsigned char *p, uint32_t n)
{
    p[0] = (unsigned char)(n >> 24); p[1] = (unsigned char)(n >> 16);
    p[2] = (unsigned char)(n >> 8); p[3] = (unsigned char)n;
}
static unsigned int depth_for(uint32_t n)
{
    unsigned int depth = 0;
    while (n > 1) { n = (n + 1) / 2; depth++; }
    return depth;
}
int mt_root_encode(const MTRoot *root, unsigned char out[MT_ROOT_SIZE])
{
    if (!root || !out || !root->leaves || root->leaves > MT_MAX_LEAVES) return 0;
    memcpy(out, "MTR1", 4); put32(out + 4, root->leaves);
    memcpy(out + 8, root->root.bytes, 32);
    return 1;
}
int mt_root_decode(const unsigned char *in, size_t len, MTRoot *root)
{
    if (!in || !root || len != MT_ROOT_SIZE || memcmp(in, "MTR1", 4)) return 0;
    root->leaves = get32(in + 4);
    if (!root->leaves || root->leaves > MT_MAX_LEAVES) return 0;
    memcpy(root->root.bytes, in + 8, 32);
    return 1;
}
int mt_proof_encode(const MTRoot *tree, uint32_t index, const MerkleProof *proof,
                    unsigned char *out, size_t capacity, size_t *len)
{
    unsigned int depth;
    uint32_t pos = index;
    if (!tree || !proof || !out || !len || !tree->leaves
        || tree->leaves > MT_MAX_LEAVES || index >= tree->leaves) return 0;
    depth = depth_for(tree->leaves);
    if (proof->count != depth || (depth && !proof->elements)
        || capacity < MT_PROOF_HEADER + 32u * depth) return 0;
    for (unsigned int i = 0; i < depth; i++, pos /= 2)
        if (proof->elements[i].is_left != (bool)(pos & 1)) return 0;
    memcpy(out, "MTP1", 4); put32(out + 4, tree->leaves); put32(out + 8, index);
    memcpy(out + 12, tree->root.bytes, 32); out[44] = (unsigned char)depth;
    for (unsigned int i = 0; i < depth; i++)
        memcpy(out + MT_PROOF_HEADER + 32u * i, proof->elements[i].hash.bytes, 32);
    *len = MT_PROOF_HEADER + 32u * depth;
    return 1;
}
int mt_proof_decode(const unsigned char *in, size_t len, MTProof *proof)
{
    if (!in || !proof || len < MT_PROOF_HEADER || len > MT_MAX_WIRE
        || memcmp(in, "MTP1", 4)) return 0;
    proof->tree.leaves = get32(in + 4); proof->index = get32(in + 8);
    proof->depth = in[44];
    if (!proof->tree.leaves || proof->tree.leaves > MT_MAX_LEAVES
        || proof->index >= proof->tree.leaves
        || proof->depth != depth_for(proof->tree.leaves)
        || len != MT_PROOF_HEADER + 32u * proof->depth) return 0;
    memcpy(proof->tree.root.bytes, in + 12, 32);
    for (unsigned int i = 0; i < proof->depth; i++)
        memcpy(proof->siblings[i].bytes, in + MT_PROOF_HEADER + 32u * i, 32);
    return 1;
}
int mt_proof_verify(const unsigned char *der, size_t len, const MTProof *proof,
                    const MTRoot *trusted)
{
    MerkleHash current, next;
    uint32_t pos, width;
    if (!der || !proof || !trusted || !trusted->leaves
        || trusted->leaves > MT_MAX_LEAVES || proof->tree.leaves != trusted->leaves
        || proof->index >= trusted->leaves || proof->depth != depth_for(trusted->leaves)
        || CRYPTO_memcmp(proof->tree.root.bytes, trusted->root.bytes, 32)
        || !merkle_leaf_hash(der, len, &current)) return 0;
    pos = proof->index; width = trusted->leaves;
    for (unsigned int i = 0; i < proof->depth; i++) {
        const MerkleHash *sibling = &proof->siblings[i];
        /* Canonical odd-width tree: the final unpaired node duplicates itself. */
        if (!(pos & 1) && pos + 1 == width
            && CRYPTO_memcmp(current.bytes, sibling->bytes, 32)) return 0;
        if (!(pos & 1) ? !merkle_parent_hash(&current, sibling, &next)
                       : !merkle_parent_hash(sibling, &current, &next)) return 0;
        current = next; pos /= 2; width = (width + 1) / 2;
    }
    return CRYPTO_memcmp(current.bytes, trusted->root.bytes, 32) == 0;
}
int mt_read_file(const char *path, unsigned char *out, size_t cap, size_t *len)
{
    FILE *f;
    int extra, ok;
    if (!path || !out || !len || !(f = fopen(path, "rb"))) return 0;
    *len = fread(out, 1, cap, f); extra = fgetc(f);
    ok = extra == EOF && !ferror(f);
    if (fclose(f)) ok = 0;
    return ok;
}
