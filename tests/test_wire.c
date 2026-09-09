#include "mt_wire.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    const unsigned char *data[17];
    size_t lengths[17];
    unsigned char leaves[17], wire[MT_MAX_WIRE + 1], bad[MT_MAX_WIRE + 1], rootwire[MT_ROOT_SIZE];
    for (size_t i = 0; i < 17; i++) { leaves[i] = (unsigned char)i; data[i] = &leaves[i]; lengths[i] = 1; }
    for (uint32_t n = 1; n <= 17; n++) {
        MTRoot root, decoded_root;
        root.leaves = n;
        assert(merkle_root(data, lengths, n, &root.root));
        assert(mt_root_encode(&root, rootwire));
        assert(mt_root_decode(rootwire, sizeof(rootwire), &decoded_root));
        assert(decoded_root.leaves == n && !memcmp(root.root.bytes, decoded_root.root.bytes, 32));
        for (size_t k = 0; k < MT_ROOT_SIZE; k++) assert(!mt_root_decode(rootwire, k, &decoded_root));
        for (uint32_t index = 0; index < n; index++) {
            MerkleProof original = {0};
            MTProof decoded;
            size_t len;
            assert(merkle_generate_proof(data, lengths, n, index, &original));
            assert(merkle_verify_proof(data[index], 1, &original, &root.root));
            assert(mt_proof_encode(&root, index, &original, wire, sizeof(wire), &len));
            assert(mt_proof_decode(wire, len, &decoded));
            assert(mt_proof_verify(data[index], 1, &decoded, &root));
            for (size_t k = 0; k < len; k++) {
                assert(!mt_proof_decode(wire, k, &decoded));
                memcpy(bad, wire, len); bad[k] ^= 0x80;
                assert(!mt_proof_decode(bad, len, &decoded)
                       || !mt_proof_verify(data[index], 1, &decoded, &root));
            }
            memcpy(bad, wire, len); bad[len] = 0;
            assert(!mt_proof_decode(bad, len + 1, &decoded));
            assert(mt_proof_decode(wire, len, &decoded));
            unsigned char different = 99;
            assert(!mt_proof_verify(&different, 1, &decoded, &root));
            MTRoot wrong = root; wrong.root.bytes[0] ^= 1;
            assert(!mt_proof_verify(data[index], 1, &decoded, &wrong));
            wrong = root; wrong.leaves++;
            assert(!mt_proof_verify(data[index], 1, &decoded, &wrong));
            assert(!mt_proof_encode(&root, n, &original, wire, sizeof(wire), &len));
            merkle_free_proof(&original);
        }
    }
    assert(!mt_proof_decode(NULL, 0, NULL));
    assert(!mt_root_decode(NULL, 0, NULL));
    /* Claimed maximum depth and oversized/zero leaf counts must be rejected. */
    memset(wire, 0, sizeof(wire)); memcpy(wire, "MTP1", 4);
    assert(!mt_proof_decode(wire, MT_PROOF_HEADER, &(MTProof){0}));
    memset(wire + 4, 255, 4); wire[44] = 255;
    assert(!mt_proof_decode(wire, sizeof(wire), &(MTProof){0}));
    puts("Wire tests: PASS (153 valid paths, byte mutations, truncations, odd trees)");
    return 0;
}
