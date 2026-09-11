#ifndef PCMA_PROTOCOL_H
#define PCMA_PROTOCOL_H
#include "mt_wire.h"
#define PC_MAX 2046
#define PC_WIRE 8192
#define PC_VERSION "pcma-stage-b-v1"
typedef struct { unsigned id; MerkleHash hash; } PcNode;
typedef struct { MTRoot tree; unsigned budget, policy, count; PcNode nodes[PC_MAX]; } PcCache;
typedef struct {
    unsigned advertised, proof_bytes, credential_bytes, normal, reused, sent;
    unsigned hits, misses, added, evicted, cache_nodes, cache_bytes;
    double encode_ms, parse_ms, range_ms, construct_ms, lookup_ms, reconstruct_ms, verify_ms, credential_verify_ms;
} PcMetrics;
unsigned pc_total(unsigned n);
int pc_id(unsigned n, unsigned level, unsigned index, unsigned *id);
int pc_encode(const PcCache *c, unsigned char *out, size_t cap, size_t *len);
int pc_decode(const unsigned char *in, size_t len, const MTRoot *tree, unsigned char available[PC_MAX]);
int pc_partial(const MTProof *proof, const unsigned char available[PC_MAX], unsigned char *out, size_t cap, size_t *len, PcMetrics *m);
int pc_reconstruct(const unsigned char *in, size_t len, const PcCache *cache, MTProof *proof, PcMetrics *m);
int pc_learn(PcCache *cache, const unsigned char *credential, size_t len, const MTProof *proof, PcMetrics *m);
int pc_load(PcCache *cache, const char *file);
int pc_save(const PcCache *cache, const char *file);
double pc_clock(void);
#endif
