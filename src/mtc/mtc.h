#ifndef LAB_MTC_H
#define LAB_MTC_H
#include <openssl/ssl.h>
#include <stdint.h>
#define MTC_MAX 65536
/* Provisional Chromium/BoringSSL trust_anchors codepoint; not final IANA. */
#define MTC_EXT 0xca34
#define MTC_DRAFT "draft-ietf-plants-merkle-tree-certs-06"
typedef struct mtc_config MTCConfig;
typedef struct mtc_authority_v2 MTCAuthorityV2;
typedef struct mtc_checkpoint_v2 MTCCheckpointV2;
typedef struct mtc_trust_bundle_v2 MTCTrustBundleV2;
MTCConfig *mtc_load_authority_config_v2(const char *path);
MTCConfig *mtc_load_trust_config_v2(const char *path);
void mtc_free(MTCConfig *c);
/* Typed local-format parsers. */
MTCAuthorityV2 *mtc_load_authority_v2(const char *path);
MTCCheckpointV2 *mtc_load_checkpoint_v2(const char *path);
MTCTrustBundleV2 *mtc_load_trust_bundle_v2(const char *path);
int mtc_authenticate_checkpoint_v2(const MTCAuthorityV2 *authority,
                                   const MTCCheckpointV2 *checkpoint);
void mtc_free_authority_v2(MTCAuthorityV2 *authority);
void mtc_free_checkpoint_v2(MTCCheckpointV2 *checkpoint);
void mtc_free_trust_bundle_v2(MTCTrustBundleV2 *bundle);
/* Local relying-party policy with inclusive endpoints [first,last].
 * Draft half-open [a,b) maps to [a,b-1]; [a,2^64) maps to [a,UINT64_MAX].
 * Configure ranges before certificate verification. */
int mtc_add_revoked_serial_range(MTCConfig *c, uint64_t first, uint64_t last);
/* Draft-06 Section 7.4 relying-party trusted-subtree configuration.
 * The caller must validate consistency/cosigner policy before installation. */
int mtc_add_trusted_subtree(MTCConfig *c, uint64_t log_number,
                            uint64_t start, uint64_t end,
                            const unsigned char hash[32]);
/* Load local MTS1 relying-party trusted-subtree configuration.
 * The file contains only already-validated Section 7.4 state; it is not
 * itself an authenticated checkpoint or standardized wire format. */
int mtc_load_trusted_subtrees(MTCConfig *c, const char *path);
int mtc_verify(X509 *x, MTCConfig *c);
int mtc_client(SSL_CTX *ctx,const char *path,int landmark,
               const char *trusted_subtrees);
int mtc_server(SSL_CTX *ctx,const char *id);
int mtc_server_verify_client(SSL_CTX *ctx,const char *path,int landmark);
int mtc_client_present(SSL_CTX *ctx,const char *id,int landmark);
int mtc_eval(const unsigned char leaf[32],uint64_t index,uint64_t start,uint64_t end,const unsigned char *proof,size_t n,unsigned char out[32]);
#endif
