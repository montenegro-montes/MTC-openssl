/** Merkle Tree Certificate (MTC) Header File 
 * 
 * This file contains the specification of MTC operations.
 *
 */

#ifndef MTC_H
#define MTC_H

#include <openssl/x509.h>
#include "merkle.h"

// ===============================================
// Definition of data structures MTC Certificates
// ===============================================
typedef struct {
    unsigned char *der; // Pointer to the DER-encoded certificate
    size_t der_len;     // Length of the DER-encoded certificate
} MTCCertificate;

/** Gets the DER-encoded certificate.
 * Args:
 *     - cert: pointer to the MTCCertificate structure
 *     - der_len: pointer to store the length of the DER-encoded certificate
 * Returns:
 *     - pointer to the DER-encoded certificate
 */
const unsigned char *mtc_get_der(
    const MTCCertificate *cert, 
    size_t *der_len);

// == Certificate management =========================

/** Loads a Certificate. 
 * Args:
 *     - filename: path to the PEM/DER certificate file
 *     - cert: pointer to the MTCCertificate structure to populate
 * Returns:
 *     - 1 on success, 0 on error
 */
int mtc_load(
    const char *filename, 
    MTCCertificate *cert);

/** Frees a certificate. 
 * Args:
 *     - cert: pointer to the MTCCertificate structure to free
 */
void mtc_free(
    MTCCertificate *cert);

/** Prints information about a certificate. 
 * Args:
 *     - cert: pointer to the MTCCertificate structure
 */
void mtc_print(
    const MTCCertificate *cert);


// == Merkle integration =========================

/** Calculates the Merkle leaf hash associated with a certificate. 
 * Args:
 *     - cert: pointer to the X509 certificate
 *     - hash: pointer to the MerkleHash structure
 * Returns:
 *     - 1 on success, 0 on error
 */
int mtc_leaf_hash(
    const MTCCertificate *cert,
    MerkleHash *hash);

#endif // MTC_H