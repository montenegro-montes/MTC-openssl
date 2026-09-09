#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "mtc.h"

/* ==================================================
 * Internal helpers
 * ================================================== */

/* Simple PEM detection */
static int mtc_is_pem(const unsigned char *buf, size_t len)
{
    const char *marker = "-----BEGIN CERTIFICATE-----";
    size_t marker_len = strlen(marker);

    if (!buf || len < marker_len)
        return 0;

    return (memcmp(buf, marker, marker_len) == 0);
}

/* ==================================================
 * DER access
 * ================================================== */
const unsigned char *mtc_get_der(
    const MTCCertificate *cert,
    size_t *der_len)
{
    if (!cert || !cert->der)
        return NULL;

    if (der_len)
        *der_len = cert->der_len;

    return cert->der;
}

/* ==================================================
 * Certificate management
 * ================================================== */

int mtc_load(
    const char *filename,
    MTCCertificate *cert)
{
    FILE *fp;
    X509 *cert_x509;

    // Initialize the MTCCertificate structure
    memset(cert, 0, sizeof(*cert));

    // Try to open the file
    fp = fopen(filename, "rb");
    if (!fp)
        return 0;

    // Try to read as PEM first
    cert_x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert_x509) {
        // If PEM reading fails, try to read as DER
        ERR_clear_error();
        rewind(fp);
        cert_x509 = d2i_X509_fp(fp,NULL);
    }
    fclose(fp);

    // Return an error if both PEM and DER reading fail
    if (!cert_x509)
        return 0;

    // Convert the X509 certificate to DER format
    int der_len = i2d_X509(cert_x509, &cert->der);
    X509_free(cert_x509);
    if (der_len <= 0) {
        mtc_free(cert);
        return 0;
    }
    cert->der_len = (size_t)der_len;

    return 1;
}

void mtc_free(MTCCertificate *cert)
{
    if (!cert)
        return;

    OPENSSL_free(cert->der);

    cert->der = NULL;
    cert->der_len = 0;
}

void mtc_print(
    const MTCCertificate *cert)
{
    char subject[512];
    char issuer[512];

    // Check if the certificate is valid
    if (!cert || !cert->der)
        return;

    // Create an X509 structure from the DER data
    const unsigned char * aux = cert->der;
    X509 * cert_x509 = d2i_X509(NULL, &aux, cert->der_len);
    if (!cert_x509)
        return;

    X509_NAME_oneline(
        X509_get_subject_name(cert_x509),
        subject,
        sizeof(subject));

    X509_NAME_oneline(
        X509_get_issuer_name(cert_x509),
        issuer,
        sizeof(issuer));

    printf("Certificate information:\n");
    printf("  Subject : %s\n", subject);
    printf("  Issuer  : %s\n", issuer);
    printf("  DER size: %zu bytes\n", cert->der_len);

    // Free the X509 structure
    X509_free(cert_x509);
}

/* ==================================================
 * Merkle integration
 * ================================================== */

int mtc_leaf_hash(
    const MTCCertificate *cert,
    MerkleHash *hash)
{
    if (!cert || !hash || !cert->der || cert->der_len == 0)
        return 0;

    return merkle_leaf_hash(cert->der, cert->der_len, hash);
}