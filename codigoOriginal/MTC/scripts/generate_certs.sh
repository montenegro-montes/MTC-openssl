#!/bin/bash
# ===============================================================
# Generate certificates
# Must be run INSIDE a Linux machine/container with OpenSSL 3.5+
# Arguments:
#   --sig-alg <algorithm>       Signature algorithm (ML-DSA, SLH-DSAs, SLH-DSAf
#                               , EC). Default: ML-DSA
#   --sec-levels <levels>       Comma-separated security levels for each 
#                               certificate in the chain (e.g., 3,4,5). 
#                               Default: 3
#   --clean                     Clear old certificates and keys, and continues
#   --clean-only                Clear old certificates and keys, and exit
#   --h, --help                 Show this help message and exit
# ===============================================================

# ----------------------------------------------------
# General configuration
# ----------------------------------------------------

# Set strict mode for better error handling
set -euo pipefail  

# Load common functions and environment variables from library
source "$(dirname "$0")/lib/common.sh"


# ----------------------------------------------------
# Auxiliary functions
# ----------------------------------------------------

# print usage information
print_usage() {
    echo "Usage: $0 [--sig-alg <algorithm>] [--sec-levels <levels>] [--clean] [--clean-only]"
    echo "  --sig-alg <algorithm>       Signature algorithm (ML-DSA, SHL-DSAs, SHL-DSAf, EC). Default: ML-DSA"
    echo "  --sec-levels <levels>       Comma-separated security levels for each certificate in the chain (e.g., 3,4,5). Default: 3"
    echo "  --clean, --clean-only       Clear old certificates and keys and continue or exit"
    echo "  -h, --help                  Show this help message and exit"
    exit 1
}


# Function to parse command-line arguments
parse_args() {

    while [[ $# -gt 0 ]]; do
        case "$1" in

            --sig-alg)
                [[ $# -ge 2 ]] || {
                    log_error "--sig-alg requires a value"
                    exit 1
                }

                SIG_ALG="$2"
                shift 2
                ;;

            --sec-levels)
                [[ $# -ge 2 ]] || {
                    log_error "--sec-levels requires a value"
                    exit 1
                }

                IFS=',' read -ra SEC_LEVELS <<< "$2"
                shift 2
                ;;

            --clean)
                clean_old_certs
                shift
                ;;

            --clean-only)
                clean_old_certs
                exit 0
                ;;

            -h|--help)
                print_usage
                ;;

            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}


# ----------------------------------------------------
# Main script execution
# ----------------------------------------------------

# Default configuration
SIG_ALG="ML-DSA"
SEC_LEVELS=(3)

# ----------------------------------------------------
# 1. Read input arguments
# ----------------------------------------------------
parse_args "$@"

# ----------------------------------------------------
# 2. Build certificate chain configuration
# ----------------------------------------------------
build_algorithm_chain

# ----------------------------------------------------
# 2. Generate certificates based on input arguments
# ----------------------------------------------------
log_info "Certificate chain configuration: ${SIG_ALGS[*]}"

# Create output directories for keys, CSRs, and certificates
mkdir -p "${KEYS_DIR}" "${CSRS_DIR}" "${CERTS_DIR}" "${CHAIN_DIR}"

# Generate certificates in the chain
for ((i=0; i<CHAIN_LENGTH; i++)); do

    # Determine the certificate name, profile, and self-signed status
    get_cert_info "$i" "${SIG_ALGS[$i]}"

    # Files containing key, csr, and certificate
    KEY="${KEYS_DIR}/${CERT_NAME}.key"
    CSR="${CSRS_DIR}/${CERT_NAME}.csr"
    CRT="${CERTS_DIR}/${CERT_NAME}.crt"

    # Generate private key, CSR, and certificate
    generate_key "${SIG_ALGS[$i]}" "$KEY"
    generate_csr "$KEY" "$CSR" "$CERT_NAME"
    generate_certificate "$CSR" "$CRT" "$KEY" "$CERT_PROFILE" "$ISSUER"
done

# Generate the certificate chain that the TLS server will send to the client.
# The chain does not include the Root CA (already pre-installed) 
generate_tls_cert_chain
