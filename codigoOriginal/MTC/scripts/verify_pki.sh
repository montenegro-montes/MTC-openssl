#!/bin/bash

set -euo pipefail

source "$(dirname "$0")/lib/common.sh"


# ----------------------------------------------------
# Build chain
# ----------------------------------------------------

build_chain() {

    local cert="$1"

    declare -A visited=()

    ROOT_CA=""
    INTERMEDIATES=()
    CHAIN=()

    while true; do

        local subject issuer

        subject=$(get_cert_subject "$cert")
        issuer=$(get_cert_issuer "$cert")
        
        # Add the current certificate to the chain
        CHAIN+=("$cert")

        if [[ -n "${visited[$subject]:-}" ]]; then
            log_error "Loop detected in certificate chain"
            return 1
        fi

        visited["$subject"]=1

        # Root reached
        if [[ "$subject" == "$issuer" ]]; then

            if ! is_ca_cert "$cert"; then
                log_error "$(basename "$cert") is self-signed but not a CA"
                return 1
            fi

            ROOT_CA="$cert"
            return 0
        fi

        # Find the issuer certificate in the chain
        local issuer_cert
        issuer_cert=$(find_cert_by_subject "$issuer") || {
            log_error "Issuer not found"
            log_error "Certificate: $(basename "$cert")"
            log_error "Issuer: $issuer"
            return 1
        }

        if ! is_ca_cert "$issuer_cert"; then
            log_error "$(basename "$issuer_cert") is not a CA"
            return 1
        fi

        INTERMEDIATES+=("$issuer_cert")

        # Move to the next certificate in the chain
        cert="$issuer_cert"

    done
}

# ----------------------------------------------------
# Validate end-entity certificates
# ----------------------------------------------------

validated=0

while IFS= read -r cert; do

    if is_ca_cert "$cert"; then
        continue
    fi

    validated=$((validated + 1))

    log_info "Validating: $(basename "$cert")"
    
    # Build the chain for the current certificate
    build_chain "$cert"

    # Print the chain for debugging
    log_info "Certificate chain:"
    for c in "${CHAIN[@]}"; do
        log_info "  $(basename "$c")"
        log_info "    Subject: $(get_cert_subject "$c")"
        log_info "    Issuer:  $(get_cert_issuer "$c")"
        if is_ca_cert "$c"; then
            role="CA"
        else
            role="End Entity"
        fi
        log_info "    Role:    $role"
    done

    # Create a temporary file to hold the intermediate certificates 
    # for OpenSSL verification
    tmp_chain=$(mktemp)
    for ((i=0; i<${#INTERMEDIATES[@]}-1; i++)); do
        cat "${INTERMEDIATES[$i]}" >> "$tmp_chain"
    done

    # Validate the certificate chain using OpenSSL
    log_info "OpenSSL verify:"
    openssl verify \
        -CAfile "$ROOT_CA" \
        -untrusted "$tmp_chain" \
        "$cert"

    # Clean up the temporary file
    rm -f "$tmp_chain"

done < <(find "$CERTS_DIR" -name "*.crt" | sort)


if [[ "$validated" -eq 0 ]]; then
    log_error "No end-entity certificates found"
    exit 1
fi


# If all validations passed, print a success message
echo "[OK] PKI validation successful"