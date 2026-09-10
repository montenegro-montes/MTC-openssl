#!/bin/bash


#----------------------------------------------------
# Logging functions
#----------------------------------------------------
log_info()  { 
    if [[ "${DEBUG:-false}" == true ]]; then  
        echo -e "\033[0;34m[INFO]\033[0m $1" 
    fi 
}

log_error() { 
    echo -e "\033[0;31m[ERROR]\033[0m $1"; 
}

#----------------------------------------------------
# Configuration functions
#----------------------------------------------------

load_env() {
    local env_file="$1"
    [[ -r "$env_file" ]] || {
        log_error "Environment file not found: $env_file"
        exit 1
    }
    set -a
    source "$env_file"
    set +a
}

load_library() {
    local library="$1"
    [[ -r "$library" ]] || {
        log_error "Cannot load library: $library"
        exit 1
    }
    source "$library"
}

#----------------------------------------------------
# PKI functions
#----------------------------------------------------

# Function to clean old certificates and keys
clean_old_certs() {
    log_info "Cleaning old certificates and keys..."
    rm -rf "${KEYS_DIR}" "${CSRS_DIR}" "${CERTS_DIR}" "${CHAIN_DIR}"
}

# Function to build certificate chain configuration from input arguments
build_algorithm_chain() {

    CHAIN_LENGTH=${#SEC_LEVELS[@]}
    SIG_ALGS=()
    
    for sec_level in "${SEC_LEVELS[@]}"; do
        # Get the exact algorithm name for use with OpenSSL
        exact_alg=$(get_algorithm_name "$SIG_ALG" "$sec_level") || {
            log_error "Unsupported security level (${sec_level}) for algorithm ${SIG_ALG}"
            exit 1
        }
        SIG_ALGS+=("$exact_alg")
    done

}

# Function to determine the information for the certificate
get_cert_info() {

    local index="$1"
    local alg="$2"

    # Single self-signed certificate
    if (( CHAIN_LENGTH == 1 )); then
        CERT_NAME="server-${alg}"
        CERT_PROFILE="server"
        CERT_SELF_SIGNED=1
        ISSUER=""
    else
    # Certificate chain with several certificates
        # Root CA
        if (( index == 0 )); then
            CERT_NAME="root-${alg}"
            CERT_PROFILE="root_ca"
            CERT_SELF_SIGNED=1
            ISSUER=""
        # Server certificate
        elif (( index == CHAIN_LENGTH - 1 )); then
            CERT_NAME="server-${alg}"
            CERT_PROFILE="server"
            CERT_SELF_SIGNED=0
            if (( index == 1 )); then
                ISSUER="root-${SIG_ALGS[0]}"
            else
                ISSUER="intermediate$((index-1))-${SIG_ALGS[$((index-1))]}"
            fi
        # Intermediate CA
        else
            CERT_NAME="intermediate${index}-${alg}"
            CERT_PROFILE="intermediate_ca"
            CERT_SELF_SIGNED=0
            if (( index == 1 )); then
                ISSUER="root-${SIG_ALGS[0]}"
            else
                ISSUER="intermediate$((index-1))-${SIG_ALGS[$((index-1))]}"
            fi
        fi
    fi
}

# Function to get the issuer name for a certificate 
get_cert_issuer() {

    local cert="$1"

    openssl x509 -in "$cert" -noout -issuer | \
        sed 's/^issuer=//'
}

# Function to extract the subject from a certificate
get_cert_subject() {

    local cert="$1"

    openssl x509 -in "$cert" -noout -subject | \
        sed 's/^subject=//'
}

# Function to check if a certificate is a CA
is_ca_cert() {
    local cert="$1"

    openssl x509 \
        -in "$cert" \
        -text \
        -noout | \
        grep -q "CA:TRUE"
}

# Function to check if a certificate is self-signed
is_self_signed() {
    local cert="$1"
    local subject issuer
    
    subject=$(openssl x509 -in "$cert" -noout -subject)
    issuer=$(openssl x509 -in "$cert" -noout -issuer)

    [[ "${subject#subject=}" == "${issuer#issuer=}" ]]
}

# Function to find a certificate by its subject in the CERTS_DIR
find_cert_by_subject() {
    local wanted_subject="$1"

    # Search for a certificate in the CERTS_DIR that matches
    while IFS= read -r cert; do
        local subject
        subject=$(get_cert_subject "$cert")
        
        if [[ "$subject" == "$wanted_subject" ]]; then
            echo "$cert"
            return 0
        fi
    done < <(find "$CERTS_DIR" -name "*.crt" | sort)
    return 1
}

#----------------------------------------------------
# OpenSSL functions
#----------------------------------------------------

# Map a signature family and security level to an OpenSSL algorithm
get_algorithm_name() {
    local family="$1"
    local level="$2"

    case "${family}:${level}" in
        # ML-DSA
        ML-DSA:1|ML-DSA:2)
            echo "mldsa44"
            ;;
        ML-DSA:3)
            echo "mldsa65"
            ;;
        ML-DSA:4|ML-DSA:5)
            echo "mldsa87"
            ;;
        #SLH-DSA small
        SLH-DSAs:1|SLH-DSAs:2)
            echo "slh-dsa-sha2-128s"
            ;;
        SLH-DSAs:3)
            echo "slh-dsa-sha2-192s"
            ;;
        SLH-DSAs:4|SLH-DSAs:5)
            echo "slh-dsa-sha2-256s"
            ;;
        #SHL-DSA fast
        SLH-DSAf:1|SLH-DSAf:2)
            echo "slh-dsa-sha2-128f"
            ;;
        SLH-DSAf:3)
            echo "slh-dsa-sha2-192f"
            ;;
        SLH-DSAf:4|SLH-DSAf:5)
            echo "slh-dsa-sha2-256f"
            ;;
        # EC
        EC:1|EC:2)
            echo "prime256v1"
            ;;
        EC:3)
            echo "secp384r1"
            ;;
        EC:4|EC:5)
            echo "secp521r1"
            ;;

        *)
            return 1
            ;;
    esac
}

# Function to generate a private key using OpenSSL
generate_key() {

    local key_type="$1"
    local key_file="$2"

    local params=()

    case "$key_type" in

        # EC algorithms
        prime256v1|secp384r1|secp521r1)
            params=(
                -algorithm EC
                -pkeyopt "ec_paramgen_curve:${key_type}"
                -out "$key_file"
            )
            ;;
        # PQC algorithms
        # ML-DSA       
        mldsa*)
            params=(
                -algorithm "$key_type"
                -provparam "mldsa.output_formats=seed-only" #prevent expanded key form (Cloudflare way)
                -out "$key_file"
                )
            ;;
        # SLH-DSA and other algorithms
        *)
            params=(
                -algorithm "$key_type"
                -out "$key_file"
            )
            ;;
    esac

    # Generate the private key with the right parameters
    log_info "Generating private key: ${key_file}"
    openssl genpkey \
        "${params[@]}"
}

# Function to generate a CSR using OpenSSL
generate_csr() {

    local key_file="$1"
    local csr_file="$2"
    local cn="$3"

    openssl req \
        -new \
        -key "${key_file}" \
        -subj "/CN=${cn}" \
        -out "${csr_file}"
}

# Function to generate a certificate using OpenSSL
generate_certificate() {

    local csr="$1"
    local crt="$2"
    local key="$3"
    local profile="$4"
    local issuer="$5"

    if [[ -z "$issuer" ]]; then
        # Self-signed certificate
        openssl x509 \
            -req \
            -in "${csr}" \
            -signkey "${key}" \
            -days 3650 \
            -extfile "${OPENSSL_CONF}" \
            -extensions "${profile}" \
            -out "${crt}"

    else
        # Certificate signed by issuer
        openssl x509 \
            -req \
            -in "${csr}" \
            -CA "${CERTS_DIR}/${issuer}.crt" \
            -CAkey "${KEYS_DIR}/${issuer}.key" \
            -CAcreateserial \
            -days 365 \
            -extfile "${OPENSSL_CONF}" \
            -extensions "${profile}" \
            -out "${crt}"
    fi
}

# Function to extract a specific field from a certificate
get_cert_field() {
    local cert="$1"
    local field="$2"

    openssl x509 -in "$cert" -noout "-${field}"
}

# Function to generate the TLS cert chain send to the client
generate_tls_cert_chain(){
    
    log_info "Generating TLS certificate chain ${TLS_CHAIN_FILE}"

    cat "${CERTS_DIR}"/server-*.crt > "$TLS_CHAIN_FILE"
    
    find "${CERTS_DIR}" -name "intermediate*.crt" | sort -r | while read -r crt; do
        cat "$crt" >> "$TLS_CHAIN_FILE"
    done    
}


#----------------------------------------------------
# Load environment variables
#----------------------------------------------------
load_env "/workspace/config/.env"
log_info "Loaded environment variables from /workspace/config/.env"
