#!/bin/bash

set -e

#mkdir -p certs
#cd certs

read -p "Number of certificates to generate: " NUM_CERTS

for ((i=1; i<=NUM_CERTS; i++))
do
    echo    
    echo "=== Certificate $i ==="

    # Ask for CN (rest is fixed) 
    read -p "Common Name (CN): " CN
    SUBJECT="/C=ES/ST=Malaga/L=Malaga/O=MTC Test/CN=$CN"

    KEY_FILE="cert${i}.key"
    PEM_FILE="cert${i}.pem"
    DER_FILE="cert${i}.der"
    
    echo "[+] Generating private key..."
    openssl genpkey \
        -algorithm RSA \
        -pkeyopt rsa_keygen_bits:2048 \
        -out "$KEY_FILE"

    echo "[+] Generating self-signed certificate (PEM)..."
    openssl req \
        -new \
        -x509 \
        -key "$KEY_FILE" \
        -out "$PEM_FILE" \
        -days 365 \
        -subj "$SUBJECT"

    echo "[+] Converting certificate to DER..."
    openssl x509 \
        -in "$PEM_FILE" \
        -outform DER \
        -out "$DER_FILE"

done

echo
echo "[+] Generated files:"
ls -l

#echo
#echo "[+] PEM certificate:"
#openssl x509 \
#    -in test.pem \
#   -text -noout | head -20