#!/bin/sh
set -eu

umask 077

for path in \
    /run/cosigner/external.key \
    /run/cosigner/server.key \
    /run/cosigner/server.pem \
    /run/cosigner/client-ca.pem \
    /client/client.key \
    /client/client.pem \
    /client/server-ca.pem \
    /client/external.pub
do
    if [ -e "$path" ]; then
        echo "Refusing to overwrite existing credential: $path" >&2
        exit 1
    fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -new -x509 -newkey rsa:2048 -nodes \
    -keyout "$work/ca.key" -out "$work/ca.pem" \
    -subj '/CN=MTC cosigner deployment CA' -days 30 \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign'

openssl req -new -newkey rsa:2048 -nodes \
    -keyout /run/cosigner/server.key -out "$work/server.csr" \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost' \
    -addext 'extendedKeyUsage=serverAuth'
openssl x509 -req -in "$work/server.csr" \
    -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
    -out /run/cosigner/server.pem -days 30 -copy_extensions copy

openssl req -new -newkey rsa:2048 -nodes \
    -keyout /client/client.key -out "$work/client.csr" \
    -subj '/CN=MTC CA client' \
    -addext 'extendedKeyUsage=clientAuth'
openssl x509 -req -in "$work/client.csr" \
    -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
    -out /client/client.pem -days 30 -copy_extensions copy

openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out /run/cosigner/external.key
openssl pkey -in /run/cosigner/external.key -pubout \
    -out /client/external.pub

cp "$work/ca.pem" /run/cosigner/client-ca.pem
cp "$work/ca.pem" /client/server-ca.pem
chmod 600 /run/cosigner/external.key /run/cosigner/server.key \
    /client/client.key
chmod 644 /run/cosigner/server.pem /run/cosigner/client-ca.pem \
    /client/client.pem /client/server-ca.pem /client/external.pub
