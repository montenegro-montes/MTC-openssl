#!/usr/bin/env bash
set -euo pipefail
umask 077
mkdir -p /work/certs
for scenario in classic pq; do
  dest=/work/certs/$scenario
  if [[ -e "$dest" ]]; then
    echo "Ya existe $dest; se conserva. Use otro directorio de artifacts para regenerar." >&2
    continue
  fi
  tmp=$(mktemp -d /work/certs/.new-XXXXXX)
  trap 'rm -rf "$tmp"' EXIT
  if [[ $scenario == classic ]]; then
    keyargs=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256)
  else
    keyargs=(-algorithm ML-DSA-65)
  fi
  openssl genpkey "${keyargs[@]}" -out "$tmp/ca.key"
  openssl req -new -x509 -key "$tmp/ca.key" -out "$tmp/ca.pem" -days 30 -subj "/CN=MT Lab $scenario CA" -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
  openssl genpkey "${keyargs[@]}" -out "$tmp/server.key"
  openssl req -new -key "$tmp/server.key" -out "$tmp/server.csr" -subj '/CN=server'
  cat > "$tmp/extensions.cnf" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1
EXT
  openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca.key" -set_serial 2 -days 30 -extfile "$tmp/extensions.cnf" -out "$tmp/server.pem"
  openssl x509 -in "$tmp/server.pem" -outform DER -out "$tmp/server.der"
  openssl verify -CAfile "$tmp/ca.pem" -verify_hostname server "$tmp/server.pem"
  mv "$tmp" "$dest"
  trap - EXIT
done

bash /opt/lab/generate-merkle.sh
