# Sourced by client/server; keep authentication and key exchange independent.
case ${SCENARIO:-classic} in
  classic|pq) CERT_SCENARIO=${SCENARIO:-classic}; OPENSSL_BIN=/opt/openssl/bin/openssl; MERKLE_ENABLED=0 ;;
  classic-mt) CERT_SCENARIO=classic; OPENSSL_BIN=/opt/openssl-mt/bin/openssl; MERKLE_ENABLED=1 ;;
  pq-mt) CERT_SCENARIO=pq; OPENSSL_BIN=/opt/openssl-mt/bin/openssl; MERKLE_ENABLED=1 ;;
  *) echo 'Escenario no implementado: use classic, pq, classic-mt o pq-mt' >&2; exit 2 ;;
esac
