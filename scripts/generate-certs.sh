#!/usr/bin/env bash
set -euo pipefail
umask 077

work_root=${WORK_ROOT:-/work}
cert_root="$work_root/certs"
merkle_script=${MERKLE_SCRIPT:-/opt/lab/generate-merkle.sh}
generation_tmp=''
cleanup() {
  [[ -z ${generation_tmp:-} ]] || rm -rf -- "$generation_tmp"
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage:
  generate-certs.sh
  generate-certs.sh --profile NAME --algorithm ALGORITHM [OPTIONS]

Without arguments, generate the preserved laboratory profiles:
  classic  EC with ec_paramgen_curve:P-256
  pq       ML-DSA-65

Custom profile options:
  --profile NAME       Output name below certs/ and merkle/ (required).
  --algorithm NAME     OpenSSL genpkey algorithm (required).
  --pkeyopt OPTION     Repeatable OpenSSL genpkey -pkeyopt value.
  --sigopt OPTION      Repeatable OpenSSL req/x509 -sigopt value.
  --digest NAME        Optional signature digest, for example sha384.
  --days NUMBER        Certificate validity in days (default: 30).
  -h, --help           Show this help.

Existing profile directories are preserved and never overwritten.
EOF
}

valid_profile() {
  [[ $1 =~ ^[a-z0-9][a-z0-9._-]*$ ]]
}

if [[ $# == 1 && ( $1 == -h || $1 == --help ) ]]; then
  usage
  exit
fi

generate_profile() {
  local profile=$1 algorithm=$2 days=$3 digest=$4
  shift 4
  local -a pkeyopts=()
  local -a sigopts=()
  local mode=pkey
  while (($#)); do
    if [[ $1 == --signature-options ]]; then
      mode=signature
    elif [[ $mode == pkey ]]; then
      pkeyopts+=("$1")
    else
      sigopts+=("$1")
    fi
    shift
  done

  local dest="$cert_root/$profile"
  if [[ -e $dest ]]; then
    echo "$dest already exists and is preserved. Use a different profile name to regenerate." >&2
    bash "$merkle_script" "$profile"
    return
  fi

  generation_tmp=$(mktemp -d "$cert_root/.new-XXXXXX")
  local tmp=$generation_tmp

  local -a keyargs=(-algorithm "$algorithm")
  local option
  for option in "${pkeyopts[@]}"; do keyargs+=(-pkeyopt "$option"); done
  local -a signature_args=()
  [[ -n $digest ]] && signature_args+=("-$digest")
  for option in "${sigopts[@]}"; do signature_args+=(-sigopt "$option"); done

  openssl genpkey "${keyargs[@]}" -out "$tmp/ca.key"
  openssl req -new -x509 -key "$tmp/ca.key" -out "$tmp/ca.pem" -days "$days" \
    -subj "/CN=MT Lab $profile CA" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' "${signature_args[@]}"
  openssl genpkey "${keyargs[@]}" -out "$tmp/server.key"
  openssl req -new -key "$tmp/server.key" -out "$tmp/server.csr" \
    -subj '/CN=server' "${signature_args[@]}"
  cat >"$tmp/extensions.cnf" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1
EXT
  openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" \
    -CAkey "$tmp/ca.key" -set_serial 2 -days "$days" \
    -extfile "$tmp/extensions.cnf" -out "$tmp/server.pem" "${signature_args[@]}"
  openssl x509 -in "$tmp/server.pem" -outform DER -out "$tmp/server.der"
  openssl verify -CAfile "$tmp/ca.pem" -verify_hostname server "$tmp/server.pem"

  {
    printf 'profile=%s\nalgorithm=%s\ndays=%s\n' "$profile" "$algorithm" "$days"
    [[ -n $digest ]] && printf 'digest=%s\n' "$digest"
    for option in "${pkeyopts[@]}"; do printf 'pkeyopt=%s\n' "$option"; done
    for option in "${sigopts[@]}"; do printf 'sigopt=%s\n' "$option"; done
  } >"$tmp/generation-parameters.txt"

  mv "$tmp" "$dest"
  generation_tmp=''
  bash "$merkle_script" "$profile"
}

mkdir -p "$cert_root"

if (($# == 0)); then
  generate_profile classic EC 30 '' ec_paramgen_curve:P-256 --signature-options
  generate_profile pq ML-DSA-65 30 '' --signature-options
  exit
fi

profile='' algorithm='' digest='' days=30
declare -a pkeyopts=()
declare -a sigopts=()
while (($#)); do
  case $1 in
    --profile) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; profile=$2; shift 2 ;;
    --algorithm) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; algorithm=$2; shift 2 ;;
    --pkeyopt) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; pkeyopts+=("$2"); shift 2 ;;
    --sigopt) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; sigopts+=("$2"); shift 2 ;;
    --digest) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; digest=$2; shift 2 ;;
    --days) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; days=$2; shift 2 ;;
    -h|--help) usage; exit ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n $profile && -n $algorithm ]] || {
  echo '--profile and --algorithm are required in custom mode.' >&2
  usage >&2
  exit 2
}
valid_profile "$profile" || {
  echo 'Invalid profile name: use lowercase letters, digits, dots, hyphens, or underscores.' >&2
  exit 2
}
[[ $days =~ ^[1-9][0-9]*$ ]] || {
  echo '--days must be a positive integer.' >&2
  exit 2
}

generate_profile "$profile" "$algorithm" "$days" "$digest" \
  "${pkeyopts[@]}" --signature-options "${sigopts[@]}"
