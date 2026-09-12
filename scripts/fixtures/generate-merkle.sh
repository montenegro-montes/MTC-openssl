#!/usr/bin/env bash
set -euo pipefail

work_root=${WORK_ROOT:-/work}
bundle_command=${MT_BUNDLE:-/opt/mt/bin/mt_bundle}
mkdir -p "$work_root/merkle"

if (($# == 0)); then
  set -- classic pq
fi

for profile in "$@"; do
  [[ $profile =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
    echo "Invalid Merkle profile name: $profile" >&2
    exit 2
  }
  certs="$work_root/certs/$profile"
  dest="$work_root/merkle/$profile"
  [[ -f $certs/server.pem && -f $certs/ca.pem ]] || {
    echo "Certificates are missing for profile $profile" >&2
    exit 1
  }
  if [[ -e $dest ]]; then
    echo "$dest is preserved (it must match the profile certificates)."
    continue
  fi
  # Ordered fixture: server leaf first, CA certificate second. The CA's inclusion
  # is only a second tree leaf; it does not authenticate the Merkle root.
  "$bundle_command" "$dest" "$certs/server.pem" "$certs/ca.pem"
done
