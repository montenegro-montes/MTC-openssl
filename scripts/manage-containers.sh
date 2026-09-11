#!/usr/bin/env bash
set -euo pipefail

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

COMPOSE_FILES="
base:docker/compose.yaml
compact:docker/compose.compact.yaml
profile:docker/compose.profile.yaml
mtc:docker/compose.mtc.yaml
measurement:docker/compose.measurement.yaml
scaling:docker/compose.scaling.yaml
latency:docker/compose.network-latency.yaml
bandwidth:docker/compose.network-bandwidth.yaml
loss:docker/compose.network-loss.yaml
combined:docker/compose.network-combined.yaml
capture:docker/compose.capture.yaml
"

usage() {
  cat <<'EOF'
Usage: scripts/manage-containers.sh COMMAND [TARGET] [OPTIONS]

Commands:
  list                         list Compose targets and purposes
  doctor                       check Docker, Compose, disk and project images
  ps [all|TARGET]              show project containers
  build TARGET                 build one Compose target
  build-chain [measurement|network]  repair the project image chain
  up TARGET [SERVICE]          start a project or one service
  down [all|TARGET]            stop containers and remove project networks
  restart TARGET [SERVICE]     recreate a project or service
  logs TARGET [SERVICE]        follow logs
  shell TARGET SERVICE [CMD]   open a shell or run CMD in a running container
  run TARGET SERVICE [ARGS...] run an ephemeral service container
  images                       list mt-tls-* images
  inspect-image IMAGE          show image identity and creation metadata
  remove-images [--yes]        remove project images after stopping projects
  clean [--yes]                stop every project and remove orphan containers
  menu                         interactive menu

Targets: base compact profile mtc measurement scaling latency bandwidth loss
         combined capture

This tool does not delete artifacts or campaign results. Use
scripts/archive-results.py --clean-artifacts only after archiving results.
EOF
}

compose_file() {
  case "${1:-}" in
    base) echo docker/compose.yaml ;;
    compact) echo docker/compose.compact.yaml ;;
    profile) echo docker/compose.profile.yaml ;;
    mtc) echo docker/compose.mtc.yaml ;;
    measurement) echo docker/compose.measurement.yaml ;;
    scaling) echo docker/compose.scaling.yaml ;;
    latency) echo docker/compose.network-latency.yaml ;;
    bandwidth) echo docker/compose.network-bandwidth.yaml ;;
    loss) echo docker/compose.network-loss.yaml ;;
    combined) echo docker/compose.network-combined.yaml ;;
    capture) echo docker/compose.capture.yaml ;;
    *) echo "Unknown target: ${1:-<empty>}" >&2; return 2 ;;
  esac
}

targets() { printf '%s\n' base compact profile mtc measurement scaling latency bandwidth loss combined capture; }
compose() { local f; f=$(compose_file "$1"); shift; docker compose -f "$f" "$@"; }
confirm() {
  [ "${1:-}" = "--yes" ] && return 0
  printf 'Continue? [y/N] '
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0;; *) echo "Cancelled"; return 1;; esac
}

list_targets() {
  cat <<'EOF'
base         initial OpenSSL/PQ/Merkle laboratory
compact      Compact Merkle fixtures and benchmark
profile      detailed timing instrumentation
mtc          experimental MTC implementation
measurement  controlled N=16 measurement image
scaling      Merkle population scaling
latency      latency-only network campaign
bandwidth    bandwidth-limited network campaign
loss         packet-loss network campaign
combined     combined network profiles
capture      TLS handshake packet capture
EOF
}

doctor() {
  local failed=0
  command -v docker >/dev/null || { echo "FAIL docker command missing"; failed=1; }
  if command -v docker >/dev/null; then
    docker version >/dev/null 2>&1 && echo "PASS Docker daemon" || { echo "FAIL Docker daemon"; failed=1; }
    docker compose version >/dev/null 2>&1 && echo "PASS Docker Compose" || { echo "FAIL Docker Compose"; failed=1; }
    echo
    docker image ls --filter reference='mt-tls-*' --format 'IMAGE {{.Repository}}:{{.Tag}}  {{.ID}}  {{.Size}}' || true
    echo
    docker system df || true
  fi
  [ "$failed" -eq 0 ]
}

all_down() {
  local target
  for target in $(targets); do
    echo "==> down $target"
    compose "$target" down --remove-orphans || true
  done
}

menu() {
  while :; do
    cat <<'EOF'

Container manager
  1) doctor       2) ps all       3) images
  4) build        5) up           6) logs
  7) shell        8) down         9) clean all
  0) exit
EOF
    printf 'Selection: '; read -r choice
    case "$choice" in
      1) doctor || true;; 2) "$0" ps all;; 3) "$0" images;;
      4) printf 'Target: '; read -r t; "$0" build "$t";;
      5) printf 'Target: '; read -r t; "$0" up "$t";;
      6) printf 'Target: '; read -r t; "$0" logs "$t";;
      7) printf 'Target: '; read -r t; printf 'Service: '; read -r s; "$0" shell "$t" "$s";;
      8) printf 'Target: '; read -r t; "$0" down "$t";;
      9) "$0" clean;; 0) return;; *) echo "Invalid selection";;
    esac
  done
}

cmd=${1:-help}; shift || true
case "$cmd" in
  help|-h|--help) usage ;;
  list) list_targets ;;
  doctor) doctor ;;
  ps)
    target=${1:-all}
    if [ "$target" = all ]; then for t in $(targets); do echo "==> $t"; compose "$t" ps || true; done
    else compose "$target" ps; fi ;;
  build) [ "$#" -ge 1 ] || { usage; exit 2; }; compose "$1" build ;;
  build-chain) python3 -m campaigns.common.image_chain "${1:-network}" ;;
  up) [ "$#" -ge 1 ] || { usage; exit 2; }; t=$1; shift; compose "$t" up -d --force-recreate "$@" ;;
  down)
    target=${1:-all}; if [ "$target" = all ]; then all_down; else compose "$target" down --remove-orphans; fi ;;
  restart) [ "$#" -ge 1 ] || { usage; exit 2; }; t=$1; shift; compose "$t" up -d --force-recreate "$@" ;;
  logs) [ "$#" -ge 1 ] || { usage; exit 2; }; t=$1; shift; compose "$t" logs -f --tail=200 "$@" ;;
  shell)
    [ "$#" -ge 2 ] || { usage; exit 2; }; t=$1; s=$2; shift 2
    if [ "$#" -gt 0 ]; then compose "$t" exec "$s" "$@"; else compose "$t" exec "$s" sh; fi ;;
  run) [ "$#" -ge 2 ] || { usage; exit 2; }; t=$1; s=$2; shift 2; compose "$t" run --rm "$s" "$@" ;;
  images) docker image ls --filter reference='mt-tls-*' ;;
  inspect-image) [ "$#" -eq 1 ] || { usage; exit 2; }; docker image inspect "$1" ;;
  remove-images)
    yes=${1:-}; echo "This stops projects and removes local mt-tls-* images."; confirm "$yes"
    all_down
    ids=$(docker image ls --filter reference='mt-tls-*' -q | sort -u)
    [ -z "$ids" ] || docker image rm $ids ;;
  clean)
    yes=${1:-}; echo "This stops every project and removes its containers and networks."; confirm "$yes"; all_down ;;
  menu) menu ;;
  *) echo "Unknown command: $cmd" >&2; usage; exit 2 ;;
esac
