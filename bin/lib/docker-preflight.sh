# Sourced by launchers; never starts Docker or creates resources.
mt_docker_ready() {
 bash "${REPO:?}/bin/base/mt-doctor" --core --quiet || return
}
mt_compose_ready() {
 mt_docker_ready || return
 docker compose version >/dev/null 2>&1 || { echo 'ERROR: Docker Compose is not available (docker compose).' >&2; return 1; }
}
# GCC AddressSanitizer in the Debian base image can crash before main() when a
# Linux host exposes 32 bits of mmap randomization.  Never change this global
# kernel setting here; fail before the expensive stage-1 build with a precise
# administrator action instead.
mt_asan_kernel_ready() {
 local path=${1:-/proc/sys/vm/mmap_rnd_bits} value
 [[ -r "$path" ]] || return 0
 read -r value < "$path" || return 0
 [[ "$value" =~ ^[0-9]+$ ]] || return 0
 if (( value >= 32 )); then
  printf '%s\n' \
   "ERROR: Linux vm.mmap_rnd_bits=$value is incompatible with the GCC AddressSanitizer runtime used by docker/base/Dockerfile." \
   'The sanitizer may terminate test_wire with repeated AddressSanitizer:DEADLYSIGNAL messages and exit code 139.' \
   'An administrator must apply the temporary host setting before retrying:' \
   '  sudo sysctl -w vm.mmap_rnd_bits=28' \
   'This launcher will not change a global kernel security setting automatically.' >&2
  return 1
 fi
}
# Called only from explicit execution paths, never status/show/plan.
mt_profile_ready() {
 mt_compose_ready || return
 local selected=${MTC_PROFILE_IMAGE:-mt-tls-mtc-profile:local}
 if [[ "$selected" == mt-tls-mtc-profile:local ]]; then
  python3 "$REPO/campaigns/common/image_chain.py" profile || return
 else
  mt_image_required "$selected" || return
 fi
}
mt_image_matches_parent() {
 local child=$1 parent=$2
 docker image inspect "$child" "$parent" 2>/dev/null | python3 -c '
import json,sys
try:
 child,parent=json.load(sys.stdin)
 p=parent["RootFS"]["Layers"]
 sys.exit(0 if child["RootFS"]["Layers"][:len(p)]==p else 1)
except (ValueError,KeyError,TypeError): sys.exit(1)
'
}
mt_image_required() {
 docker image inspect "$1" >/dev/null 2>&1 || {
  printf 'ERROR: Required image is not available: %s. Prepare that image before retrying the action.\n' "$1" >&2
  return 1
 }
}
mt_images_required() {
 mt_docker_ready || return
 local image
 for image in "$@"; do mt_image_required "$image" || return; done
}
mt_compose_inputs() {
 local file=$1 action=$2 images image ids id health service
 shift 2
 mt_compose_ready || return
 case "$action" in
  up|run)
   images=$(docker compose -f "$file" config --images 2>/dev/null) || {
    echo 'ERROR: Compose configuration is incomplete or invalid. Check the environment variables and paths required by the project.' >&2; return 1;
   }
   while IFS= read -r image; do [[ -z "$image" ]] || mt_image_required "$image" || return; done <<< "$images";;
  exec|logs)
   service=${1:-}
   local services=()
   [[ -z "$service" || "$service" == -* ]] || services=("$service")
   ids=$(docker compose -f "$file" ps -a -q "${services[@]}" 2>/dev/null) || { echo 'ERROR: Could not query the Compose containers.' >&2; return 1; }
   [[ -n "$ids" ]] || { echo 'ERROR: The requested container does not exist. Start the service first with mt-containers up TARGET SERVICE.' >&2; return 1; }
   if [[ "$action" == exec ]]; then
    for id in $ids; do
     health=$(docker inspect --format '{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null) || return 1
     case "$health" in 'true healthy'|'true none') ;; *) echo 'ERROR: The container is not running or is not healthy yet.' >&2; return 1;; esac
    done
   fi;;
 esac
}

# Fail before launcher configuration/output writes. Help remains available on a
# fresh machine. Container-only operations do not require the plotting stack.
case "${1:-menu}" in
 help|--help|-h|list|show|build-plan) ;;
 *)
  case "${0##*/}:${1:-menu}" in
   mt-install:*|mt-containers:*|*:clean|*:reset-all)
    bash "${REPO:?}/bin/base/mt-doctor" --offline --core --quiet || return 1;;
   *) bash "${REPO:?}/bin/base/mt-doctor" --offline --quiet || return 1;;
  esac;;
esac
