# Sourced by launchers; never starts Docker or creates resources.
mt_docker_ready() {
 command -v docker >/dev/null 2>&1 || { echo 'ERROR: Docker no está instalado o no está en PATH.' >&2; return 1; }
 docker info >/dev/null 2>&1 || {
  echo 'ERROR: no se puede conectar al motor Docker. Abre Docker Desktop y espera a que esté listo; revisa también el contexto Docker activo. No se ha iniciado la etapa.' >&2
  return 1
 }
}
mt_compose_ready() {
 mt_docker_ready || return
 docker compose version >/dev/null 2>&1 || { echo 'ERROR: falta Docker Compose (docker compose).' >&2; return 1; }
}
mt_image_required() {
 docker image inspect "$1" >/dev/null 2>&1 || {
  printf 'ERROR: imagen necesaria no disponible: %s. Prepara esa imagen antes de repetir la acción.\n' "$1" >&2
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
    echo 'ERROR: configuración Compose incompleta; revisa las variables y rutas exigidas por el proyecto.' >&2; return 1;
   }
   while IFS= read -r image; do [[ -z "$image" ]] || mt_image_required "$image" || return; done <<< "$images";;
  exec|logs)
   service=${1:-}
   local services=()
   [[ -z "$service" || "$service" == -* ]] || services=("$service")
   ids=$(docker compose -f "$file" ps -a -q "${services[@]}" 2>/dev/null) || { echo 'ERROR: no se pudieron consultar los contenedores Compose.' >&2; return 1; }
   [[ -n "$ids" ]] || { echo 'ERROR: no existe el contenedor solicitado. Arranca primero el servicio con mt-containers up TARGET SERVICE.' >&2; return 1; }
   if [[ "$action" == exec ]]; then
    for id in $ids; do
     health=$(docker inspect --format '{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null) || return 1
     case "$health" in 'true healthy'|'true none') ;; *) echo 'ERROR: el contenedor no está en ejecución o todavía no está saludable.' >&2; return 1;; esac
    done
   fi;;
 esac
}
