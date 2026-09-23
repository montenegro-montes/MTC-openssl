#!/bin/sh
set -eu
usage() {
  cat <<'EOF'
Usage:
  ./campaigns/historical_campaigns/pcma/run_pcma_experiment.sh --validate --fixtures MANIFEST
  ./campaigns/historical_campaigns/pcma/run_pcma_experiment.sh --diagnostic --fixtures MANIFEST --output NEW_DIR [--seed N]
  ./campaigns/historical_campaigns/pcma/run_pcma_experiment.sh --stage-a --fixtures MANIFEST --output NEW_DIR [run.py options]
  ./campaigns/historical_campaigns/pcma/run_pcma_experiment.sh --full-stage-a --fixtures MANIFEST --output NEW_DIR [--accesses N] [--seed N]
  ./campaigns/historical_campaigns/pcma/run_pcma_experiment.sh --analyze --output RESULT_DIR

No mode is selected by default. --full-stage-a is potentially expensive and
must be invoked explicitly. Stage B TLS integration is not implemented.
EOF
}
[ "$#" -gt 0 ] || { usage; exit 0; }
MODE=$1; shift
case "$MODE" in
  --validate) exec python3 campaigns/historical_campaigns/pcma/validate.py "$@" ;;
  --diagnostic) exec python3 campaigns/historical_campaigns/pcma/run.py --tree-size 16 --workload targeted --accesses 16 --cache-policy full "$@" ;;
  --stage-a) exec python3 campaigns/historical_campaigns/pcma/run.py "$@" ;;
  --full-stage-a) exec python3 campaigns/historical_campaigns/pcma/matrix.py "$@" ;;
  --analyze) OUTPUT=""; while [ "$#" -gt 0 ]; do case "$1" in --output) OUTPUT=$2; shift 2;; *) echo "Unknown argument: $1" >&2; usage; exit 2;; esac; done; [ -n "$OUTPUT" ] || { echo "--output is required" >&2; exit 2; }; exec python3 campaigns/historical_campaigns/pcma/analyze.py "$OUTPUT" ;;
  -h|--help) usage ;;
  *) echo "Unknown mode: $MODE" >&2; usage; exit 2 ;;
esac
