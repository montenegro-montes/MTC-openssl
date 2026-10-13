# Shared menu helpers; sourced by setup/tests, never executed directly.
menu_invoke() {
 local mode=$1 answer result
 shift
 if [[ "$mode" == confirm ]]; then
  printf 'Command: '; printf '%q ' "$0" "$@"; printf '\n'
  read -r -p 'Continue? [y/N] ' answer || exit 0
  case "$answer" in y|Y) ;; *) echo 'Cancelled.'; return 0;; esac
 fi
 # Preserve the caller's directory so relative invocations of "$0" still work.
 if (cd "$MENU_CALL_DIR" && "$0" "$@"); then :
 else result=$?; printf 'Command exited with status %s.\n' "$result"; fi
}

menu_browser_mode() {
 local browser_case=$1 selection
 shift
 local extra_args=("$@")
 while true; do
  printf '\n%s\n1. Headless automated validation\n2. Visible browser inspection\n3. Back\n' "$browser_case"
  read -r -p 'Select an option: ' selection || exit 0
  case "$selection" in
   1) menu_invoke confirm browser-validation run "$browser_case" --browser-mode headless "${extra_args[@]}"; return 0;;
   2) menu_invoke confirm browser-validation run "$browser_case" --browser-mode headed "${extra_args[@]}"; return 0;;
   0|3) return 0;;
   *) echo 'Invalid option.';;
  esac
 done
}

menu_mtc_case() {
 local browser_case=$1 selection trust_mode
 shift
 local extra_args=("$@")
 if [[ " ${extra_args[*]} " == *' --mtc-trusted-subtrees-url '* ]]; then
  echo 'RP HTTP supplies landmark trusted subtrees; standalone is not supported by this workflow.'
  menu_browser_mode "$browser_case" --mtc-trust-mode landmark "${extra_args[@]}"
  return 0
 fi
 while true; do
  printf '\nMTC trust mode\n1. Landmark (default)\n2. Standalone\n3. Back\n'
  read -r -p 'Select [1-3, Enter=1]: ' selection || return 0
  case "${selection:-1}" in
   1) trust_mode=landmark;;
   2) trust_mode=standalone;;
   3) return 0;;
   *) echo 'Invalid option.'; continue;;
  esac
  if [[ "$trust_mode" == standalone && "$browser_case" == mtc-bad-merkle ]]; then
   echo 'Standalone mtc-bad-merkle is not implemented: this case mutates landmark trusted subtrees.'
   echo 'No command was executed.'
   return 0
  fi
  menu_browser_mode "$browser_case" --mtc-trust-mode "$trust_mode" "${extra_args[@]}"
  return 0
 done
}

menu_validation_all() {
 local selection
 printf '\nMTC trust mode for Run all\n1. Landmark (default)\n2. Standalone\n3. Both modes\n4. Back\n'
 read -r -p 'Select [1-4, Enter=1]: ' selection || return 0
 case "${selection:-1}" in
  1) menu_invoke confirm browser-validation run all --mtc-trust-mode landmark;;
  2|3)
   echo 'Run all is currently complete only for landmark.'
   echo 'Standalone mtc-bad-merkle has no trusted-subtree anchor to mutate; no incomplete Run all was started.';;
  4) return 0;;
  *) echo 'Invalid option.';;
 esac
}

menu_measurement_summary() {
 local kem=$1 depth=$2 pairs=$3 warmups=$4
 printf '\nProfiles: ALL (6)\n'
 printf 'Scenarios: 3\n'
 printf 'Key establishment: %s\n' "$kem"
 printf 'X.509 depth: %s\n' "$depth"
 printf 'Measured pairs per profile: %s\n' "$pairs"
 printf 'Warmup pairs per profile: %s\n' "$warmups"
 printf 'Total measured runs: %s × %s × %s = %s\n\n' \
  6 3 "$pairs" "$((6*3*pairs))"
 printf 'Total warmup runs: %s × %s × %s = %s\n' \
  6 3 "$warmups" "$((6*3*warmups))"
 printf 'Total TLS runs: %s\n\n' "$((6*3*(pairs+warmups)))"
}

menu_measurements_run_prepared() {
 local depth=$1 answer
 shift
 printf 'Campaign command: '; printf '%q ' "$0" browser-measurements "$@"; printf '\n'
 echo 'The campaign command performs dependency preparation before measurements.'
 read -r -p 'Prepare dependencies, then run the campaign? [y/N] ' answer || return 0
 case "$answer" in y|Y) ;; *) echo 'Cancelled.'; return 0;; esac
 (cd "$MENU_CALL_DIR" && "$0" browser-measurements "$@")
}

menu_preflight() {
 local selection
 while true; do
  printf '\nPreflight\n1. Development (read-only)\n2. Development + capture permissions check\n3. Strict (read-only)\n4. Strict + capture permissions check\n0. Back\n'
  read -r -p 'Select an option: ' selection || return 0
  case "$selection" in
   1) menu_invoke readonly preflight; return 0;;
   2) menu_invoke readonly preflight --check-capture; return 0;;
   3) menu_invoke readonly preflight --strict; return 0;;
   4) menu_invoke readonly preflight --strict --check-capture; return 0;;
   0) return 0;;
   *) echo 'Invalid option.';;
  esac
 done
}

menu_submenu() {
 local section=$1 title selection index mode root_path
 local labels=() commands=() prefix=() args=()
 case "$section" in
  source)
   title='Source reconstruction'; prefix=(reconstruct-source)
   labels=('100 Verify reconstruction inputs' '110 Prepare depot_tools' '120 Prepare Chromium base' '130 Prepare BoringSSL base' '140 Import preserved commits' '150 Checkout patched source' '160 Verify source trees' 'Status' 'Plan')
   commands=('run 100' 'run 110' 'run 120' 'run 130' 'run 140' 'run 150' 'run 160' status plan);;
  preparation)
   title='Build preparation'; prefix=(prepare-build)
   labels=('170 Verify reconstructed source' '180 Prepare Chromium checkout layout' '190 Sync pinned dependencies' '200 Check platform build dependencies' '210 Configure release build' '220 Verify build configuration' 'Status' 'Plan' 'Run all remaining preparation steps')
   commands=('run 170' 'run 180' 'run 190' 'run 200' 'run 210' 'run 220' status plan run-remaining)
   if [[ "$(uname -s)" == Darwin ]]; then
    labels+=('Check Xcode / SDK readiness')
   else
    labels+=('Install build dependencies')
   fi
   commands+=(install-deps)
   if type apparmor_required >/dev/null 2>&1 && apparmor_required; then
    labels+=('Prepare Chromium AppArmor sandbox' 'Check Chromium AppArmor sandbox')
    commands+=(sandbox-setup sandbox-status)
   fi;;
  build)
   title='Build Chromium'; prefix=(build)
   labels=('Plan' 'Status' 'Build Chromium'); commands=(plan status 'run chromium');;
  setup)
   title='Existing Chromium / MTC setup'
   labels=('00 Preflight' '10 Detect existing Chromium' '20 Select or generate MTC fixture' '30 Validate MTC fixture' '40 Export MTC anchor' '50 Configure hostname' '60 Start MTC positive server' 'Status' 'Resume from next pending step')
   commands=('run 00' 'run 10' 'run 20' 'run 30' 'run 40' 'run 50' 'run 60' status resume);;
  trust)
   title='X.509 trust management'; prefix=(browser-validation)
   labels=('Trust status' 'Trust X.509 root' 'Remove X.509 root trust')
   commands=(trust-status trust-x509 untrust-x509);;
  validation)
   title='Browser functional validation'; prefix=(browser-validation)
   labels=('Plan' 'Status' 'Run mtc-positive' 'Run mtc-no-trust' 'Run mtc-bad-merkle' 'Run mtc-bad-serial' 'Run x509-positive' 'Run all' 'Run MTC via RP HTTP')
   commands=(plan status 'run mtc-positive' 'run mtc-no-trust' 'run mtc-bad-merkle' 'run mtc-bad-serial' 'run x509-positive' 'run all' 'run mtc-positive --mtc-trusted-subtrees-url http://127.0.0.1:18083/trusted-subtrees');;
  pcap)
   title='Browser PCAP validation'; prefix=(browser-pcap)
   labels=('Plan' 'Requirements / capture backend' 'Status' 'Capture mtc-positive' 'Capture mtc-no-trust' 'Capture mtc-bad-merkle' 'Capture mtc-bad-serial' 'Capture x509-positive' 'Capture all')
   commands=(plan requirements status 'run mtc-positive' 'run mtc-no-trust' 'run mtc-bad-merkle' 'run mtc-bad-serial' 'run x509-positive' 'run all');;
  measurements)
   title='Browser measurements'; prefix=(browser-measurements)
   labels=('Status' 'Run paired comparison (ALL profiles)')
   commands=(readiness run);;
 esac
 while true; do
  printf '\n%s\n' "$title"
  for ((index=0; index<${#labels[@]}; index++)); do
   printf '%d. %s\n' "$((index+1))" "${labels[index]}"
  done
  if [[ "$section" == measurements ]]; then printf '3. Back\n'; else printf '0. Back\n'; fi
  read -r -p 'Select an option: ' selection || exit 0
  [[ "$selection" != 0 ]] || return 0
  [[ "$section" != measurements || "$selection" != 3 ]] || return 0
  [[ "$selection" =~ ^[1-9][0-9]?$ ]] || { echo 'Invalid option.'; continue; }
  (( selection <= ${#labels[@]} )) || { echo 'Invalid option.'; continue; }
  read -r -a args <<< "${commands[selection-1]}"
  if [[ "$section" == preparation && "${args[0]}" == run-remaining ]]; then
   menu_preparation_run_remaining
   continue
  fi
  if [[ "$section" == validation && "${args[0]}" == run ]]; then
   if [[ "${args[1]}" == all ]]; then
    menu_validation_all
   elif [[ "${args[1]}" == x509-positive ]]; then
    menu_browser_mode "${args[@]:1}"
   else
    menu_mtc_case "${args[@]:1}"
   fi
   continue
  fi
  if [[ "$section" == trust ]]; then
   read -r -p 'Root certificate path (PEM): ' root_path || return 0
   [[ -n "$root_path" ]] || { echo 'Root path is required.'; continue; }
   args+=(--root "$root_path")
  fi
  if [[ "$section" == measurements && "${args[0]}" == run ]]; then
   printf 'Key establishment:\n1. X25519 (default)\n2. X25519+ML-KEM768\n'
   read -r -p 'Select [1-2, Enter=1]: ' kem_choice || return 0
   case "${kem_choice:-1}" in
    1) kem=x25519;;
    2) kem=x25519-mlkem768;;
    *) echo 'Invalid key-establishment option.'; continue;;
   esac
   printf 'X.509 depth:\n1. 2 (default)\n2. 3\n3. 4\n4. 5\n'
   read -r -p 'Select [1-4, Enter=1]: ' depth_choice || return 0
   case "${depth_choice:-1}" in
    1) depth=2;;
    2) depth=3;;
    3) depth=4;;
    4) depth=5;;
    *) echo 'Invalid X.509-depth option.'; continue;;
   esac
   args+=(--key-establishment "$kem" --depth "$depth")
   printf 'Number of pairs:\n1. 1\n2. 30 (default)\n3. 100\n'
   read -r -p 'Select [1-3, Enter=2]: ' pairs_choice || return 0
   case "${pairs_choice:-2}" in
    1) pairs=1;;
    2) pairs=30;;
    3) pairs=100;;
    *) echo 'Invalid number-of-pairs option.'; continue;;
   esac
   if (( pairs == 1 )); then warmups=1; else warmups=5; fi
   menu_measurement_summary "$kem" "$depth" "$pairs" "$warmups"
   args+=(--pairs "$pairs" --warmups "$warmups" --all-profiles)
   menu_measurements_run_prepared "$depth" "${args[@]}"
   continue
  fi
  if [[ "${args[0]}" == sandbox-setup || "${args[0]}" == sandbox-status ]]; then
   prefix=()
  elif [[ "$section" == preparation ]]; then
   prefix=(prepare-build)
  fi
  mode=confirm
  case "${args[0]}" in status|readiness|plan|trust-status|requirements|sandbox-status) mode=readonly;; esac
  menu_invoke "$mode" ${prefix[@]+"${prefix[@]}"} "${args[@]}"
 done
}

selected_mtc_arguments() {
 local trust_mode=landmark profile=ecdsa-p256 argument previous selected fixture validation
 previous=''
 for argument in "$@"; do
  case "$argument" in
   --mtc-trust-mode=*) trust_mode=${argument#*=};;
   --profile=*) profile=${argument#*=};;
  esac
  [[ "$previous" != --mtc-trust-mode ]] || trust_mode=$argument
  [[ "$previous" != --profile ]] || profile=$argument
  previous=$argument
 done
 if [[ "$trust_mode" == standalone ]]; then
  selected=$(python3 -B - "$REPO" "$profile" <<'PY'
import sys
from pathlib import Path
repo, profile = Path(sys.argv[1]), sys.argv[2]
sys.path.insert(0, str(repo/'campaigns/browser_client/chromium_mtc'))
import browser_validation as bv
selected, _ = bv.preselect_mtc_fixture(repo, profile, 'standalone')
print(selected['fixture']+'\t'+selected['validation_evidence'])
PY
  ) || fail "No compatible prevalidated standalone fixture for profile $profile. Prepare it with: bin/browser_client/mt-chromium-setup browser-validation credentials --profile $profile --mtc-trust-mode standalone"
  fixture=${selected%%$'\t'*}
  validation=${selected#*$'\t'}
  [[ "$fixture" != "$selected" && -d "$fixture" && -f "$validation" ]] ||
   fail 'Standalone fixture selection returned incomplete evidence.'
  MTC_ARGUMENTS=(--mtc-fixture "$fixture" --mtc-validation "$validation")
  return 0
 fi
 [[ -f "$STATE/paths.env" ]] || fail 'Required setup: mt-chromium-setup init, then run 20 and run 30.'
 source "$STATE/paths.env"
 [[ -n "${FIXTURE:-}" && -d "$FIXTURE" && -n "${VALIDATION:-}" && -f "$VALIDATION" ]] ||
  fail 'Selected MTC fixture/evidence missing. Required setup: mt-chromium-setup run 20 --fixture PATH; mt-chromium-setup run 30.'
 local arg
 for arg in "$@"; do
  case "$arg" in --mtc-fixture|--mtc-validation|--mtc-fixture=*|--mtc-validation=*)
   fail 'Controlled workflow uses FIXTURE/VALIDATION from paths.env; change selection with setup step 20.';; esac
 done
 MTC_ARGUMENTS=(--mtc-fixture "$FIXTURE" --mtc-validation "$VALIDATION")
}
