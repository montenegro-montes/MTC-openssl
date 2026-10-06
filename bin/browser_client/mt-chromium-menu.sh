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

menu_submenu() {
 local section=$1 title selection index mode root_path
 local labels=() commands=() prefix=() args=()
 case "$section" in
  source)
   title='Source reconstruction'; prefix=(reconstruct-source)
   labels=('100 Verify reconstruction inputs' '110 Prepare depot_tools' '120 Prepare Chromium base' '130 Prepare BoringSSL base' '140 Import preserved commits' '150 Checkout patched source' '160 Verify source trees' 'Status' 'Plan')
   commands=('run 100' 'run 110' 'run 120' 'run 130' 'run 140' 'run 150' 'run 160' status plan);;
  preparation)
   title='Build preparation (macOS / Linux)'; prefix=(prepare-build)
   labels=('170 Verify reconstructed source' '180 Prepare Chromium checkout layout' '190 Sync pinned dependencies' '200 Check platform build dependencies' '210 Configure release build' '220 Verify build configuration' 'Status' 'Plan' 'Install build dependencies' 'Prepare Chromium AppArmor sandbox' 'Check Chromium AppArmor sandbox')
   commands=('run 170' 'run 180' 'run 190' 'run 200' 'run 210' 'run 220' status plan install-deps sandbox-setup sandbox-status);;
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
   labels=('Plan' 'Requirements / capture backend' 'Status' 'Run pilot (3 pairs)' 'Run supported matrix smoke (1 pair/cell)' 'Run supported matrix (30 pairs/cell)')
   commands=(plan requirements status 'run --pairs 3' matrix-smoke matrix);;
 esac
 while true; do
  printf '\n%s\n' "$title"
  for ((index=0; index<${#labels[@]}; index++)); do
   printf '%d. %s\n' "$((index+1))" "${labels[index]}"
  done
  if [[ "$section" == measurements ]]; then printf '7. Back\n'; else printf '0. Back\n'; fi
  read -r -p 'Select an option: ' selection || exit 0
  [[ "$selection" != 0 ]] || return 0
  [[ "$section" != measurements || "$selection" != 7 ]] || return 0
  [[ "$selection" =~ ^[1-9][0-9]?$ ]] || { echo 'Invalid option.'; continue; }
  (( selection <= ${#labels[@]} )) || { echo 'Invalid option.'; continue; }
  read -r -a args <<< "${commands[selection-1]}"
  if [[ "$section" == validation && "${args[0]}" == run && "${args[1]}" != all ]]; then
   menu_browser_mode "${args[@]:1}"
   continue
  fi
  if [[ "$section" == trust ]]; then
   read -r -p 'Root certificate path (PEM): ' root_path || return 0
   [[ -n "$root_path" ]] || { echo 'Root path is required.'; continue; }
   args+=(--root "$root_path")
  fi
  if [[ "${args[0]}" == sandbox-setup || "${args[0]}" == sandbox-status ]]; then
   prefix=()
  elif [[ "$section" == preparation ]]; then
   prefix=(prepare-build)
  fi
  mode=confirm
  case "${args[0]}" in status|plan|trust-status|requirements|sandbox-status) mode=readonly;; esac
  menu_invoke "$mode" ${prefix[@]+"${prefix[@]}"} "${args[@]}"
 done
}

selected_mtc_arguments() {
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
