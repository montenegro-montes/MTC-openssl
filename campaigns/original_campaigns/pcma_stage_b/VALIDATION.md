# Preparation validation and execution boundary — 2026-09-11

Codex did not launch TLS, Docker builds/containers, packet captures, network
impairments or benchmarks. Validation used local compilation, help, syntax,
configuration parsing and tiny deterministic tests only.

During the final review the user reported manually launching the lab. Read-only
inspection found these result directories with completion markers:

- `artifacts/results/pcma-stage-b-20260911T160635-0e156dcf`: diagnostic, expected 8 handshakes.
- `artifacts/results/pcma-stage-b1-20260911-180725`: B.1, expected 12,600 handshakes.

All files listed in both recorded source inventories matched current SHA-256
values at inspection. This check is **not a complete scientific result audit**.
No timing/benefit conclusion follows from a completion marker. Protocol/runner
files were not changed after that inspection. This validation record and the
preparation report were added afterwards; they do not change the experiment's
recorded implementation. The README's preparation boundary refers to work by
Codex, not the user's independently initiated manual execution.

## Commands executed for validation

```sh
cc -std=c11 -Wall -Wextra -Werror -Wno-unused-function \
  -I/opt/homebrew/opt/openssl@3/include -Iintegration -IcodigoOriginal/C/crypto \
  -fsyntax-only campaigns/original_campaigns/pcma_stage_b/native/protocol.c \
  campaigns/original_campaigns/pcma_stage_b/native/tls.c campaigns/original_campaigns/pcma_stage_b/native/driver.c

./campaigns/original_campaigns/pcma_stage_b/build.sh /opt/homebrew/opt/openssl@3 /tmp/pcma-stage-b-native-build-20260911
/tmp/pcma-stage-b-native-build-20260911/pcma_tls --help

OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3 python3 campaigns/original_campaigns/pcma_stage_b/test_native.py
OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3 python3 campaigns/original_campaigns/pcma_stage_b/test_lab.py
./campaigns/original_campaigns/pcma_stage_b/run_pcma_stage_b.sh --validate \
  --openssl-prefix /opt/homebrew/opt/openssl@3

# Final full native compile/link in a different new temporary directory:
./campaigns/original_campaigns/pcma_stage_b/build.sh /opt/homebrew/opt/openssl@3 /tmp/pcma-stage-b-native-final-20260911
/tmp/pcma-stage-b-native-final-20260911/pcma_tls --help
./campaigns/original_campaigns/pcma_stage_b/run_pcma_stage_b.sh --help

sh -n campaigns/original_campaigns/pcma_stage_b/build.sh campaigns/original_campaigns/pcma_stage_b/run_pcma_stage_b.sh
git diff --check
```

Each build script also invokes the built binary with `--version` only. These
invocations do not open a socket. Final compile/link succeeded against the
installed host OpenSSL; this is not a replacement for a pinned-image build check.

Exact Python/JSON syntax check:

```sh
python3 - <<'PY'
import ast,json
from pathlib import Path
base=Path('campaigns/original_campaigns/pcma_stage_b')
for p in sorted(base.glob('*.py')):ast.parse(p.read_text(),filename=str(p))
for p in sorted((base/'configs').glob('*.json')):json.loads(p.read_text())
print('PASS Python syntax and JSON parsing')
PY
```

Final outcome: **4 native equivalence/security tests + 5 laboratory tests pass**.
The first native test compilation encountered an existing unused static helper
in the original Merkle source under `-Werror`; the test compiler now uses the
same unused-function exception as the native build, without editing that source.
An initial laboratory import resolved the A.2 CLI instead of the B CLI; the
Stage-B-only import path was corrected and the suite rerun successfully.

Native coverage: exact PCA2 ranges against A.2 for empty/single/full/max-coordinate
states; exact MTP2 bytes and counts; five handcrafted N=4/8 accesses with both
policies and zero/small budgets; actual node hashes and cache order; wrong roots,
missing/corrupt hashes, wrong credential, malformed/truncated/extra proof bytes,
noncanonical ranges/integers, persistence round trip and root/config binding.
N=1024 is a coordinate serialization test, not a large tree/TLS experiment.

Laboratory coverage: counts and pairing, deterministic sequences, B.2 selection
gate, no-argument safety, plan-only safety, negative metrics parsing, configurable
campaign bootstrap and access-paired effect calculation. Statistical tests use
in-memory synthetic values; no synthetic scientific CSV, table or plot is saved.

## Not executed by Codex

- Native `client` / `server` operations, `--diagnostic`, `--stage-b1`, `--stage-b2`, `--capture`.
- Docker build/up/exec, TLS smoke, packet capture, ping/iperf or impairment commands.
- Full Stage-B audit/model replay or scientific analysis/plots/tables.
- Stage A or A.2 campaigns, or any long benchmark.

Code inspection used read-only source/config/result-manifest reads and hashes.
An attempted read-only `ps` query was denied by the environment; no process was
stopped or controlled. The completion/source checks above did not require it.
Stage A/A.2 and existing protocol sources/results were not modified. A separately
appearing `.dockerignore` change was left untouched.
