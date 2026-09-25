# Chromium MTC integration

Goal: experimental Chromium integration using the validated BoringSSL MTC port.

Initial milestone:
1. Identify where Chromium configures client-side BoringSSL.
2. Identify SSL_CTX / SSL creation and verification configuration.
3. Determine how to enable experimental MTC negotiation.
4. Configure native trust_anchors (provisional 0xca34) in ClientHello.
5. Confirm the historical private 0xffa7 is not emitted. Do not patch Chromium
   to negotiate the old laboratory codepoint; this is not a final IANA assignment.

Out of scope for this milestone:
- MTC certificate verification
- Chromium certificate policy integration
- trust-anchor retry
- resumption
- client authentication
- performance campaigns

## Isolated browser fixture (`server.mtc.example.com`)

Chromium rejects internal or non-unique hostnames during normal certificate
verification. In particular, the earlier browser-only hostname `server.test`
results in `ERR_CERT_NON_UNIQUE_NAME`.

For browser interoperability, use `server.mtc.example.com`.

The hostname is resolved locally to loopback through `/etc/hosts`; no public DNS
record or external network service is required.

`--server-hostname` defaults to `server` in the shared MTC workflow. It sets only
leaf 0's CN and DNS SAN, and both `s_client -servername` and
`-verify_hostname` during validation. Other leaves retain `member-N.lab`.

The following MTC properties remain unchanged:
- Plants-05 semantics
- CA and registry IDs
- log and serial-number rules
- landmark semantics
- trust-anchor ID semantics
- SHA-256 Merkle construction
- ECDSA-P256 profile for the initial browser fixture
- N=16 for the initial browser interoperability case

**Always use a new output directory.**

`populate` contains:

```python
if cert.exists():
    continue
```

Therefore, an existing certificate is not reissued merely because a different
hostname was supplied. Do not reuse or edit existing artifacts.

## Generate the Chromium browser fixture

```sh
cd ~/Desktop/MT

BROWSER_HOSTNAME="server.mtc.example.com"
BROWSER_FIXTURE="artifacts/mtc/browser-server-mtc-example-com-ecdsa-p256-n16-$(date -u +%Y%m%dT%H%M%SZ)-$$"

python3 campaigns/browser_client/chromium_mtc/fixtures.py generate \
  --output "$BROWSER_FIXTURE" \
  --server-hostname "$BROWSER_HOSTNAME" \
  --execute
```

## Validate the fixture

```sh
python3 campaigns/browser_client/chromium_mtc/fixtures.py validate \
  --fixtures "$BROWSER_FIXTURE" \
  --output "${BROWSER_FIXTURE}-validation" \
  --server-hostname "$BROWSER_HOSTNAME" \
  --execute
```

Expected leaf-0 identity:

```text
CN  = server.mtc.example.com
SAN = DNS:server.mtc.example.com
```

## Export the Chromium trust configuration

```sh
CHROMIUM_JSON="${BROWSER_FIXTURE}-chromium.json"

test ! -e "$CHROMIUM_JSON" && \
python3 campaigns/browser_client/chromium_mtc/export_chromium_anchor.py \
  --trust "$BROWSER_FIXTURE/batch16/mtc/ecdsa-p256/trust.bin" \
  --output "$CHROMIUM_JSON"
```

The Chromium JSON must come from the same newly generated fixture.

## Local hostname resolution

The driver checks the existing `/etc/hosts` entry and local resolution. It never
modifies this file. If missing, manually add `127.0.0.1 server.mtc.example.com`
once, then rerun step 50. Existing entries are never owned by the workflow.

The browser can then access:

```text
https://server.mtc.example.com:4433/
```

No `--host-resolver-rules` Chromium flag is required.

## Chromium-specific fixture wrapper

`campaigns/browser_client/chromium_mtc/fixtures.py` is the
Chromium-specific entrypoint.

For the initial browser experiment:

```text
profile     = ecdsa-p256
tree size   = 16
mode        = landmark
hostname    = configurable through --server-hostname
```

It delegates generation and validation to the shared MTC workflow and does not
duplicate MTC issuance or verification code.

## Expected browser interoperability flow

```text
Chromium
   |
   | HTTPS to server.mtc.example.com:4433
   |
   | ClientHello
   | trust_anchors = 32473.101.2.1.1
   v
OpenSSL/MTC server
   |
   | EncryptedExtensions
   | selected trust anchor = 32473.101.1.1.1
   |
   | MTC landmark certificate
   | CertificateVerify
   | Finished
   v
Chromium
   |
   | Plants-05 MTC validation
   | hostname = server.mtc.example.com
   | Finished
   v
HTTPS application data
```

A clean positive result requires:
- `server.mtc.example.com` resolves to `127.0.0.1`
- certificate CN/SAN matches `server.mtc.example.com`
- ClientHello carries provisional `trust_anchors` extension `0xca34`
- requested trust-anchor ID is `32473.101.2.1.1`
- server selects `32473.101.1.1.1`
- historical private `0xffa7` is not emitted
- CertificateVerify is present
- server Finished is present
- client Finished is present
- Chromium loads the HTTPS response
- no `ERR_CERT_*` interstitial is shown

## Existing-build resumable driver

```sh
bin/browser_client/mt-chromium-mtc init
bin/browser_client/mt-chromium-mtc plan
bin/browser_client/mt-chromium-mtc resume
bin/browser_client/mt-chromium-mtc status
# Stop only the labelled workflow container; preserve fixtures/results/hosts:
bin/browser_client/mt-chromium-mtc cleanup
```

`show STEP` displays implementation/commands; `run STEP` executes one step.
Steps: 00 preflight, 10 existing Chromium detection, 20 fixture selection,
30 validation-evidence verification, 40 anchor export/check, 50 hostname check,
60 positive server start. `resume` skips every stage with an existing `.done` marker. Use `run STEP`
to explicitly recheck a completed stage; `status` checks container state. Stopped/foreign containers require inspection;
they are never silently replaced. No retries of TLS samples occur.

Paths persist in `.mt-state/chromium-mtc/paths.env`; no inherited terminal
variables are needed. `chromium.json` records checkout commits, executable hash,
and debug/component flags (component flag falls back to generated base Ninja
compile definitions). Checkout commits describe the current checkout, not proof
that the executable was built from a clean tree. The small launcher executable's
hash is not a hash of all component libraries.

Step 20 selects the known ECDSA-P256 N=16 fixture. If missing it stops: use the
explicit generation command above with a fresh timestamped output, validate it,
then update the persisted FIXTURE/VALIDATION/ANCHOR paths. No generation is
implicit. Step 30 verifies all fixture hashes against successful existing TLS
validation and checks the hostname/profile/size; it does not rerun TLS. Steps
20–50 do not need Chromium. Step 40 preserves and checks an existing JSON against
the trust configuration, or exports to a new path.

Step 60 pins the image ID from the validation evidence, uses `--pull never`,
read-only fixtures, and publishes only `127.0.0.1:4433`. It records container ID
and a unique `artifacts/results/chromium-mtc-validation-<timestamp>-<suffix>/`
directory. `server.log` is written directly there for the container lifetime.
Readiness checks OpenSSL's ACCEPT marker, not browser interoperability.
No browser is launched and no browser profiles are created. Cleanup removes
only the container labelled with this workflow state directory; it preserves
logs, all artifacts and the pre-existing hosts entry.

## Deterministic source reconstruction

`reconstruct-plan` prints upstream pins, preserved custom commits and exact Git
source tree hashes from `versions/chromium-mtc.env`. Tree hashes are authoritative
for source content; commit IDs additionally preserve history and Chromium's exact
BoringSSL gitlink. The readable format-patches remain unchanged, but reconstruction
imports incremental bundles instead of replaying `git am` (which can change IDs).

Both bundles require the corresponding upstream base commit and its reachable
objects. They contain only custom history, not the complete upstream repository.
Verify integrity from this campaign directory:

```sh
shasum -a 256 -c patches/SHA256SUMS
shasum -a 256 -c source-bundles/SHA256SUMS
# Run in repositories already containing the respective base histories:
git -C /path/to/chromium bundle verify /absolute/path/to/source-bundles/chromium-mtc.bundle
git -C /path/to/boringssl bundle verify /absolute/path/to/source-bundles/boringssl-mtc.bundle
```

The separate source interface defaults to `$HOME/chromium-mtc-rebuild`.
Use optional `--dest ABSOLUTE_PATH` before or after the subcommand to override it:

```sh
bin/browser_client/mt-chromium-mtc reconstruct-plan
bin/browser_client/mt-chromium-mtc reconstruct-source plan
bin/browser_client/mt-chromium-mtc reconstruct-source status
# Future server only: explicitly run each step in order; 110–130 download sources.
bin/browser_client/mt-chromium-mtc reconstruct-source run 100
# Then individually run 110, 120, 130, 140, 150, 160.
# Optional override (also accepted after run 100):
bin/browser_client/mt-chromium-mtc reconstruct-source --dest /srv/mtc-source plan
```

| Step | Operation |
| --- | --- |
| 100.verify-reconstruction-inputs | Verify patch/bundle SHA-256 and advertised commit tips; claim empty destination. |
| 110.prepare-depot-tools | Fetch and checkout pinned depot_tools; do not invoke its wrappers. |
| 120.prepare-chromium-base | Fetch upstream Chromium base history, checkout and verify base tree. |
| 130.prepare-boringssl-base | Fetch upstream BoringSSL base history, checkout and verify base tree. |
| 140.import-preserved-commits | Verify bundle prerequisites, import exact objects and verify patched trees. |
| 150.checkout-patched-source | Checkout preserved commits and verify source. |
| 160.verify-source-trees | Recheck exact HEADs, tree hashes, clean source and BoringSSL gitlink. |

The first run of step 100 creates an absent destination automatically and writes
`.mtc-source-owner.json`, identifying the `chromium-mtc-source-v1` workflow and
binding the canonical path and version metadata. An empty directory can also be
claimed; an existing matching owned destination is reused. A non-empty directory
without a matching ownership marker is refused and never deleted. Unrelated
content is never overwritten. `plan` and `status` do not create the destination;
both print the resolved default or override path.
Unexpected non-empty destinations, symlink source paths, and overlaps with MT,
`~/Desktop/chromium-mtc` or `~/Desktop/depot_tools` are rejected. Each step requires
all earlier completion markers and uses a separate destination lock. Existing
source repositories must match the expected state; no forced checkout or cleanup
is performed. Interrupted fetch/checkouts may require manual inspection before
retrying. Status reports recorded completion, not fresh validation; explicitly
run 160 to revalidate. Input checks run before every source execution.

Normal `resume` retains only the existing positive interoperability steps 00–60;
it cannot reach any reconstruction stage. Source stages have no resume command.
The reconstruction namespace performs no build, package installation, gclient
sync, hook execution, or automatic DEPS/toolchain download. This reconstructs the pinned Chromium and BoringSSL Git
content plus depot_tools, **not a build-ready full Chromium dependency checkout**.
Fetching the upstream histories and checking out sources can be expensive and is
reserved for explicit execution. The separate preparation and build interfaces
below handle DEPS, Linux prerequisites, GN and compilation. Browser validation
remains a separate activity.

`doctor` prints OS, architecture, tool presence and free space without invoking
wrappers or installing tools. `reconstruct-plan`, source `plan` and source `status`
perform no reconstruction, download or build.


## Explicit Ubuntu 24.04 x86_64 build preparation

Source reconstruction through 160 has been manually validated on the server
(user-reported). The new preparation/build path has only been checked statically
and through print-only interfaces on macOS; real sync, hooks, installation, GN
and compilation still require server validation.

All commands default to `$HOME/chromium-mtc-rebuild` and accept optional
`--dest ABSOLUTE_PATH` before or after the action. Plan/status are portable and
read-only; execution rejects platforms other than Ubuntu 24.04 x86_64.

```sh
bin/browser_client/mt-chromium-mtc prepare-build plan
bin/browser_client/mt-chromium-mtc prepare-build status
bin/browser_client/mt-chromium-mtc prepare-build run 170
bin/browser_client/mt-chromium-mtc prepare-build run 180
bin/browser_client/mt-chromium-mtc prepare-build run 190
bin/browser_client/mt-chromium-mtc prepare-build run 200
# Only if packages are missing: explicitly install with Chromium's own script.
# It may request sudo; this action is never inferred from a failed check.
bin/browser_client/mt-chromium-mtc prepare-build install-deps
# After installation, explicitly rerun 200, then continue:
bin/browser_client/mt-chromium-mtc prepare-build run 210
bin/browser_client/mt-chromium-mtc prepare-build run 220
```

| Stage | Explicit action |
| --- | --- |
| 170.verify-reconstructed-source | Check preserved Chromium/BoringSSL HEADs and trees, BoringSSL gitlink, clean tracked files/index and pinned depot_tools. |
| 180.prepare-chromium-checkout-layout | Write a matching `.gclient` in the reconstruction root; refuse conflicting configuration. Never replace `src`. |
| 190.sync-pinned-deps | Run pinned `depot_tools/gclient sync --nohooks --noprehooks` from the reconstruction root. Downloads dependencies without running hooks. |
| 200.check-linux-build-dependencies | Run `src/build/install-build-deps.sh --quick-check`; fail on missing packages without installing anything. |
| 210.configure-linux-release | Run pinned `gclient runhooks`, then `gn gen out/mtc-release` from `src`. Hooks download/setup toolchains; GN generates build files, without compiling Chromium. |
| 220.verify-build-configuration | Reverify source, layout, exact args, generated `build.ninja` hash and absence of recorded build attempts/known compilation artifacts. |

The `.gclient` is exactly:

```python
# Owned by the Chromium MTC reconstruction workflow.
solutions = [{
    'name': 'src',
    'url': 'https://chromium.googlesource.com/chromium/src.git',
    'managed': False,
    'deps_file': 'DEPS',
    'custom_deps': {'src/third_party/boringssl/src': None},
}]
target_os = ['linux']
target_os_only = True
```

`managed=False` leaves the reconstructed Chromium HEAD authoritative. Its
preserved DEPS supplies dependency revisions; no revision override requests an
unpublished custom commit from upstream. `custom_deps=None` excludes BoringSSL
from synchronization: its DEPS pin names the upstream base whereas the patched
Chromium gitlink names the preserved custom commit. The existing BoringSSL
checkout is kept in place. There is no force/reset/delete operation or fallback
that overwrites it. Exact HEADs, trees, tracked content and the gitlink are checked
before and after synchronization, including after a failed sync. A mismatch
fails closed for manual inspection. Untracked/ignored dependency and output
files are not claimed to be covered by the two Git tree hashes.

All tool commands prepend the reconstructed pinned depot_tools to PATH and set
`DEPOT_TOOLS_UPDATE=0`. gclient and autoninja use absolute paths to that checkout.
Wrappers may bootstrap their pinned tools during explicit execution. The Linux
package list belongs to Chromium, not this driver. `install-deps` invokes
`build/install-build-deps.sh`, then its `--quick-check`; it invalidates stages
200–220, which must be run explicitly again. No plan/status or other namespace
installs packages. The upstream workflow reference is
[Chromium Linux build instructions](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/build_instructions.md);
actual commands/flags were checked against the local pinned scripts.

The complete `src/out/mtc-release/args.gn` is:

```gn
is_debug = false
is_component_build = false
symbol_level = 1
use_remoteexec = false
```

The last two settings retain the known-good checkout's symbol level and local
execution choice. No additional MTC feature flag was present in its `args.gn`;
MTC functionality remains in the preserved source patches. The Linux x86_64
host supplies the native target defaults. A non-empty output directory must
already carry matching ownership evidence in `.mtc-build-state/output-owner.json`;
conflicting args are refused rather than overwritten.

## Explicit compilation and provenance

```sh
bin/browser_client/mt-chromium-mtc build plan
bin/browser_client/mt-chromium-mtc build status
# The only driver interface that compiles Chromium:
bin/browser_client/mt-chromium-mtc build run chromium
```

The last command invokes exactly the equivalent of:

```sh
cd "$HOME/chromium-mtc-rebuild/src"
"$HOME/chromium-mtc-rebuild/depot_tools/autoninja" -C out/mtc-release chrome
```

It requires current successful stages 170–220, the reconstruction ownership and
160 record, matching `.gclient`, exact sources/depot_tools, output ownership,
matching args and the generated Ninja file. It reruns the package quick-check
before compilation. Missing output or stale prerequisites cause failure, never
implicit sync, install, hooks or GN generation.

Preparation evidence binds the driver SHA-256, version pins, destination, GN args,
layout and source verification marker timestamp. Rerunning a preparation stage
invalidates its own and later evidence. Preparation/build share reconstruction's
lock, so these driver operations cannot race. Status reports recorded evidence,
not fresh verification of files or external manual activity. Stage 220's
pre-compilation check is limited to workflow attempts and known artifact names;
it cannot prove that no external compilation has ever occurred.

A successful future build records `.mtc-build-state/build-result.json`: UTC time,
Chromium/BoringSSL commits and trees, depot_tools commit, GN args, exact command,
working directory, executable path and streamed SHA-256. A separate attempt
record distinguishes started/failed/successful attempts; an older success record
is retained if a later attempt fails. No large artifacts are archived. Once a
build has been attempted, stage 220 refuses to certify a fresh pre-compilation
state; existing current preparation evidence permits an explicit build retry.

Normal `resume` remains limited to interoperability stages 00–60. Reconstruction
100–160 is unchanged. Neither reconstruction nor preparation can dispatch
compilation. `build plan/status` cannot build, and missing output never triggers
an automatic build.
